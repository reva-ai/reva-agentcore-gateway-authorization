"""The call to the RTG: `POST {base}/pdp/v2/ai/evaluation`.

The HTTP status is authoritative. 200 is an allow, 403 is a policy denial; the body
is only read for a reason, an error type and an optional conditional-allow signal.

Headers are sent with `http.client.putheader`, NOT urllib: urllib re-capitalises
header names, which turned `policyStoreId` into `Policystoreid` on the wire and
made the RTG answer "missing required header".
"""

from __future__ import annotations

import http.client
import json
import random
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .classify import Call
from .config import Settings
from .trace import traceparent_header

ALLOW, CONDITIONAL, POLICY_DENY, REJECTED, OPERATIONAL = (
    "allow", "conditional", "policy_deny", "rejected", "operational")
USER_STATES = ("USER_NOT_FOUND", "USER_DISABLED")
USER_AGENT = "reva-agentcore-interceptor/1.0"
MIN_ATTEMPT_SECONDS = 1.0
_sleep = time.sleep      # a name of its own so tests can skip the backoff without touching time


@dataclass
class Decision:
    outcome: str            # allow | conditional | policy_deny | rejected | operational
    status: int = 0         # HTTP status, 0 when there was no response
    error_type: str = ""
    reason: str = ""        # for the log only, never shown to the caller
    attempts: int = 0
    latency_ms: int = 0


def build_request(cfg: Settings, call: Call, principal: str, subject: Dict[str, str],
                  role: str, thread_id: str, turn: int, started_at: str,
                  hops: List[Dict[str, Any]], messages: List[Dict[str, Any]],
                  groups: List[str]) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "subject": subject,
        "principal": {"type": "User", "id": principal},
        "action": {"name": call.action},
        "resource": call.resource,
        "transmission": {"promptKey": cfg.prompt_key, cfg.prompt_key: call.prompt,
                         "role": role, "contentType": "text/plain"},
    }

    context: Dict[str, Any] = {}
    if cfg.history == "interceptor":
        # `hops` is always sent, empty on a trace's first call; `conversation` only
        # when there is something in it. The RTG keeps caller-supplied history and
        # does not replace it, which is why `rtg` mode sends neither.
        context["hops"] = hops
        if messages:
            context["conversation"] = {"messages": messages}
        body["session"] = {"id": thread_id, "turn": turn, "startedAt": started_at}
    for argument, attribute in cfg.context_map.items():
        value = call.arguments.get(argument)
        if value not in (None, "", [], {}):    # an empty set fails validation at the RTG
            context[attribute] = value
    if context:
        body["context"] = context

    if groups:
        body["entities"] = [{"uid": {"type": "User", "id": principal},
                             "parents": [{"type": "UserGroup", "id": g} for g in groups]}]
    return body


def request_headers(cfg: Settings, trace_id: str, span: str, thread_id: str
                    ) -> List[Tuple[str, str]]:
    headers = [
        ("Content-Type", "application/json"),
        ("traceparent", traceparent_header(trace_id, span)),
        ("x-ms-correlation-id", trace_id),
        ("X-Reva-Thread-Id", thread_id),
        ("User-Agent", USER_AGENT),
    ]
    if cfg.auth_mode == "bearer":
        headers.append(("Authorization", f"Bearer {cfg.token}"))
        if cfg.policy_store_id:
            headers.append(("policyStoreId", cfg.policy_store_id))
    else:
        headers.append(("X-API-Token", cfg.token))
    if cfg.verify_user_scope:
        headers.append(("X-API-Origin-App", cfg.origin_app))
        headers.append(("X-Reva-Verification-Codes", "CODE_USER_SCOPE"))
    return headers


def _post(url: str, data: bytes, headers: List[Tuple[str, str]], timeout: float
          ) -> Tuple[int, str]:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"not an http(s) URL: {url!r}")
    connection_class = (http.client.HTTPSConnection if parts.scheme == "https"
                        else http.client.HTTPConnection)
    connection = connection_class(parts.netloc, timeout=timeout)
    try:
        connection.putrequest("POST", parts.path + (f"?{parts.query}" if parts.query else ""),
                              skip_accept_encoding=True)
        for name, value in headers:
            connection.putheader(name, value)
        connection.putheader("Content-Length", str(len(data)))
        connection.endheaders(data)
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        connection.close()


def _reason(payload: Any, text: str) -> str:
    """Why, for the log. A JSON body with no reason in it has none; anything that is not
    JSON (an HTML error page, a gateway message) is the best explanation there is."""
    if isinstance(payload, dict):
        context = payload.get("context")
        for candidate in ((context or {}).get("reason") if isinstance(context, dict) else None,
                          payload.get("message"), payload.get("error"), payload.get("reason")):
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()[:300]
        return ""
    return text[:300]


def interpret(status: int, text: str) -> Decision:
    try:
        payload = json.loads(text) if text else None
    except ValueError:
        payload = None
    error_type = ""
    if isinstance(payload, dict) and isinstance(payload.get("error_type"), str):
        error_type = payload["error_type"]
    reason = _reason(payload, text)

    if 200 <= status < 300:
        if not isinstance(payload, dict):
            return Decision(OPERATIONAL, status, error_type, f"unreadable {status} response")
        if payload.get("decision") is False:
            return Decision(POLICY_DENY, status, error_type, reason)
        guardrails = payload.get("guardrails")
        if isinstance(guardrails, dict) and guardrails.get("outcome") == "conditional_allow":
            return Decision(CONDITIONAL, status, error_type,
                            str(guardrails.get("reason") or "conditional allow")[:300])
        return Decision(ALLOW, status, error_type, reason)
    if status == 403:
        return Decision(POLICY_DENY, status, error_type, reason)
    if status == 401 and error_type in USER_STATES:
        return Decision(POLICY_DENY, status, error_type, reason)
    if status in (401, 404, 408, 413, 424, 425, 429) or status >= 500:
        return Decision(OPERATIONAL, status, error_type, reason)
    return Decision(REJECTED, status, error_type, reason)    # our request was invalid


def _transient(decision: Decision) -> bool:
    status = decision.status
    return status == 0 or status in (408, 424, 425, 429) or status >= 500


def evaluate(cfg: Settings, body: Dict[str, Any], headers: List[Tuple[str, str]],
             remaining_ms: Optional[int] = None) -> Decision:
    """Ask the RTG. Retries only a transient fault, inside the time the Lambda has left.

    The inner timeout must stay below the function timeout: a function killed at the
    same instant its own HTTP timeout fires never reaches its fail-closed path.
    """
    attempts = 1 + cfg.retries
    started = time.monotonic()
    if remaining_ms is None:
        budget = cfg.timeout_seconds * attempts + 2.0
    else:
        budget = max(0.0, (remaining_ms - cfg.safety_margin_ms) / 1000.0)
    deadline = started + budget
    data = json.dumps(body).encode("utf-8")

    last = Decision(OPERATIONAL, 0, "", "no time left to ask the policy engine")
    made = 0
    for attempt in range(attempts):
        remaining = deadline - time.monotonic()
        if remaining < MIN_ATTEMPT_SECONDS:
            break
        made += 1
        try:
            status, text = _post(cfg.evaluate_url, data, headers,
                                 min(cfg.timeout_seconds, remaining))
            last = interpret(status, text)
        except Exception as exc:  # noqa: BLE001 - refused, DNS, TLS, timeout
            last = Decision(OPERATIONAL, 0, "", f"policy engine unreachable: {type(exc).__name__}")
        if last.outcome != OPERATIONAL or not _transient(last):
            break
        if attempt + 1 < attempts:
            pause = 0.4 * (3 ** attempt) + random.uniform(0, 0.2)
            if time.monotonic() + pause >= deadline - MIN_ATTEMPT_SECONDS:
                break
            _sleep(pause)

    last.attempts = made
    last.latency_ms = int((time.monotonic() - started) * 1000)
    return last
