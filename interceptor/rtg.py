"""The call to the RTG: `POST {base}/pdp/ai/access/ai/evaluation`.

Token-evaluation body: business prompt at the root, Reva fields under `rtg/a2a`.
Headers request a transaction token on allow (`X-Reva-Token-Request: transaction`).
Prior-hop tokens go as `X-Transaction-Token`; the caller's user JWT stays on
`Authorization` when the gateway credential uses `X-API-Token`.

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
from .config import SUMMARIZE_OUTPUT_MAX, Settings
from .context import build_context
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
    token: str = ""         # minted transaction token on allow, when requested


def context_for(cfg: Settings, call: Call) -> Tuple[Dict[str, Any], List[str]]:
    """The call's `context` and what was left out of it (names and reasons, never values).

    The pairs in the request body (unless REVA_CONTEXT_FROM_BODY=false) plus the arguments
    REVA_CONTEXT_MAP renames to policy attributes, which win a repeated name.
    """
    pinned: Dict[str, Any] = {}
    for argument, attribute in cfg.context_map.items():
        value = call.arguments.get(argument)
        if value not in (None, "", [], {}):    # an empty set fails validation at the RTG
            pinned[attribute] = value
    return build_context(call.context_sources if cfg.context_from_body else [], pinned)


def build_request(cfg: Settings, call: Call, principal: str, subject: Dict[str, str],
                  role: str, groups: List[str], *, thread_id: str = "",
                  omit_subject: bool = False,
                  context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Token-evaluation body: root prompt + `rtg/a2a` envelope.

    Thread correlation uses `rtg/a2a.threadId` / `session.id` plus
    `X-Reva-Thread-Id` on the wire. Do not send `context.hops` or prior
    `session.messages` — the RTG attaches those from its store. When a prior
    transaction token is present (`omit_subject`), body subject and principal
    are omitted — RTG derives them from the token.
    """
    prompt_key = cfg.prompt_key
    a2a: Dict[str, Any] = {
        "action": {"name": call.action},
        "resource": call.resource,
        "transmission": {
            "promptKey": prompt_key,
            prompt_key: call.prompt,
            "role": role,
            "contentType": "text/plain",
        },
    }
    if not omit_subject:
        a2a["subject"] = subject
        a2a["principal"] = {"type": "User", "id": principal}
    if thread_id:
        a2a["threadId"] = thread_id
        a2a["session"] = {"id": thread_id}

    if context is None:
        context, _left_out = context_for(cfg, call)
    if context:
        a2a["context"] = context

    if groups and not omit_subject:
        a2a["entities"] = [{"uid": {"type": "User", "id": principal},
                            "parents": [{"type": "UserGroup", "id": g} for g in groups]}]

    return {"rtg/a2a": a2a, prompt_key: call.prompt}


def request_headers(cfg: Settings, trace_id: str, span: str, thread_id: str,
                    *, user_bearer: str = "", txn_token: str = ""
                    ) -> List[Tuple[str, str]]:
    headers = [
        ("Content-Type", "application/json"),
        ("traceparent", traceparent_header(trace_id, span)),
        ("x-ms-correlation-id", trace_id),
        ("X-Reva-Token-Request", "transaction"),
        ("User-Agent", USER_AGENT),
    ]
    if thread_id:
        headers.append(("X-Reva-Thread-Id", thread_id))
    if cfg.auth_mode == "bearer":
        # Gateway credential occupies Authorization; user JWT is not dual-sent.
        headers.append(("Authorization", f"Bearer {cfg.token}"))
        if cfg.policy_store_id:
            headers.append(("policyStoreId", cfg.policy_store_id))
    else:
        # The gateway credential carries the scheme, as the Kong plugin sends it.
        headers.append(("X-API-Token", f"Bearer {cfg.token}"))
        if user_bearer:
            headers.append(("Authorization", f"Bearer {user_bearer}"))
    if txn_token:
        headers.append(("X-Transaction-Token", txn_token))
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
    minted = ""
    if isinstance(payload, dict):
        if isinstance(payload.get("error_type"), str):
            error_type = payload["error_type"]
        token = payload.get("token")
        if isinstance(token, str) and token.strip():
            minted = token.strip()
    reason = _reason(payload, text)

    if 200 <= status < 300:
        if not isinstance(payload, dict):
            return Decision(OPERATIONAL, status, error_type, f"unreadable {status} response")
        decision = payload.get("decision")
        if decision is False:
            return Decision(POLICY_DENY, status, error_type, reason)
        guardrails = payload.get("guardrails")
        if isinstance(guardrails, dict) and guardrails.get("outcome") == "conditional_allow":
            return Decision(CONDITIONAL, status, error_type,
                            str(guardrails.get("reason") or "conditional allow")[:300],
                            token=minted)
        if decision is True:
            return Decision(ALLOW, status, error_type, reason, token=minted)
        # An allow says so. A 2xx that carries no `decision: true` is not one.
        return Decision(POLICY_DENY, status, error_type,
                        reason or "no allow decision in the response")
    if status == 403:
        # A 403 is a policy decision only when the RTG says so. One without a `decision`
        # or an `error_type` is an edge or proxy refusing the call, not a verdict.
        if isinstance(payload, dict) and ("decision" in payload or error_type):
            return Decision(POLICY_DENY, status, error_type, reason)
        return Decision(OPERATIONAL, status, error_type, reason or "HTTP 403 without a decision")
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


def summarize_headers(cfg: Settings, thread_id: str = "") -> List[Tuple[str, str]]:
    """Auth headers for POST …/trace/summarize."""
    # The summarize endpoint takes the credential as `Authorization: Bearer`, whichever
    # header the evaluation call uses (the Kong plugin does the same).
    headers = [
        ("Content-Type", "application/json"),
        ("Authorization", f"Bearer {cfg.token}"),
        ("User-Agent", USER_AGENT),
    ]
    if cfg.policy_store_id:
        headers.append(("policyStoreId", cfg.policy_store_id))
    if thread_id:
        headers.append(("X-Reva-Thread-Id", thread_id))
    if cfg.origin_app:
        headers.append(("X-API-Origin-App", cfg.origin_app))
    return headers


def summarize(cfg: Settings, trace_id: str, thread_id: str = "", output: str = "",
              timeout: Optional[float] = None) -> int:
    """Best-effort finalize of a finished prompt. Never raises; returns HTTP status or 0.

    RTG already has the hops from evaluation; `output` is the agent's final answer
    so later turns can populate `session.messages`.
    """
    trace_id = (trace_id or "").strip()
    if not trace_id or not cfg.token:
        return 0
    body: Dict[str, Any] = {"trace_id": trace_id}
    if thread_id.strip():
        body["thread_id"] = thread_id.strip()
    if output:
        body["output"] = output[:SUMMARIZE_OUTPUT_MAX]
    data = json.dumps(body).encode("utf-8")
    try:
        status, _text = _post(
            cfg.summarize_url, data, summarize_headers(cfg, thread_id.strip()),
            timeout if timeout is not None else min(cfg.timeout_seconds, 5.0))
        return status
    except Exception:  # noqa: BLE001 - summarize must never fail the caller
        return 0
