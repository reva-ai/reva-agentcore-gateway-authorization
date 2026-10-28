"""The pipeline: event in, gateway response out. Nothing here raises past `handle`.

    parse -> (response leg? pass) -> config check -> classify -> trace
          -> trace record (principal, thread, turn, hops) -> subject
          -> ask the RTG -> enforce -> record the hop (only if permitted) -> respond

Failure policy, in one place:

    local problems   no RTG token, no principal, malformed body, unresolvable resource,
                     bad config, internal error                        always deny
    RTG policy deny  403, a false `decision`, USER_NOT_FOUND/DISABLED  deny
                                                    (monitor mode logs it and passes)
    RTG invalid      any other 4xx: our request is wrong                always deny
    dependency down  RTG 401/404/413/424/429/5xx, timeout, or the history table
                     unreadable                          deny, or pass if REVA_FAIL_OPEN
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from . import respond
from .classify import Call, Reject, Skip, classify
from .config import Settings
from .event import Envelope, EventError, parse_event
from .history import StoreError, open_store, paired_history
from .identity import resolve_agent, resolve_principal, subject_for
from .rtg import (ALLOW, CONDITIONAL, POLICY_DENY, REJECTED, Decision, build_request,
                  evaluate, request_headers)
from .secret import SecretError, with_token
from .trace import resolve_thread, resolve_trace, span_id
from .util import canonical_json, clip_utf8, iso_now, sha256_hex

_STORES: Dict[Any, Any] = {}

PRINCIPAL_REASONS = {
    "missing_authorization": "no bearer token: attach the interceptor with "
                             "passRequestHeaders=true and send the user's JWT on the "
                             "first call of each trace",
    "invalid_authorization": "the Authorization bearer token is not a decodable JWT",
    "principal_unresolved": "the configured user claim is missing from the token",
}


def _log(**fields: Any) -> None:
    print(json.dumps(fields, default=str, separators=(",", ":")))


def get_store(cfg: Settings) -> Any:
    key = (cfg.history_table, cfg.history_pk_attr, cfg.history_sk_attr)
    if key not in _STORES:
        try:
            _STORES[key] = open_store(cfg)
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"cannot open table {cfg.history_table!r}: {exc}") from exc
    return _STORES[key]


def _remaining_ms(context: Any) -> Optional[int]:
    try:
        return int(context.get_remaining_time_in_millis())
    except Exception:  # noqa: BLE001 - tests and local runs have no Lambda context
        return None


def _shape(env: Envelope) -> Dict[str, Any]:
    """The event's shape, never its values: header NAMES only, no bodies, no tokens."""
    return {"transport": env.transport, "leg": env.leg, "method": env.http_method,
            "path": env.path, "headers": sorted(env.headers),
            "body": type(env.body).__name__, "bodyBytes": len(env.body_bytes)}


def _local_deny(env: Envelope, cfg: Settings, code: str, reason: str) -> Dict[str, Any]:
    _log(event="local_deny", code=code, reason=reason, route=f"{env.transport}:{env.path}")
    return respond.deny(env, cfg.deny_message, code, cfg.deny_status)


def _seed(env: Envelope) -> str:
    """What a minted trace id is derived from: the same call always gives the same id."""
    body = sha256_hex(env.body_bytes) if env.transport == "http" else sha256_hex(
        canonical_json(env.body))
    return "|".join((env.request_id, env.path, body, env.headers.get("authorization", "")))


def handle(event: Any, context: Any, cfg: Settings, store: Any = None) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        env = parse_event(event, context)
    except EventError as exc:
        _log(event="local_deny", code="malformed_event", reason=str(exc))
        return respond.emergency_deny(event, cfg.deny_message, "malformed_event",
                                      cfg.deny_status)

    if env.leg == "response":
        # REQUEST-only in v1. If the customer attached both interception points, the
        # response is returned exactly as it came.
        return respond.pass_response(env)

    if cfg.debug:
        _log(event="debug_event", **_shape(env))
    if cfg.errors:
        return _local_deny(env, cfg, "config_error", "; ".join(cfg.errors))

    # ── what is being called ────────────────────────────────────────────────
    result = classify(env, cfg)
    if isinstance(result, Skip):
        _log(event="skip", reason=result.reason, route=f"{env.transport}:{env.path}")
        return respond.pass_request(env)
    if isinstance(result, Reject):
        return _local_deny(env, cfg, result.code, result.reason)
    call: Call = result

    # ── the credential for the RTG, read only when a call is actually evaluated ─
    try:
        cfg = with_token(cfg)
    except SecretError as exc:
        return _local_deny(env, cfg, "token_unavailable", str(exc))

    # ── which prompt ────────────────────────────────────────────────────────
    trace_id, trace_source = resolve_trace(env.headers, cfg, _seed(env))
    if trace_id is None:
        return _local_deny(env, cfg, "traceparent_missing",
                           "no traceparent and REVA_ON_MISSING_TRACEPARENT=deny")
    if trace_source == "minted":
        _log(event="warn", code="traceparent_missing",
             reason="no traceparent: this call is its own trace and has no history")
    span = span_id(trace_id, call.span_key)

    # ── who, which chat, and the hops so far: from the table when it knows this trace
    use_store = cfg.history == "interceptor" and trace_source != "minted"
    if use_store and store is None:
        try:
            store = get_store(cfg)
        except StoreError as exc:
            if not cfg.fail_open:
                return _local_deny(env, cfg, "history_unavailable", str(exc))
            _log(event="warn", code="history_unavailable", reason=str(exc))
            use_store = False

    record: Optional[Dict[str, Any]] = None
    if use_store:
        try:
            record = store.get_trace(trace_id)
        except StoreError as exc:
            if not cfg.fail_open:
                return _local_deny(env, cfg, "history_unavailable", str(exc))
            _log(event="warn", code="history_unavailable", reason=str(exc))
            use_store = False

    stored_hops: List[Dict[str, Any]] = []
    thread_source = "stored"
    first_call = not (record and record["principal"])
    if not first_call:
        principal, groups = record["principal"], record["groups"]
        thread_id, turn, started_at = record["thread_id"], record["turn"], record["started_at"]
        stored_hops = record["hops"]
    else:
        # The trace's first call: the user's token and a thread id are read once, here.
        principal, groups, code = resolve_principal(env.headers, cfg)
        if code:
            return _local_deny(env, cfg, code, PRINCIPAL_REASONS[code])
        thread_id, thread_source = resolve_thread(env.headers, call.thread_hint, trace_id)
        if thread_source == "trace":
            _log(event="warn", code="thread_missing",
                 reason="no thread id: this prompt is its own chat")
        turn, started_at = 1, iso_now()
        stored_hops = record["hops"] if record else []
        if use_store:
            try:
                turn, chat_started = store.claim_turn(thread_id, trace_id)
                established = store.establish(trace_id, principal, groups, thread_id,
                                              turn, chat_started)
                # The first writer wins a race, so adopt what is stored. The hops are the
                # ones read above: a hop another call writes in between is not yet history.
                principal, groups = established["principal"], established["groups"]
                thread_id, turn = established["thread_id"], established["turn"]
                started_at = established["started_at"]
            except StoreError as exc:
                if not cfg.fail_open:
                    return _local_deny(env, cfg, "history_unavailable", str(exc))
                _log(event="warn", code="history_unavailable", reason=str(exc))
                use_store = False

    # ── who is acting ───────────────────────────────────────────────────────
    agent_id, agent_source = resolve_agent(env.headers, cfg)
    subject = subject_for(principal, agent_id)
    role = "user" if subject["type"] == "User" and call.action == "invokeAgent" else "assistant"

    hops: List[Dict[str, Any]] = []
    messages: List[Dict[str, Any]] = []
    if cfg.history == "interceptor":
        hops, messages = paired_history(stored_hops, span, cfg.max_hops_sent)

    # ── ask the RTG ─────────────────────────────────────────────────────────
    body = build_request(cfg, call, principal, subject, role, thread_id, turn, started_at,
                         hops, messages, groups)
    if cfg.debug:
        _log(event="debug_request", body=body)
    decision = evaluate(cfg, body, request_headers(cfg, trace_id, span, thread_id),
                        _remaining_ms(context))

    permitted, record_hop, verdict, code = _enforce(cfg, decision)

    if permitted and record_hop and use_store:
        hop = {"span": span, "subject": subject, "action": call.action,
               "resource": {"type": call.resource["type"], "id": call.resource["id"]},
               "time": iso_now(), "role": role,
               "content": clip_utf8(call.prompt, cfg.content_max_bytes)}
        try:
            store.append_hop(trace_id, hop)
        except StoreError as exc:
            # The call already passed policy: say so loudly, do not fail it.
            _log(event="error", code="hop_write_failed", reason=str(exc))

    _log(event="decision", decision=verdict, outcome=decision.outcome, status=decision.status,
         errorType=decision.error_type, reason=decision.reason, attempts=decision.attempts,
         rtgMs=decision.latency_ms, totalMs=int((time.monotonic() - started) * 1000),
         trace=trace_id, traceSource=trace_source, thread=thread_id, threadSource=thread_source,
         turn=turn, firstCall=first_call, action=call.action, resource=call.resource["id"],
         subjectType=subject["type"], subjectSource=agent_source,
         principalHash=sha256_hex(principal)[:12], hopsSent=len(hops),
         route=f"{env.transport}:{env.path}")

    if permitted:
        return respond.pass_request(env)
    return respond.deny(env, cfg.deny_message, code, cfg.deny_status)


def _enforce(cfg: Settings, decision: Decision):
    """(permitted, record the hop, verdict for the log, deny code)."""
    outcome = decision.outcome
    if outcome == ALLOW:
        return True, True, "permit", ""
    if outcome == CONDITIONAL:
        if cfg.conditional_allow == "allow":
            return True, True, "permit_conditional", ""
        return False, False, "deny", "policy_denied"
    if outcome == POLICY_DENY:
        if cfg.monitor_mode:
            # The call ran, so it is part of the path later hops are judged against.
            return True, True, "monitor_would_deny", ""
        return False, False, "deny", "policy_denied"
    if outcome == REJECTED:
        return False, False, "deny", "rtg_rejected"
    if cfg.fail_open:      # OPERATIONAL: a dependency, not a decision
        return True, False, "permit_fail_open", ""
    return False, False, "deny", "rtg_unavailable"
