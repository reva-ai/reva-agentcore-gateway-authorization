"""The pipeline: event in, gateway response out. Nothing here raises past `handle`.

    parse -> (response leg? finalize+pass) -> config check -> classify -> trace
          -> principal / thread from the call -> subject
          -> ask the RTG -> enforce -> respond

Hop history lives in the RTG (Postgres trace_hop). This Lambda sends
`traceparent` and, on the first call of a trace, the thread id and `session.id`. It does not
send `context.hops` or prior `session.messages`. On RESPONSE for the UI chat turn it POSTs
`/trace/summarize` so the RTG can attach `session.messages` on later turns.

Failure policy, in one place:

    local problems   no RTG token, no principal, malformed body, unresolvable resource,
                     bad config, internal error                        always deny
    RTG policy deny  403, a false `decision`, USER_NOT_FOUND/DISABLED  deny
                                                    (monitor mode logs it and passes)
    RTG invalid      any other 4xx: our request is wrong                always deny
    dependency down  RTG 401/404/413/424/429/5xx, timeout
                                                     deny, or pass if REVA_FAIL_OPEN
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

from . import respond
from .classify import Call, Reject, Skip, classify
from .config import Settings
from .event import Envelope, EventError, parse_event
from .finalize import from_envelope as finalize_hint
from .identity import bearer_token, resolve_principal
from .rtg import (ALLOW, CONDITIONAL, POLICY_DENY, REJECTED, Decision, build_request,
                  context_for, evaluate, request_headers, summarize)
from .secret import SecretError, with_token
from .trace import resolve_thread, resolve_trace, span_id
from .util import canonical_json, sha256_hex

PRINCIPAL_REASONS = {
    "missing_authorization": "no bearer token and no X-Transaction-Token: attach "
                             "the interceptor with passRequestHeaders=true and "
                             "send the user's JWT (and txn token on nested hops)",
    "invalid_authorization": "the Authorization bearer token is not a decodable JWT",
    "principal_unresolved": "the configured user claim is missing from the token",
}


def _log(**fields: Any) -> None:
    print(json.dumps(fields, default=str, separators=(",", ":")))


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


def handle(event: Any, context: Any, cfg: Settings) -> Dict[str, Any]:
    started = time.monotonic()
    try:
        env = parse_event(event, context)
    except EventError as exc:
        _log(event="local_deny", code="malformed_event", reason=str(exc))
        return respond.emergency_deny(event, cfg.deny_message, "malformed_event",
                                      cfg.deny_status)

    if env.leg == "response":
        return _handle_response(env, cfg)

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

    # ── who is acting (token-enrich: user JWT + txn token) ──────────────────
    # Entry (UI chat): User from the JWT. Nested hops: carry Authorization and
    # X-Transaction-Token; RTG derives Agent + principal from the txn token
    # (body omits subject/principal). AgentCore Runtime often never surfaces
    # Authorization on /invocations, so a nested hop may carry only the txn —
    # that is still valid.
    txn_token = (env.headers.get("x-transaction-token")
                 or env.headers.get("x-reva-token") or "").strip()
    if txn_token[:7].lower() == "bearer ":
        txn_token = txn_token[7:].strip()
    principal, groups, code = resolve_principal(env.headers, cfg)
    if code == "missing_authorization" and txn_token:
        principal, groups, code = "", [], ""
        _log(event="warn", code="nested_txn_no_jwt",
             reason="no Authorization on nested hop; evaluating from X-Transaction-Token only")
    if code:
        return _local_deny(env, cfg, code, PRINCIPAL_REASONS[code])
    # The thread is recorded on the first call of a turn only. A later hop carries the prior
    # transaction token and the RTG joins it to the thread through the trace, so sending a
    # thread id again could only split the thread if a hop carried a different one.
    if txn_token:
        thread_id, thread_source = "", "nested_hop"
    else:
        thread_id, thread_source = resolve_thread(env.headers, call.thread_hint, trace_id)
        if thread_source == "trace":
            _log(event="warn", code="thread_missing",
                 reason="no thread id: this prompt is its own chat")

    subject = {"type": "User", "id": principal} if principal else {"type": "User", "id": "derived"}
    # The speaker the RTG records. Earlier user requests are recalled from hops with
    # role=user, so the first call of a turn (the end user's utterance) is always "user";
    # a later hop, which carries the prior transaction token, is the agent.
    role = (call.role or "agent") if txn_token else "user"
    subject_source = "transaction_token" if txn_token else "user"
    user_bearer = bearer_token(env.headers)

    # ── ask the RTG (rtg/a2a token-evaluation body) ─────────────────────────
    pairs, left_out = context_for(cfg, call)
    body = build_request(cfg, call, principal, subject, role, groups,
                         thread_id=thread_id, omit_subject=bool(txn_token), context=pairs)
    if cfg.debug:
        _log(event="debug_request", body=body)
        if left_out:        # names and reasons only, never values
            _log(event="debug_context_left_out", pairs=left_out)
    headers = request_headers(cfg, trace_id, span, thread_id,
                              user_bearer=user_bearer, txn_token=txn_token)
    decision = evaluate(cfg, body, headers, _remaining_ms(context))
    if decision.status == 400 and pairs:
        # The RTG turns a whole request away when one context pair is outside what it reads.
        # The pairs are filtered first, but if its rules move ahead of the filter, decide the
        # call without them rather than lose the decision.
        _log(event="warn", code="context_refused",
             reason="the RTG refused the request with context: evaluating again without it")
        body["rtg/a2a"].pop("context", None)
        decision = evaluate(cfg, body, headers, _remaining_ms(context))

    permitted, verdict, code = _enforce(cfg, decision)

    _log(event="decision", decision=verdict, outcome=decision.outcome, status=decision.status,
         errorType=decision.error_type, reason=decision.reason, attempts=decision.attempts,
         rtgMs=decision.latency_ms, totalMs=int((time.monotonic() - started) * 1000),
         trace=trace_id, traceSource=trace_source, thread=thread_id, threadSource=thread_source,
         action=call.action, resource=call.resource["id"],
         subjectType=("derived" if txn_token else "User"), subjectSource=subject_source,
         principalHash=sha256_hex(principal)[:12],
         route=f"{env.transport}:{env.path}")

    if permitted:
        out = respond.pass_request(env, txn_token=decision.token or None)
        transform = (out.get("http") or out.get("mcp") or {})
        req = transform.get("transformedGatewayRequest") or {}
        hdrs = req.get("headers") or {}
        # Never log token values — only the shape the gateway will validate.
        _log(event="pass_request",
             keys=sorted(transform.keys()),
             hasBody=bool(req.get("body")),
             bodyBytes=len(req.get("body") or ""),
             headerNames=sorted(hdrs.keys()),
             hasTxn=bool(decision.token),
             txnInjected=bool(hdrs),
             outputKeys=sorted(out.keys()))
        return out
    return respond.deny(env, cfg.deny_message, code, cfg.deny_status)


def _enforce(cfg: Settings, decision: Decision):
    """(permitted, verdict for the log, deny code)."""
    outcome = decision.outcome
    if outcome == ALLOW:
        return True, "permit", ""
    if outcome == CONDITIONAL:
        if cfg.conditional_allow == "allow":
            return True, "permit_conditional", ""
        return False, "deny", "policy_denied"
    if outcome == POLICY_DENY:
        if cfg.monitor_mode:
            return True, "monitor_would_deny", ""
        return False, "deny", "policy_denied"
    if outcome == REJECTED:
        return False, "deny", "rtg_rejected"
    if cfg.fail_open:      # OPERATIONAL: a dependency, not a decision
        return True, "permit_fail_open", ""
    return False, "deny", "rtg_unavailable"


def _handle_response(env: Envelope, cfg: Settings) -> Dict[str, Any]:
    """Pass the response through; at end of the UI chat turn, best-effort POST
    /trace/summarize so RTG can populate session.messages on later turns.
    """
    try:
        hint = finalize_hint(env)
        summarize_status = 0
        if hint.should_summarize and hint.trace_id:
            try:
                cfg = with_token(cfg)
                summarize_status = summarize(
                    cfg, hint.trace_id, hint.thread_id, hint.output)
            except SecretError as exc:
                _log(event="summarize_skip", reason=str(exc)[:200])
        # Shape only — never headers, bodies, tokens, or prompt/output text.
        _log(event="response_leg",
             transport=env.transport,
             path=env.path,
             shouldSummarize=hint.should_summarize,
             summarizeStatus=summarize_status,
             hasTrace=bool(hint.trace_id),
             hasThread=bool(hint.thread_id),
             outputBytes=len(hint.output or ""))
    except Exception as exc:  # noqa: BLE001 - never fail the caller on finalize parse
        _log(event="response_leg", error=type(exc).__name__, detail=str(exc)[:200])
    return respond.pass_response(env)
