"""RESPONSE-leg finalize: extract final answer + trace/thread, POST summarize.

HTTP AgentCore RESPONSE events have `gatewayRequest: null`, so correlation cannot
come from request headers. Runtime agents embed `_reva` in the JSON body
(see the README, step 7). MCP RESPONSE still includes the request, so headers
work there.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from .event import Envelope
from .trace import THREAD_HEADER, parse_traceparent
from .util import canonical_json, clip_utf8

A2A_DATA_PART_MAX = 8192
REPLY_FIELDS = ("message", "reply", "text", "content", "output")


@dataclass
class FinalizeHint:
    trace_id: str = ""
    thread_id: str = ""
    output: str = ""
    should_summarize: bool = False


def _b64_json(raw: Any) -> Any:
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw:
        return None
    try:
        data = base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


def _response_text(env: Envelope) -> str:
    """The response body as text: base64 on an HTTP target, parsed JSON or a string on MCP."""
    body = (env.response or {}).get("body")
    if isinstance(body, (dict, list)):
        return json.dumps(body)
    if not isinstance(body, str) or not body:
        return ""
    if env.transport == "http":
        try:
            return base64.b64decode(body, validate=False).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return ""
    return body


def _response_payload(env: Envelope) -> Any:
    block = env.response or {}
    body = block.get("body")
    if env.transport == "http":
        return _b64_json(body)
    if isinstance(body, str):
        try:
            return json.loads(body)
        except ValueError:
            return body
    return body


def _trace_id(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    parsed = parse_traceparent(text)
    if parsed:
        return parsed
    lower = text.lower()
    if len(lower) == 32 and all(c in "0123456789abcdef" for c in lower):
        return lower
    return ""


def _from_reva_block(payload: Any) -> Tuple[str, str, Optional[bool]]:
    """(trace_id, thread_id, summarize override or None if absent)."""
    if not isinstance(payload, dict):
        return "", "", None
    reva = payload.get("_reva")
    if not isinstance(reva, dict):
        out = payload.get("output")
        reva = out.get("_reva") if isinstance(out, dict) else None
    if not isinstance(reva, dict):
        return "", "", None
    trace = _trace_id(reva.get("trace") or reva.get("trace_id") or reva.get("traceparent"))
    thread = str(reva.get("thread") or reva.get("thread_id") or "").strip()
    if "summarize" not in reva:
        return trace, thread, None
    return trace, thread, bool(reva.get("summarize"))


def _parts_text(value: Any) -> str:
    """Text of A2A-style parts (`[{"text": ...}, {"data": ...}]`): the text parts, and a data
    part as JSON, in order. A bare string is its own text."""
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return ""
    texts = []
    for part in value:
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if isinstance(text, str):
            texts.append(text)
        elif part.get("data") is not None:
            texts.append(clip_utf8(canonical_json(part["data"]), A2A_DATA_PART_MAX))
    return "\n".join(texts)


def _message_text(message: Any) -> str:
    """Text of an A2A Message: `{parts: [...]}`, or `{message: {parts: [...]}}`."""
    if not isinstance(message, dict):
        return ""
    parts = message.get("parts")
    if not isinstance(parts, list) and isinstance(message.get("message"), dict):
        parts = message["message"].get("parts")
    return _parts_text(parts)


def _task_text(task: Any) -> str:
    """The answer in an A2A Task: its status message, else its artifacts' parts, in order."""
    if not isinstance(task, dict):
        return ""
    status = task.get("status")
    if isinstance(status, dict):
        text = _message_text(status.get("message"))
        if text:
            return text
    artifacts = task.get("artifacts")
    if isinstance(artifacts, list):
        texts = [_parts_text(a.get("parts")) for a in artifacts if isinstance(a, dict)]
        texts = [t for t in texts if t]
        if texts:
            return "\n".join(texts)
    return _message_text(task)


def _reply_field(payload: Dict[str, Any]) -> str:
    """The agent's own reply field: a plain string, or one level down inside an object."""
    for key in REPLY_FIELDS:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, dict):
            nested = _message_text(value)
            if not nested:
                nested = next((value[k] for k in ("message", "reply", "text", "content")
                               if isinstance(value.get(k), str) and value[k]), "")
            if nested:
                return nested
    return ""


def _openai_text(payload: Dict[str, Any]) -> str:
    choices = payload.get("choices")
    first = choices[0] if isinstance(choices, list) and choices else None
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    text = ""
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str):
            text = content
        elif isinstance(content, list):
            text = _parts_text(content)
    if not text and isinstance(first.get("text"), str):
        text = first["text"]
    return text


def _jsonrpc_text(payload: Dict[str, Any]) -> str:
    """An A2A Message or Task in `result`, or an MCP tools/call result."""
    result = payload.get("result")
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        text = _task_text(result)
        if not text and isinstance(result.get("content"), list):
            text = _parts_text(result["content"])
        elif not text and isinstance(result.get("content"), str):
            text = result["content"]
        # No text anywhere: the result itself still says what the call returned.
        return text or json.dumps(result, separators=(",", ":"))
    error = payload.get("error")
    if isinstance(error, dict):
        return "error: " + str(error.get("message") or "unknown")
    return ""


def assistant_text(body: str) -> str:
    """The agent's final answer from a response body, for `/trace/summarize`.

    Covers OpenAI chat.completions, MCP tools/call, A2A Message and Task (JSON-RPC and REST),
    and the plain `message`/`reply`/`text`/`content`/`output` shapes of Runtime agents. A body
    that is not JSON, or has no recognised shape, is reported as it is so the turn still
    carries an answer. "" only when there is no body.
    """
    if not isinstance(body, str) or not body.strip():
        return ""
    try:
        payload = json.loads(body)
    except ValueError:
        return body.strip()
    if not isinstance(payload, dict):
        return body.strip()
    text = _openai_text(payload)
    if not text and ("jsonrpc" in payload or "result" in payload or "error" in payload):
        text = _jsonrpc_text(payload)
    if not text:
        text = _task_text(payload)            # the A2A REST binding: the body is the Message
    if not text:
        text = _reply_field(payload)
    return text.strip() or body.strip()


def from_envelope(env: Envelope) -> FinalizeHint:
    """Best-effort finalize hint from a RESPONSE interceptor event.

    Summarize at end of the UI chat turn (user → UI), not mid-trace nested hops.
    Entry is the session/thread key on the call (`X-Reva-Session-Id` /
    `X-Reva-Thread-Id`), or `_reva.summarize` when HTTP RESPONSE
    has no gatewayRequest. Do **not** use X-Transaction-Token for this — that
    only selects User vs token-derived subject on REQUEST.
    """
    payload = _response_payload(env)
    trace, reva_thread, summarize_override = _from_reva_block(payload)
    output = assistant_text(_response_text(env))

    # Only the explicit session keys mark the entry hop. `Mcp-Session-Id` does not: the
    # agents send it on their nested tool calls too, so a tool hop's RESPONSE would be
    # summarised with a tool result as the "answer".
    header_thread = (env.headers.get("x-reva-session-id")
                     or env.headers.get(THREAD_HEADER)
                     or "").strip()
    # UI Session-Id on the request is authoritative for RTG's thread. Runtime
    # agents often mint a local thread when allowlists drop the header — that
    # id must not be used for /trace/summarize.
    thread = header_thread or reva_thread

    if not trace:
        trace = parse_traceparent(env.headers.get("traceparent", "")) or ""

    # End of trace for the UI turn: session/thread present again, or the agent
    # armed `_reva.summarize` because HTTP RESPONSE dropped gatewayRequest.
    entry = bool(header_thread)
    if entry:
        should = bool(trace)
    elif summarize_override is True:
        should = bool(trace)
    else:
        should = False

    if not trace:
        should = False
    return FinalizeHint(
        trace_id=trace, thread_id=thread, output=output, should_summarize=should)
