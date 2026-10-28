"""Which prompt (trace), which call (span) and which chat (thread).

The only thing agents must send is a W3C `traceparent`, one trace per user
prompt, the same on every hop. That id keys everything this interceptor stores.

trace   `traceparent`, else the optional REVA_TRACE_HEADER, else minted.
span    derived from the trace and the call, so a gateway retry of the same call
        has the same span and is recorded once.
thread  the chat. Needed on a trace's first call only; it is then stored with the
        trace. The RTG requires one, so there is always a value.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional, Tuple

from .config import Settings
from .util import sha256_hex

_TRACEPARENT = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_XRAY_ROOT = re.compile(r"Root=1-([0-9a-f]{8})-([0-9a-f]{24})", re.IGNORECASE)
_HEX32 = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)

THREAD_HEADER = "x-reva-thread-id"
MAX_THREAD_CHARS = 256


def parse_traceparent(value: str) -> Optional[str]:
    """The trace id out of a valid `traceparent`, else None."""
    match = _TRACEPARENT.match((value or "").strip().lower())
    if not match:
        return None
    version, trace_id, parent_id, _flags = match.groups()
    if version == "ff" or trace_id == "0" * 32 or parent_id == "0" * 16:
        return None
    return trace_id


def _from_trace_header(value: str) -> Optional[str]:
    """A 32-hex trace id from a configured header: used as is when it already is one,
    taken out of an X-Ray `Root=1-…` header, otherwise hashed so any stable id works."""
    value = (value or "").strip()
    if not value:
        return None
    if _HEX32.match(value) and set(value) != {"0"}:
        return value.lower()
    xray = _XRAY_ROOT.search(value)
    if xray:
        return (xray.group(1) + xray.group(2)).lower()
    return sha256_hex(value)[:32]


def resolve_trace(headers: Mapping[str, str], cfg: Settings, seed: str
                  ) -> Tuple[Optional[str], str]:
    """(trace id, source). `source` is "traceparent", "header", "minted" or "missing".

    A minted id is deterministic in `seed`, so a retry of the same call agrees with
    itself. It joins no other call, so a minted trace has no history.
    """
    trace_id = parse_traceparent(headers.get("traceparent", ""))
    if trace_id:
        return trace_id, "traceparent"
    if cfg.trace_header:
        trace_id = _from_trace_header(headers.get(cfg.trace_header, ""))
        if trace_id:
            return trace_id, "header"
    if cfg.on_missing_traceparent == "deny":
        return None, "missing"
    return sha256_hex(seed)[:32], "minted"


def span_id(trace_id: str, key: str) -> str:
    return sha256_hex(f"{trace_id}:{key}")[:16]


def traceparent_header(trace_id: str, span: str) -> str:
    return f"00-{trace_id}-{span}-01"


def resolve_thread(headers: Mapping[str, str], hint: str, trace_id: str) -> Tuple[str, str]:
    """(thread id, source), for a trace's first call.

    `X-Reva-Thread-Id`, then the A2A `contextId`, then the MCP session id. With none
    of them the trace is its own thread (the RTG's own fallback): the prompt is
    judged, but cannot be linked to earlier prompts of the same chat.
    """
    for source, value in (("header", headers.get(THREAD_HEADER, "")),
                          ("contextId", hint),
                          ("mcp-session-id", headers.get("mcp-session-id", ""))):
        value = (value or "").strip()
        if value:
            return value[:MAX_THREAD_CHARS], source
    return trace_id, "trace"
