"""One reading of the gateway event, whichever target type produced it.

The gateway sends two shapes (AgentCore developer guide, "interceptor types"):

    MCP targets   {"mcp":  {"gatewayRequest": {path, httpMethod, headers, body = PARSED JSON},
                            "gatewayResponse": {...}}}                 (RESPONSE leg only)
    HTTP targets  {"http": {"gatewayRequest": {path, httpMethod, headers, body = BASE64},
                            "gatewayResponse": {...}}}                 (Runtime/A2A, passthrough)

`headers` is present only when the interceptor is attached with passRequestHeaders.
On the HTTP RESPONSE leg `gatewayRequest` is null, so a response leg cannot be
tied back to its request there; this interceptor is REQUEST-only and passes any
response through untouched.
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# The decoded body of an HTTP target is parsed to find the prompt. Anything larger
# is not parsed (it is still forwarded untouched) so a huge payload cannot
# exhaust the function.
MAX_PARSE_BYTES = 2 * 1024 * 1024


class EventError(Exception):
    """The event is not a gateway interceptor event."""


@dataclass
class Envelope:
    leg: str                                   # "request" | "response"
    transport: str                             # "mcp" | "http"
    http_method: str
    path: str
    headers: Dict[str, str]                    # lower-cased names
    body: Any                                  # parsed JSON (mcp) / parsed JSON or None (http)
    body_bytes: bytes = b""                    # http: decoded body
    raw_body: Optional[str] = None             # http: the base64 string exactly as received
    response: Optional[Dict[str, Any]] = None  # the gatewayResponse block, if any
    request_id: str = ""                       # Lambda client context REQUEST_ID (HTTP targets)
    extra: Dict[str, Any] = field(default_factory=dict)


def _lower_headers(raw: Any) -> Dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    return {str(k).lower(): v if isinstance(v, str) else str(v)
            for k, v in raw.items() if v is not None}


def _decode_base64(raw: Any) -> bytes:
    """Bytes from a base64 field, or b"" when absent or malformed. Never raises."""
    if not raw:
        return b""
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if not isinstance(raw, str):
        return b""
    try:
        return base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError):
        return b""


def _request_id(context: Any) -> str:
    """The gateway's REQUEST_ID from the Lambda client context, when there is one."""
    try:
        custom = getattr(getattr(context, "client_context", None), "custom", None)
        if isinstance(custom, dict):
            return str(custom.get("REQUEST_ID") or custom.get("request_id") or "")
    except Exception:  # noqa: BLE001 - client context is optional, never a reason to fail
        pass
    return ""


def parse_event(event: Any, context: Any = None) -> Envelope:
    if not isinstance(event, dict):
        raise EventError("event is not an object")

    if isinstance(event.get("mcp"), dict):
        block = event["mcp"]
        request = block.get("gatewayRequest")
        request = request if isinstance(request, dict) else {}
        response = block.get("gatewayResponse")
        body = request.get("body")
        if isinstance(body, str):          # tolerate a stringified body
            try:
                body = json.loads(body)
            except ValueError:
                pass
        return Envelope(
            leg="response" if isinstance(response, dict) else "request",
            transport="mcp",
            http_method=str(request.get("httpMethod") or "POST").upper(),
            path=str(request.get("path") or "/mcp"),
            headers=_lower_headers(request.get("headers")),
            body=body,
            response=response if isinstance(response, dict) else None,
            request_id=_request_id(context),
        )

    if isinstance(event.get("http"), dict):
        block = event["http"]
        request = block.get("gatewayRequest")
        request = request if isinstance(request, dict) else {}
        response = block.get("gatewayResponse")
        raw = request.get("body")
        data = _decode_base64(raw)
        parsed: Any = None
        if data and len(data) <= MAX_PARSE_BYTES:
            try:
                parsed = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                parsed = None
        return Envelope(
            leg="response" if isinstance(response, dict) else "request",
            transport="http",
            http_method=str(request.get("httpMethod") or "POST").upper(),
            path=str(request.get("path") or ""),
            headers=_lower_headers(request.get("headers")),
            body=parsed,
            body_bytes=data,
            raw_body=raw if isinstance(raw, str) else None,
            response=response if isinstance(response, dict) else None,
            request_id=_request_id(context),
        )

    raise EventError("event has neither an 'mcp' nor an 'http' block")
