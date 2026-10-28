"""What the Lambda returns to the gateway.

The output is versioned and shaped per transport. These shapes were each verified
against a live gateway; getting one wrong is not a deny, it is
`InterceptorException - Received invalid response from interceptor` for a permit
as well as a refusal.

    pass an MCP request     {"mcp": {"transformedGatewayRequest": {"body": <the request body>}}}
                            (the version alone is accepted and then answers the caller
                            with an empty body: an absent transform means "this is the
                            whole answer")
    pass an HTTP request    {"http": {"transformedGatewayRequest": {"body": <base64 as received>}}}
    pass any response       MCP echoes the body and status; HTTP says nothing: `{"http": {}}`
    deny                    a REQUEST interceptor that returns a transformed RESPONSE
                            short-circuits: the target is never called.

A deny is HTTP 403 whether policy refused it or no decision could be obtained. The
body's `data.code` says which. JSON-RPC either way for MCP and A2A, so a caller
parses one error shape whichever route refused it.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional

from .event import Envelope

OUTPUT_VERSION = "1.0"
JSONRPC_DENY_CODE = -32003


def pass_request(env: Envelope) -> Dict[str, Any]:
    if env.transport == "http":
        if env.raw_body:
            return {"interceptorOutputVersion": OUTPUT_VERSION,
                    "http": {"transformedGatewayRequest": {"body": env.raw_body}}}
        return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}
    # `{}`, never null, for a request with no body (a GET that opens the event stream):
    # that is what the live gateway was verified to accept.
    return {"interceptorOutputVersion": OUTPUT_VERSION,
            "mcp": {"transformedGatewayRequest": {
                "body": env.body if env.body is not None else {}}}}


def pass_response(env: Envelope) -> Dict[str, Any]:
    if env.transport == "http":
        return {"interceptorOutputVersion": OUTPUT_VERSION, "http": {}}
    response = env.response or {}
    return {"interceptorOutputVersion": OUTPUT_VERSION,
            "mcp": {"transformedGatewayResponse": {
                "body": response.get("body", {}),
                "statusCode": response.get("statusCode", 200)}}}


def _jsonrpc_error(request_id: Any, message: str, code: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id if request_id is not None else 0,
            "error": {"code": JSONRPC_DENY_CODE, "message": message, "data": {"code": code}}}


def _deny(transport: str, body: Any, message: str, code: str, status: int) -> Dict[str, Any]:
    request_id = body.get("id") if isinstance(body, dict) else None
    if transport == "http":
        if isinstance(body, dict) and "jsonrpc" in body:
            payload = _jsonrpc_error(request_id, message, code)
        else:
            payload = {"error": {"type": "permission_denied", "code": code,
                                 "message": message}}
        encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        return {"interceptorOutputVersion": OUTPUT_VERSION,
                "http": {"transformedGatewayResponse": {
                    "statusCode": status, "contentType": "application/json",
                    "body": encoded}}}
    return {"interceptorOutputVersion": OUTPUT_VERSION,
            "mcp": {"transformedGatewayResponse": {
                "statusCode": status, "body": _jsonrpc_error(request_id, message, code)}}}


def deny(env: Envelope, message: str, code: str, status: int = 403) -> Dict[str, Any]:
    return _deny(env.transport, env.body, message, code, status)


def emergency_deny(event: Any, message: str, code: str, status: int = 403,
                   body: Optional[Any] = None) -> Dict[str, Any]:
    """A deny built from the raw event, for when parsing it is what failed."""
    transport = "http" if isinstance(event, dict) and isinstance(event.get("http"), dict) else "mcp"
    return _deny(transport, body, message, code, status)
