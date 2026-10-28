"""Shared test helpers: a loopback fake RTG, event builders and a JWT helper. No network."""

from __future__ import annotations

import base64
import dataclasses
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional

from interceptor.config import Settings

TOKEN = "rtg-secret-token"
TRACE = "a" * 32
OTHER_TRACE = "c" * 32


def make_jwt(claims: Dict[str, Any]) -> str:
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{payload}.signature"


def bearer(claims: Optional[Dict[str, Any]] = None) -> str:
    return "Bearer " + make_jwt(claims if claims is not None else {"sub": "u1"})


def traceparent(trace: str = TRACE, span: str = "b" * 16) -> str:
    return f"00-{trace}-{span}-01"


def settings(**overrides: str) -> Settings:
    """Settings from a clean environment, plus the given REVA_* overrides. The RTG token is
    already in place: the deployed function reads it from Secrets Manager, not the environment."""
    env = {"REVA_HISTORY_TABLE": "table", "REVA_BASE_URL": "http://127.0.0.1:9"}
    env.update(overrides)
    return dataclasses.replace(Settings.from_env(env), token=TOKEN)


def mcp_event(name: str = "acme-tools___query", arguments: Optional[Dict[str, Any]] = None,
              headers: Optional[Dict[str, str]] = None, method: str = "tools/call",
              rpc_id: Any = 1, body: Any = "default", http_method: str = "POST",
              response: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if body == "default":
        body = {"jsonrpc": "2.0", "id": rpc_id, "method": method,
                "params": {"name": name, "arguments": arguments or {}}}
    block: Dict[str, Any] = {"gatewayRequest": {
        "path": "/mcp", "httpMethod": http_method,
        "headers": headers if headers is not None else {}, "body": body}}
    if response is not None:
        block["gatewayResponse"] = response
    return {"interceptorInputVersion": "1.0", "mcp": block}


def http_event(path: str = "/agent-a/invocations", payload: Any = None,
               headers: Optional[Dict[str, str]] = None, raw: Optional[bytes] = None,
               http_method: str = "POST") -> Dict[str, Any]:
    data = raw if raw is not None else json.dumps(payload).encode()
    return {"interceptorInputVersion": "1.0", "http": {"gatewayRequest": {
        "path": path, "httpMethod": http_method,
        "headers": headers if headers is not None else {},
        "body": base64.b64encode(data).decode()}}}


def a2a_payload(text: str = "Which projects are at risk?", context_id: str = "",
                rpc_id: Any = "req-1") -> Dict[str, Any]:
    message: Dict[str, Any] = {"role": "user", "parts": [{"kind": "text", "text": text}]}
    if context_id:
        message["contextId"] = context_id
    return {"jsonrpc": "2.0", "id": rpc_id, "method": "message/send",
            "params": {"message": message}}


class FakeRTG:
    """A loopback HTTP server that records requests exactly as received and answers
    from a script. Header NAMES are kept as sent, so tests can assert their case."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.script: List[Dict[str, Any]] = []
        self.default = {"status": 200, "body": {"decision": True}}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length)
                try:
                    parsed = json.loads(raw)
                except ValueError:
                    parsed = None
                outer.requests.append({"path": self.path, "headers": list(self.headers.items()),
                                       "json": parsed})
                step = outer.script.pop(0) if outer.script else outer.default
                if step.get("delay"):
                    time.sleep(step["delay"])
                if step.get("drop"):
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                payload = step.get("raw")
                if payload is None:
                    payload = json.dumps(step.get("body", {})).encode()
                self.send_response(step["status"])
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        kwargs={"poll_interval": 0.01}, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"

    def queue(self, status: int, body: Any = None, **kwargs: Any) -> "FakeRTG":
        self.script.append({"status": status, "body": body if body is not None else {},
                            **kwargs})
        return self

    def header_names(self, index: int = -1) -> List[str]:
        return [name for name, _ in self.requests[index]["headers"]]

    def header(self, name: str, index: int = -1) -> Optional[str]:
        for key, value in self.requests[index]["headers"]:
            if key.lower() == name.lower():
                return value
        return None

    def __enter__(self) -> "FakeRTG":
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
