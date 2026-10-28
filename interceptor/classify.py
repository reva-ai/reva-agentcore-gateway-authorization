"""What is being called: action, resource and prompt, from the shape of the payload.

Entity TYPES come from the protocol, never from names:

    MCP tools/call                       Tool  `<server>/<tool>`           invokeTool
    HTTP, A2A JSON-RPC message/send      Agent `<first path segment>`      invokeAgent
    HTTP, AgentCore Runtime /invocations Agent `<first path segment>`      invokeAgent

Ids come from the payload too: the MCP tool name is `<target>___<tool>`, and an
HTTP target is the first segment of the path. The event carries no target ARN,
URL or type. `REVA_TARGETS` can rename a target's id or exclude it, and is the
only topology configuration.

Inference (LLM) traffic is NOT evaluated in v1: an agent that calls its model
directly never reaches the gateway, and the gateway's own `/inference` targets
are opt-in. Such a request is treated as unclassified.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

from .config import Settings
from .event import Envelope
from .util import canonical_json, clip_utf8, sha256_hex

A2A_METHODS = ("message/send", "message/stream", "SendMessage", "SendStreamingMessage")
RUNTIME_PATH = re.compile(r"^/([^/]+)/invocations/?$")
PROMPT_FIELDS = ("prompt", "input", "message", "query", "text")
INFERENCE_PREFIXES = ("/inference/", "/model/")
TOOL_SEPARATOR = "___"


@dataclass
class Call:
    kind: str                       # "tool" | "agent"
    action: str                     # invokeTool | invokeAgent
    resource: Dict[str, Any]
    prompt: str
    target: str
    span_key: str
    thread_hint: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Skip:
    reason: str


@dataclass
class Reject:
    code: str
    reason: str


Result = Union[Call, Skip, Reject]


def _jsonrpc_id(body: Dict[str, Any]) -> str:
    value = body.get("id")
    return "" if value is None else str(value)


def _override(cfg: Settings, target: str) -> Dict[str, Any]:
    entry = cfg.targets.get(target)
    return entry if isinstance(entry, dict) else {}


def _unclassified(cfg: Settings, reason: str) -> Result:
    if cfg.unclassified == "deny":
        return Reject("unclassified_traffic", reason)
    return Skip(reason)


def classify(env: Envelope, cfg: Settings) -> Result:
    if env.transport == "mcp":
        return _classify_mcp(env, cfg)
    return _classify_http(env, cfg)


# ── MCP ──────────────────────────────────────────────────────────────────────

def _classify_mcp(env: Envelope, cfg: Settings) -> Result:
    if env.http_method != "POST":
        # A GET opens the server-to-client stream and a DELETE ends the session.
        # Neither can carry a tool call.
        return Skip(f"mcp {env.http_method}")

    body = env.body
    if isinstance(body, list):
        # A JSON-RPC batch. Judge it only if it could hide a tool call.
        if any(isinstance(item, dict) and item.get("method") == "tools/call"
               for item in body):
            return Reject("batch_unsupported", "JSON-RPC batch containing tools/call")
        return Skip("mcp batch without tools/call")
    if not isinstance(body, dict):
        return Reject("malformed_body", "MCP body is not a JSON-RPC object")

    method = body.get("method")
    if method != "tools/call":
        if isinstance(method, str) and method:
            # initialize, tools/list, ping, notifications/*: no tool is called.
            return Skip(f"mcp {method}")
        return Reject("malformed_body", "MCP body has no method")

    params = body.get("params")
    params = params if isinstance(params, dict) else {}
    name = params.get("name")
    if not isinstance(name, str) or not name.strip():
        return Reject("malformed_body", "tools/call without a tool name")
    name = name.strip()

    if TOOL_SEPARATOR in name:
        target, _, tool = name.partition(TOOL_SEPARATOR)
    else:
        # The gateway's own search tool has no `<target>___` prefix.
        if not cfg.eval_builtin_tools:
            return Skip(f"built-in tool {name}")
        target, tool = "gateway", name

    if not target or not tool:
        if cfg.unknown_resource == "unknown":
            target, tool = target or "unknown-server", tool or "unknown-tool"
        else:
            return Reject("unresolvable_resource", f"cannot split tool name {name!r}")

    override = _override(cfg, target)
    if override.get("kind") == "skip":
        return Skip(f"target {target} excluded by REVA_TARGETS")
    server = str(override.get("id") or target)

    arguments = params.get("arguments")
    arguments = arguments if isinstance(arguments, dict) else {}

    resource: Dict[str, Any] = {"type": "Tool", "id": f"{server}/{tool}", "name": tool}
    if cfg.tool_parents:
        resource["parents"] = [{"type": "MCPServer", "id": server}]
        resource["properties"] = {"name": tool, "connectionType": "mcp"}
    if override.get("endpoint"):
        resource.setdefault("properties", {})["endpoint"] = {
            "url": str(override["endpoint"]), "type": "MCP"}

    prompt = canonical_json(arguments) if arguments else tool
    return Call(
        kind="tool", action="invokeTool", resource=resource,
        prompt=clip_utf8(prompt, cfg.prompt_max_bytes), target=target,
        span_key="|".join(("tools/call", name, canonical_json(arguments),
                           _jsonrpc_id(body))),
        arguments=arguments,
    )


# ── HTTP (AgentCore Runtime agents, A2A, passthrough) ────────────────────────

def _first_segment(path: str) -> str:
    parts = [p for p in (path or "").split("/") if p]
    return parts[0] if parts else ""


def _a2a_text(params: Dict[str, Any]) -> str:
    message = params.get("message")
    parts = message.get("parts") if isinstance(message, dict) else None
    texts = []
    for part in parts if isinstance(parts, list) else []:
        text = part.get("text") if isinstance(part, dict) else None
        if isinstance(text, str) and text.strip():
            texts.append(text.strip())
    return "\n".join(texts)


def _a2a_thread_hint(params: Dict[str, Any]) -> str:
    message = params.get("message")
    for holder in (message if isinstance(message, dict) else {}, params):
        value = holder.get("contextId")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _a2a_arguments(body: Dict[str, Any], params: Dict[str, Any]) -> Dict[str, Any]:
    """The caller's own key/value pairs on an A2A message: its free-form `metadata`.

    A2A has no argument map, so `metadata` plays the part `params.arguments` plays for a tool
    call. The spec allows it on the message, on the send params and on the request; the most
    specific holder wins a repeated key. Nothing here is sent to the RTG as it stands:
    `REVA_CONTEXT_MAP` picks the keys, the same way it does for a tool call.
    """
    message = params.get("message")
    arguments: Dict[str, Any] = {}
    for holder in (body, params, message if isinstance(message, dict) else {}):
        metadata = holder.get("metadata")
        if isinstance(metadata, dict):
            arguments.update(metadata)
    return arguments


def _plain_prompt(env: Envelope, target: str) -> str:
    body = env.body
    if isinstance(body, dict):
        for name in PROMPT_FIELDS:
            value = body.get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
        if body:
            return canonical_json(body)
    elif body is not None:
        return canonical_json(body)
    text = env.body_bytes.decode("utf-8", "replace").strip() if env.body_bytes else ""
    return text or f"invokeAgent {target}"


def _classify_http(env: Envelope, cfg: Settings) -> Result:
    body = env.body
    target = _first_segment(env.path)
    request_key = env.request_id or "|".join(
        (env.http_method, env.path, sha256_hex(env.body_bytes)))

    kind_prompt: Optional[str] = None
    thread_hint = ""
    arguments: Dict[str, Any] = {}

    if isinstance(body, dict) and "jsonrpc" in body:
        method = body.get("method")
        if method not in A2A_METHODS:
            return Skip(f"a2a {method}")
        params = body.get("params")
        params = params if isinstance(params, dict) else {}
        kind_prompt = _a2a_text(params) or f"invokeAgent {target}"
        thread_hint = _a2a_thread_hint(params)
        arguments = _a2a_arguments(body, params)
    else:
        match = RUNTIME_PATH.match(env.path)
        if match and env.http_method == "POST":
            target = match.group(1)
            kind_prompt = _plain_prompt(env, target)
        elif env.path.startswith(INFERENCE_PREFIXES) or (
                isinstance(body, dict) and "model" in body
                and any(k in body for k in ("messages", "input", "prompt"))):
            return _unclassified(cfg, "inference-shaped request (not evaluated in v1)")
        else:
            return _unclassified(cfg, f"unclassified http {env.http_method} {env.path}")

    if not target:
        if cfg.unknown_resource == "unknown":
            target = "unknown-agent"
        else:
            return Reject("unresolvable_resource", "no target in the request path")

    override = _override(cfg, target)
    if override.get("kind") == "skip":
        return Skip(f"target {target} excluded by REVA_TARGETS")
    agent_id = str(override.get("id") or target)

    resource: Dict[str, Any] = {"type": "Agent", "id": agent_id, "name": agent_id}
    if override.get("endpoint"):
        resource["properties"] = {"endpoint": {"url": str(override["endpoint"]),
                                               "type": "Agent"}}
    return Call(
        kind="agent", action="invokeAgent", resource=resource,
        prompt=clip_utf8(kind_prompt, cfg.prompt_max_bytes), target=target,
        span_key=request_key, thread_hint=thread_hint, arguments=arguments,
    )
