"""What is being called: action, resource and prompt, from the shape of the payload.

Entity TYPES come from the protocol, never from names:

    MCP tools/call                       Tool  `<server>/<tool>`           invokeTool
    HTTP, A2A JSON-RPC message/send      Agent `<first path segment>`      invokeAgent
    HTTP, AgentCore Runtime /invocations Agent `<first path segment>`      invokeAgent

Ids come from the payload too: the MCP tool name is `<target>___<tool>`, and an
HTTP target is the first segment of the path. The event carries no target ARN,
URL or type. `REVA_TARGETS` can rename a target's id or exclude it, and is the
only topology configuration.

LLM / inference traffic that crosses the gateway (OpenAI-compatible
`/inference…` or a body with `model` + `messages`) is evaluated as
`invokeModel` on a `Model` resource. Agents that call OpenAI/Bedrock directly
never hit the gateway, so those calls are still invisible here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from .config import Settings
from .event import Envelope
from .util import canonical_json, clip_utf8, sha256_hex

A2A_METHODS = ("message/send", "message/stream", "SendMessage", "SendStreamingMessage")
# The same two operations in the A2A HTTP+JSON (REST) binding. The operation ends the path, so
# any prefix (a version, a tenant, the agent) is ignored; the body is the request itself.
A2A_REST_SUFFIXES = ("/message:send", "/message:stream")
A2A_DATA_PART_MAX = 8192
RUNTIME_PATH = re.compile(r"^/([^/]+)/invocations/?$")
PROMPT_FIELDS = ("prompt", "input", "message", "query", "text")
INFERENCE_PREFIXES = ("/inference/", "/model/")
CHAT_COMPLETIONS_SUFFIX = "/chat/completions"
TOOL_SEPARATOR = "___"
LLM_NOT_CONTEXT = ("model", "messages", "tools", "functions", "metadata")


@dataclass
class Call:
    kind: str                       # "tool" | "agent" | "model"
    action: str                     # invokeTool | invokeAgent | invokeModel
    resource: Dict[str, Any]
    prompt: str
    target: str
    span_key: str
    thread_hint: str = ""
    arguments: Dict[str, Any] = field(default_factory=dict)
    role: str = ""                  # transmission role; empty → decide picks a default
    # Name/value pairs lifted from the request body, least specific first (see context.py).
    context_sources: List[Dict[str, Any]] = field(default_factory=list)


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

    # Context: everything in params but the tool name, `arguments` and `_meta` each under their
    # own names, the arguments winning a repeated name.
    context_sources = [
        {k: v for k, v in params.items() if k not in ("name", "arguments", "_meta")},
        params.get("_meta"), arguments]

    resource: Dict[str, Any] = {"type": "Tool", "id": f"{server}/{tool}", "name": tool}
    if cfg.tool_parents:
        resource["parents"] = [{"type": "MCPServer", "id": server}]
        resource["properties"] = {"name": tool, "connectionType": "mcp"}
    # resource.endpoint must match the MCPServer baseUrl in the entity store.
    # Only send it when REVA_TARGETS provides a real URL — a guessed gateway URL
    # causes endpoint_resolution_failed.
    if override.get("endpoint"):
        endpoint = str(override["endpoint"])
        resource["endpoint"] = endpoint
        resource.setdefault("properties", {})["endpoint"] = {
            "url": endpoint, "type": "MCP"}

    prompt = canonical_json(arguments) if arguments else tool
    return Call(
        kind="tool", action="invokeTool", resource=resource,
        prompt=clip_utf8(prompt, cfg.prompt_max_bytes), target=target,
        span_key="|".join(("tools/call", name, canonical_json(arguments),
                           _jsonrpc_id(body))),
        arguments=arguments, context_sources=_dicts(context_sources),
    )


# ── HTTP (AgentCore Runtime agents, A2A, passthrough) ────────────────────────

def _dicts(items: List[Any]) -> List[Dict[str, Any]]:
    return [item for item in items if isinstance(item, dict) and item]


def _first_segment(path: str) -> str:
    parts = [p for p in (path or "").split("/") if p]
    return parts[0] if parts else ""


def _a2a_rest_operation(path: str) -> bool:
    return (path or "").endswith(A2A_REST_SUFFIXES)


def _a2a_rest_target(path: str) -> str:
    """The first path segment ahead of the operation (`/<agent>/message:send`), else ''."""
    parts = [p for p in (path or "").split("/") if p]
    return parts[0] if len(parts) > 1 else ""


def _a2a_text(params: Dict[str, Any]) -> str:
    """The message's text parts, and its data parts as JSON, in order."""
    message = params.get("message")
    parts = message.get("parts") if isinstance(message, dict) else None
    texts = []
    for part in parts if isinstance(parts, list) else []:
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if isinstance(text, str):
            if text.strip():
                texts.append(text.strip())
        elif part.get("data") not in (None, {}, [], ""):
            texts.append(clip_utf8(canonical_json(part["data"]), A2A_DATA_PART_MAX))
    return "\n".join(texts)


def _a2a_context_sources(request: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every `metadata` object of an A2A send-message request: the request's, the message's
    and each message part's, the most specific last."""
    message = request.get("message")
    message = message if isinstance(message, dict) else {}
    sources: List[Any] = [request.get("metadata"), message.get("metadata")]
    parts = message.get("parts")
    for part in parts if isinstance(parts, list) else []:
        if isinstance(part, dict):
            sources.append(part.get("metadata"))
    return _dicts(sources)


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
    """Business text for RTG. AgentCore Runtime sends `{"input":{"prompt":"…"}}`;
    prefer the nested string over serialising the whole envelope.
    """
    body = env.body
    if isinstance(body, dict):
        for name in PROMPT_FIELDS:
            value = body.get(name)
            if isinstance(value, str) and value.strip():
                return value.strip()
        # AgentCore /invocations: input is an object, not the prompt string.
        nested = body.get("input")
        if isinstance(nested, dict):
            for name in ("prompt", "message", "query", "text"):
                value = nested.get(name)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        if body:
            return canonical_json(body)
    elif body is not None:
        return canonical_json(body)
    text = env.body_bytes.decode("utf-8", "replace").strip() if env.body_bytes else ""
    return text or f"invokeAgent {target}"


def _message_text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, str) and item.strip():
                parts.append(item.strip())
            elif isinstance(item, dict):
                text = item.get("text")
                if isinstance(text, str) and text.strip():
                    parts.append(text.strip())
        return "\n".join(parts)
    return ""


def _llm_prompt(body: Dict[str, Any]) -> str:
    """Last user message from an OpenAI-compatible chat.completions body."""
    messages = body.get("messages")
    if isinstance(messages, list):
        for message in reversed(messages):
            if not isinstance(message, dict):
                continue
            if str(message.get("role") or "").lower() != "user":
                continue
            text = _message_text(message.get("content"))
            if text:
                return text
    for name in ("prompt", "input", "query", "text"):
        value = body.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _is_openai_chat(env: Envelope) -> bool:
    body = env.body
    if not isinstance(body, dict):
        return False
    if "model" not in body:
        return False
    if isinstance(body.get("messages"), list):
        return True
    path = (env.path or "").lower()
    return path.endswith(CHAT_COMPLETIONS_SUFFIX) or "/completions" in path


def _classify_llm(env: Envelope, cfg: Settings) -> Result:
    body = env.body if isinstance(env.body, dict) else {}
    model = body.get("model")
    if not isinstance(model, str) or not model.strip():
        model = "unknown-model"
    else:
        model = model.strip()
    override = _override(cfg, model)
    if override.get("kind") == "skip":
        return Skip(f"model {model} excluded by REVA_TARGETS")
    model_id = str(override.get("id") or model)
    prompt = _llm_prompt(body) or f"invokeModel {model_id}"
    resource: Dict[str, Any] = {"type": "Model", "id": model_id, "name": model_id}
    if override.get("endpoint"):
        resource["properties"] = {"endpoint": {"url": str(override["endpoint"]),
                                               "type": "Model"}}
    request_key = env.request_id or "|".join(
        (env.http_method, env.path, sha256_hex(env.body_bytes)))
    # Context: `metadata`, then the call settings at the top of the body (max_tokens, stream,
    # user, ...). The model and messages are the resource and the prompt, not context.
    settings = {k: v for k, v in body.items() if k not in LLM_NOT_CONTEXT}
    return Call(
        kind="model", action="invokeModel", resource=resource,
        prompt=clip_utf8(prompt, cfg.prompt_max_bytes), target=model_id,
        span_key=request_key, role="agent",
        context_sources=_dicts([body.get("metadata"), settings]),
    )


def _classify_http(env: Envelope, cfg: Settings) -> Result:
    body = env.body
    target = _first_segment(env.path)
    request_key = env.request_id or "|".join(
        (env.http_method, env.path, sha256_hex(env.body_bytes)))

    kind_prompt: Optional[str] = None
    thread_hint = ""
    arguments: Dict[str, Any] = {}
    context_sources: List[Dict[str, Any]] = []

    if isinstance(body, dict) and "jsonrpc" in body:
        method = body.get("method")
        if method not in A2A_METHODS:
            return Skip(f"a2a {method}")
        params = body.get("params")
        params = params if isinstance(params, dict) else {}
        kind_prompt = _a2a_text(params) or f"invokeAgent {target}"
        thread_hint = _a2a_thread_hint(params)
        arguments = _a2a_arguments(body, params)
        context_sources = _a2a_context_sources(params)
    elif (env.http_method == "POST" and isinstance(body, dict)
          and _a2a_rest_operation(env.path)):
        # A2A HTTP+JSON binding: the body is the request, with no JSON-RPC envelope.
        target = _a2a_rest_target(env.path)
        kind_prompt = _a2a_text(body) or f"invokeAgent {target}"
        thread_hint = _a2a_thread_hint(body)
        arguments = _a2a_arguments(body, body)
        context_sources = _a2a_context_sources(body)
    else:
        match = RUNTIME_PATH.match(env.path)
        if match and env.http_method == "POST":
            target = match.group(1)
            kind_prompt = _plain_prompt(env, target)
        elif env.path.startswith(INFERENCE_PREFIXES) or _is_openai_chat(env):
            return _classify_llm(env, cfg)
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
    # Only when REVA_TARGETS.endpoint matches the Agent pathUrl in the entity store.
    if override.get("endpoint"):
        endpoint = str(override["endpoint"])
        resource["endpoint"] = endpoint
        resource["properties"] = {"endpoint": {"url": endpoint, "type": "Agent"}}
    return Call(
        kind="agent", action="invokeAgent", resource=resource,
        prompt=clip_utf8(kind_prompt, cfg.prompt_max_bytes), target=target,
        span_key=request_key, thread_hint=thread_hint, arguments=arguments,
        context_sources=context_sources,
    )
