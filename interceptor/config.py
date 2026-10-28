"""Settings, read once per container from the environment (every variable is REVA_*).

Parsing is tolerant on purpose: a bad value never raises. It is recorded in
`Settings.errors`, and `decide` then denies every call with `config_error`. An
interceptor that crashes on a typo is an interceptor whose failure mode the
gateway decides, and the gateway does not document what it does.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

DEFAULT_BASE_URL = "https://api.reva.ai"
DEFAULT_HISTORY_TABLE = "reva_trace_hop"
DEFAULT_TOKEN_SECRET = "reva/secrets"
DEFAULT_TOKEN_SECRET_KEY = "RTG_TOKEN"
EVALUATE_PATH = "/pdp/v2/ai/evaluation"

AUTH_MODES = ("api-token", "bearer")
HISTORY_MODES = ("interceptor", "rtg")


def _text(env: Mapping[str, str], name: str, default: str = "") -> str:
    value = env.get(name)
    return default if value is None else value.strip()


def _bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _number(env: Mapping[str, str], name: str, default: float, errors: List[str],
            cast=float, minimum: float = 0) -> Any:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = cast(raw.strip())
    except ValueError:
        errors.append(f"{name}={raw!r} is not a number")
        return default
    if value < minimum:
        errors.append(f"{name}={raw!r} must be at least {minimum}")
        return default
    return value


def _json_object(env: Mapping[str, str], name: str, errors: List[str]) -> Dict[str, Any]:
    raw = env.get(name)
    if raw is None or not raw.strip():
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        errors.append(f"{name} is not valid JSON")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{name} must be a JSON object")
        return {}
    return value


def _csv(env: Mapping[str, str], name: str, default: Tuple[str, ...]) -> Tuple[str, ...]:
    raw = env.get(name)
    if raw is None:
        return default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def _choice(env: Mapping[str, str], name: str, default: str, allowed: Tuple[str, ...],
            errors: List[str]) -> str:
    value = _text(env, name, default).lower().replace("_", "-")
    if value not in allowed:
        errors.append(f"{name}={value!r} must be one of {', '.join(allowed)}")
        return default
    return value


def normalize_base_url(raw: str) -> str:
    """`api.reva.ai`, `https://api.reva.ai/` and `http://localhost:8080` all work."""
    raw = raw.strip().rstrip("/")
    if "://" not in raw:
        local = raw.lower().startswith(("localhost", "127.0.0.1", "[::1]"))
        raw = ("http://" if local else "https://") + raw
    return raw


@dataclass(frozen=True)
class Settings:
    # RTG connection
    base_url: str = DEFAULT_BASE_URL
    token: str = ""                 # never read from the environment: see `secret.with_token`
    token_secret: str = DEFAULT_TOKEN_SECRET
    token_secret_key: str = DEFAULT_TOKEN_SECRET_KEY
    auth_mode: str = "api-token"
    policy_store_id: str = ""
    verify_user_scope: bool = False
    origin_app: str = ""
    timeout_seconds: float = 15.0
    retries: int = 1
    safety_margin_ms: int = 2000
    prompt_key: str = "userQuery"
    # identity
    user_claim: str = "sub"
    groups_claim: str = ""
    authorize_agent: bool = True
    agent_claims: Tuple[str, ...] = ("act.sub",)
    agent_header: str = "x-reva-agent-id"
    agent_id_map: Dict[str, str] = field(default_factory=dict)
    # classification
    targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    context_map: Dict[str, str] = field(default_factory=dict)
    unclassified: str = "skip"
    unknown_resource: str = "deny"
    eval_builtin_tools: bool = False
    tool_parents: bool = False
    prompt_max_bytes: int = 12000
    # trace and history
    trace_header: str = ""
    on_missing_traceparent: str = "mint"
    history: str = "interceptor"
    history_table: str = DEFAULT_HISTORY_TABLE
    history_pk_attr: str = "pk"
    history_sk_attr: str = "sk"
    trace_ttl_seconds: int = 3600
    thread_ttl_seconds: int = 86400
    max_hops_sent: int = 30
    max_threads_traces: int = 200
    content_max_bytes: int = 1500
    # enforcement
    fail_open: bool = False
    monitor_mode: bool = False
    conditional_allow: str = "deny"
    deny_message: str = "Blocked by your organization's security policy."
    deny_status: int = 403
    debug: bool = False
    errors: Tuple[str, ...] = ()

    @property
    def evaluate_url(self) -> str:
        return self.base_url + EVALUATE_PATH

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if env is None else env
        errors: List[str] = []

        auth_mode = _choice(env, "REVA_AUTH_MODE", "api-token", AUTH_MODES, errors)
        history = _choice(env, "REVA_HISTORY", "interceptor", HISTORY_MODES, errors)
        unclassified = _choice(env, "REVA_UNCLASSIFIED", "skip", ("skip", "deny"), errors)
        unknown_resource = _choice(env, "REVA_UNKNOWN_RESOURCE", "deny",
                                   ("deny", "unknown"), errors)
        on_missing = _choice(env, "REVA_ON_MISSING_TRACEPARENT", "mint",
                             ("mint", "deny"), errors)
        conditional = _choice(env, "REVA_CONDITIONAL_ALLOW", "deny",
                              ("deny", "allow"), errors)

        if env.get("REVA_TOKEN") is not None:
            # A token left in the function's configuration is exactly what Secrets Manager is
            # here to avoid, so it is reported rather than quietly ignored.
            errors.append("REVA_TOKEN is no longer read: the RTG token comes from AWS Secrets "
                          "Manager (REVA_TOKEN_SECRET, default reva/secrets); remove the variable")

        history_table = _text(env, "REVA_HISTORY_TABLE") or DEFAULT_HISTORY_TABLE
        if env.get("REVA_HISTORY_KEY_ATTR") is not None:
            # The first version used a table with one key. Say so rather than let every
            # call fail with a DynamoDB validation error about the key schema.
            errors.append("REVA_HISTORY_KEY_ATTR is no longer used: the history table now needs "
                          "a string partition key and a string sort key "
                          "(REVA_HISTORY_PK_ATTR, REVA_HISTORY_SK_ATTR); remove the setting")

        verify = _bool(env, "REVA_VERIFY_USER_SCOPE", False)
        origin_app = _text(env, "REVA_ORIGIN_APP")
        if verify and not origin_app:
            errors.append("REVA_VERIFY_USER_SCOPE needs REVA_ORIGIN_APP")

        targets = _json_object(env, "REVA_TARGETS", errors)
        for name, entry in list(targets.items()):
            if not isinstance(entry, dict):
                errors.append(f"REVA_TARGETS[{name!r}] must be an object")
                continue
            unknown = set(entry) - {"id", "kind", "endpoint"}
            if unknown:
                errors.append(f"REVA_TARGETS[{name!r}] has unknown keys {sorted(unknown)}")
            if entry.get("kind", "") not in ("", "skip"):
                errors.append(f"REVA_TARGETS[{name!r}].kind must be 'skip' or absent")

        agent_id_map = _json_object(env, "REVA_AGENT_ID_MAP", errors)
        context_map = _json_object(env, "REVA_CONTEXT_MAP", errors)
        for label, mapping in (("REVA_AGENT_ID_MAP", agent_id_map),
                               ("REVA_CONTEXT_MAP", context_map)):
            if any(not isinstance(v, str) for v in mapping.values()):
                errors.append(f"{label} values must be strings")

        return cls(
            base_url=normalize_base_url(_text(env, "REVA_BASE_URL") or DEFAULT_BASE_URL),
            token_secret=_text(env, "REVA_TOKEN_SECRET") or DEFAULT_TOKEN_SECRET,
            token_secret_key=_text(env, "REVA_TOKEN_SECRET_KEY") or DEFAULT_TOKEN_SECRET_KEY,
            auth_mode=auth_mode,
            policy_store_id=_text(env, "REVA_POLICY_STORE_ID"),
            verify_user_scope=verify,
            origin_app=origin_app,
            timeout_seconds=_number(env, "REVA_TIMEOUT_SECONDS", 15.0, errors, float, 1),
            retries=_number(env, "REVA_RETRIES", 1, errors, int, 0),
            safety_margin_ms=_number(env, "REVA_SAFETY_MARGIN_MS", 2000, errors, int, 0),
            prompt_key=_text(env, "REVA_PROMPT_KEY", "userQuery") or "userQuery",
            user_claim=_text(env, "REVA_USER_CLAIM", "sub") or "sub",
            groups_claim=_text(env, "REVA_GROUPS_CLAIM"),
            authorize_agent=_bool(env, "REVA_AUTHORIZE_AGENT", True),
            agent_claims=_csv(env, "REVA_AGENT_CLAIMS", ("act.sub",)),
            agent_header=(_text(env, "REVA_AGENT_HEADER", "x-reva-agent-id")
                          or "x-reva-agent-id").lower(),
            agent_id_map={str(k): v for k, v in agent_id_map.items() if isinstance(v, str)},
            targets={str(k): v for k, v in targets.items() if isinstance(v, dict)},
            context_map={str(k): v for k, v in context_map.items() if isinstance(v, str)},
            unclassified=unclassified,
            unknown_resource=unknown_resource,
            eval_builtin_tools=_bool(env, "REVA_EVAL_BUILTIN_TOOLS", False),
            tool_parents=_bool(env, "REVA_TOOL_PARENTS", False),
            prompt_max_bytes=_number(env, "REVA_PROMPT_MAX_BYTES", 12000, errors, int, 1),
            trace_header=_text(env, "REVA_TRACE_HEADER").lower(),
            on_missing_traceparent=on_missing,
            history=history,
            history_table=history_table,
            history_pk_attr=_text(env, "REVA_HISTORY_PK_ATTR", "pk") or "pk",
            history_sk_attr=_text(env, "REVA_HISTORY_SK_ATTR", "sk") or "sk",
            trace_ttl_seconds=_number(env, "REVA_TRACE_TTL_SECONDS", 3600, errors, int, 1),
            thread_ttl_seconds=_number(env, "REVA_THREAD_TTL_SECONDS", 86400, errors, int, 1),
            max_hops_sent=min(_number(env, "REVA_MAX_HOPS_SENT", 30, errors, int, 1), 30),
            content_max_bytes=_number(env, "REVA_CONTENT_MAX_BYTES", 1500, errors, int, 1),
            fail_open=_bool(env, "REVA_FAIL_OPEN", False),
            monitor_mode=_bool(env, "REVA_MONITOR_MODE", False),
            conditional_allow=conditional,
            deny_message=_text(env, "REVA_DENY_MESSAGE",
                               "Blocked by your organization's security policy.")
            or "Blocked by your organization's security policy.",
            deny_status=_number(env, "REVA_DENY_STATUS", 403, errors, int, 100),
            debug=_bool(env, "REVA_DEBUG", False),
            errors=tuple(errors),
        )
