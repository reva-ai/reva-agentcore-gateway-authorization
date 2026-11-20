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
DEFAULT_TOKEN_SECRET = "reva/secrets"
DEFAULT_TOKEN_SECRET_KEY = "RTG_TOKEN"
# Unified AI evaluation path (token-evaluation body under rtg/a2a).
EVALUATE_PATH = "/pdp/ai/access/ai/evaluation"
# Finalize a finished prompt so later turns get session.messages.
SUMMARIZE_PATH = "/pdp/ai/access/ai/trace/summarize"
SUMMARIZE_OUTPUT_MAX = 16 * 1024

AUTH_MODES = ("api-token", "bearer")


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
    prompt_key: str = "content"
    # identity
    user_claim: str = "sub"
    groups_claim: str = ""
    # classification
    targets: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    context_map: Dict[str, str] = field(default_factory=dict)
    context_from_body: bool = True
    unclassified: str = "skip"
    unknown_resource: str = "deny"
    eval_builtin_tools: bool = False
    tool_parents: bool = False
    prompt_max_bytes: int = 12000
    # trace
    trace_header: str = ""
    on_missing_traceparent: str = "mint"
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

    @property
    def summarize_url(self) -> str:
        return self.base_url + SUMMARIZE_PATH

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "Settings":
        env = os.environ if env is None else env
        errors: List[str] = []

        auth_mode = _choice(env, "REVA_AUTH_MODE", "api-token", AUTH_MODES, errors)
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

        context_map = _json_object(env, "REVA_CONTEXT_MAP", errors)
        if any(not isinstance(v, str) for v in context_map.values()):
            errors.append("REVA_CONTEXT_MAP values must be strings")

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
            prompt_key=_text(env, "REVA_PROMPT_KEY", "content") or "content",
            user_claim=_text(env, "REVA_USER_CLAIM", "sub") or "sub",
            groups_claim=_text(env, "REVA_GROUPS_CLAIM"),
            targets={str(k): v for k, v in targets.items() if isinstance(v, dict)},
            context_map={str(k): v for k, v in context_map.items() if isinstance(v, str)},
            context_from_body=_bool(env, "REVA_CONTEXT_FROM_BODY", True),
            unclassified=unclassified,
            unknown_resource=unknown_resource,
            eval_builtin_tools=_bool(env, "REVA_EVAL_BUILTIN_TOOLS", False),
            tool_parents=_bool(env, "REVA_TOOL_PARENTS", False),
            prompt_max_bytes=_number(env, "REVA_PROMPT_MAX_BYTES", 12000, errors, int, 1),
            trace_header=_text(env, "REVA_TRACE_HEADER").lower(),
            on_missing_traceparent=on_missing,
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
