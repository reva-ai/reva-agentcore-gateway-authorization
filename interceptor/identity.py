"""Who is calling: the principal, the groups, and the agent (if any).

The gateway has already validated the bearer JWT, so its payload is decoded
without re-verifying the signature. Nothing here ever logs a token.

principal  the human (or the client, for a machine token): one claim, default `sub`.
           Resolved once per trace, on the trace's first call, then read from the
           trace record by every later hop.
agent      only when REVA_AUTHORIZE_AGENT is on. The gateway event carries no
           caller identity, so it comes from a token claim (RFC 8693 `act.sub`)
           or, failing that, a header the agent sets. Unresolved means "the
           user is acting", never a guess.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .config import Settings

MAX_TOKEN_CHARS = 16 * 1024
MAX_ID_CHARS = 256


def bearer_token(headers: Mapping[str, str]) -> str:
    value = headers.get("authorization", "")
    if value[:7].lower() != "bearer ":
        return ""
    return value[7:].strip()


def jwt_claims(token: str) -> Dict[str, Any]:
    """The payload of a JWT, unverified. {} for anything that is not one."""
    if not token or len(token) > MAX_TOKEN_CHARS:
        return {}
    parts = token.split(".")
    if len(parts) != 3:
        return {}
    segment = parts[1]
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
        claims = json.loads(raw)
    except (ValueError, TypeError):
        return {}
    return claims if isinstance(claims, dict) else {}


def _lookup(claims: Mapping[str, Any], path: str) -> Any:
    """The literal key first (`cognito:username`, URL-shaped claims), then a dotted path."""
    if path in claims:
        return claims[path]
    node: Any = claims
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def claim_value(claims: Mapping[str, Any], path: str) -> Optional[str]:
    value = _lookup(claims, path) if path else None
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return None
    text = str(value).strip()
    return text[:MAX_ID_CHARS] if text else None


def claim_list(claims: Mapping[str, Any], path: str) -> List[str]:
    value = _lookup(claims, path) if path else None
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return [str(v).strip() for v in value
            if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip()]


def resolve_principal(headers: Mapping[str, str], cfg: Settings
                      ) -> Tuple[Optional[str], List[str], str]:
    """(principal id, groups, error code). The code is "" on success."""
    token = bearer_token(headers)
    if not token:
        return None, [], "missing_authorization"
    claims = jwt_claims(token)
    if not claims:
        return None, [], "invalid_authorization"
    principal = claim_value(claims, cfg.user_claim)
    if not principal:
        return None, [], "principal_unresolved"
    return principal, claim_list(claims, cfg.groups_claim), ""


def resolve_agent(headers: Mapping[str, str], cfg: Settings) -> Tuple[Optional[str], str]:
    """(agent id or None, source). The source is for the log, never for a decision."""
    if not cfg.authorize_agent:
        return None, "authorize_agent_off"

    value, source = None, ""
    if cfg.agent_claims:
        claims = jwt_claims(bearer_token(headers))
        for claim in cfg.agent_claims:
            found = claim_value(claims, claim)
            if found:
                value, source = found, f"claim:{claim}"
                break
    if not value:
        header = headers.get(cfg.agent_header, "").strip()
        if header:
            value, source = header[:MAX_ID_CHARS], f"header:{cfg.agent_header}"
    if not value:
        return None, "user_fallback"
    return cfg.agent_id_map.get(value, value), source


def subject_for(principal: str, agent_id: Optional[str]) -> Dict[str, str]:
    if agent_id:
        return {"type": "Agent", "id": agent_id}
    return {"type": "User", "id": principal}
