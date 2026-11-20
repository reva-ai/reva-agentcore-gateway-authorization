"""Name/value pairs from a request body, sent to the RTG as `context` so a policy can match on them.

The same rules as the Kong plugin (2.1.0), which learned them from the RTG: the RTG refuses
the WHOLE evaluation with HTTP 400 when one pair falls outside what it reads, so anything
outside the rules is left out here instead of sent.

    * a value is a string, true/false, a whole number, or a non-empty list of one of those:
      no null, decimals, objects, mixed lists, and no text that looks like a credential
    * a name is not one the RTG keeps for itself and does not name a credential
    * a nested object becomes dotted names (`customer.tier`)
    * at most 64 pairs and 512 bytes of JSON in all; the pairs that fit are kept, in name order

`build_context` takes the sources least specific first (a repeated name takes the later
value) and returns the context plus a list of what was left out. The list holds names and
reasons only, never values.
"""

from __future__ import annotations

import math
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

MAX_BYTES = 512
MAX_PAIRS = 64
MAX_NAME_CHARS = 128
MAX_DEPTH = 8
# A number of 15 or more digits is written in exponent form by some JSON writers, which the
# RTG does not read, so a larger whole number is left out.
MAX_INT = 99999999999999
MAX_NOTES = 20

# Compared with the name lower-cased and reduced to its letters and digits, so "Api-Key",
# "api_key" and "apiKey" are the same name.
RESERVED = frozenset((
    "action", "authkey", "endpointtype", "endpointurl", "history", "issuer", "onbehalfof",
    "originurl", "origintype", "principal", "prompt", "promptintent", "promptkey", "resource",
    "rtga2a", "subject", "threadid",
))
CREDENTIAL = frozenset((
    "accesstoken", "apikey", "authorization", "auth", "bearertoken", "clientsecret", "cookie",
    "credential", "idtoken", "oauthtoken", "password", "passwd", "privatekey",
    "proxyauthorization", "refreshtoken", "secret", "secretkey", "sessiontoken", "setcookie",
    "transactiontoken", "xapikey", "xapitoken", "xtransactiontoken",
))

_NOT_ALNUM = re.compile(r"[^0-9A-Za-z\u0080-\U0010ffff]")
_BASE64URL = re.compile(r"^([0-9A-Za-z_\-]*)(=*)$")
_ASCII_LOWER = {c: c + 32 for c in range(ord("A"), ord("Z") + 1)}


def _fingerprint(name: str) -> str:
    return _NOT_ALNUM.sub("", name).translate(_ASCII_LOWER)


def _note(dropped: List[str], text: str, extra: List[int]) -> None:
    if len(dropped) < MAX_NOTES:
        dropped.append(text)
    else:
        extra[0] += 1


def _base64url_ok(part: str, allow_padding: bool) -> bool:
    match = _BASE64URL.match(part)
    if not match:
        return False
    body, padding = match.groups()
    if not padding:
        return len(body) % 4 != 1
    if not allow_padding:
        return False
    rest = len(body) % 4
    return (rest == 2 and len(padding) == 2) or (rest == 3 and len(padding) == 1)


def looks_like_credential(text: str) -> bool:
    """Text the RTG would take for a credential: a bearer value, or a signed (three parts)
    or encrypted (five parts) token."""
    raw = text.strip()
    if raw[:7].lower() == "bearer ":
        return True
    parts = raw.split(".")
    if len(parts) == 3 and parts[0] and parts[1]:
        if all(not part or _base64url_ok(part, True) for part in parts):
            return True
    if len(parts) == 5:
        if all((i == 1 and not part) or (part and _base64url_ok(part, False))
               for i, part in enumerate(parts)):
            return True
    return False


def _scalar(value: Any) -> Tuple[Optional[str], Any]:
    """(kind, value) for a scalar the RTG accepts, or (None, why not)."""
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_BYTES - 2:
            return None, "too long"
        if looks_like_credential(value):
            return None, "looks like a credential"
        return "string", value
    if isinstance(value, bool):
        return "boolean", value
    if isinstance(value, (int, float)):
        if isinstance(value, float):
            if not math.isfinite(value) or value != math.floor(value):
                return None, "not a whole number"
        if abs(value) > MAX_INT:
            return None, "number too large"
        return "integer", int(value)
    if value is None:
        return None, "null"
    return None, "unsupported value"


def _value(value: Any) -> Tuple[Any, str]:
    """(value to send, "") or (None, why not). `value` is a scalar or a non-empty list."""
    if not isinstance(value, list):
        kind, result = _scalar(value)
        return (result, "") if kind else (None, result)
    if len(value) > MAX_BYTES:
        return None, "list too long"
    out: List[Any] = []
    list_kind: Optional[str] = None
    for item in value:
        if isinstance(item, (dict, list)):
            return None, "list of objects or lists"
        kind, result = _scalar(item)
        if not kind:
            return None, result
        if list_kind and list_kind != kind:
            return None, "mixed list"
        list_kind = kind
        out.append(result)
    return out, ""


def _name_problem(name: str) -> str:
    """"" when the name can be sent, otherwise why not."""
    if len(name) > MAX_NAME_CHARS:
        return "name too long"
    if not name or name[0].isspace() or name[-1].isspace():
        return "blank name"
    if _fingerprint(name) in RESERVED:
        return "name reserved"
    if _fingerprint(name) in CREDENTIAL:
        return "name looks like a credential"
    for segment in name.split("."):
        if segment and _fingerprint(segment) in CREDENTIAL:
            return "name looks like a credential"
    return ""


def _flatten(source: Mapping[str, Any], prefix: str, out: Dict[str, Any], dropped: List[str],
             extra: List[int], depth: int) -> None:
    for key, value in source.items():
        if not isinstance(key, str):
            continue
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            if not value:
                continue
            if depth >= MAX_DEPTH:
                _note(dropped, f"{name} (nested too deep)", extra)
            else:
                _flatten(value, name, out, dropped, extra, depth + 1)
            continue
        if isinstance(value, list) and not value:
            continue                                    # an empty list is no value at all
        sendable, why = _value(value)
        if why:
            _note(dropped, f"{name} ({why})", extra)
            continue
        problem = _name_problem(name)
        if problem:
            _note(dropped, f"{name} ({problem})", extra)
        else:
            out[name] = sendable


def _json_string_len(text: str) -> int:
    """Bytes of a JSON string, counting the escapes the RTG counts."""
    data = text.encode("utf-8")
    size = len(data) + 2
    for byte in data:
        if byte in (34, 92, 8, 9, 10, 12, 13):
            size += 1
        elif byte < 32:
            size += 5
    return size


def _json_value_len(value: Any) -> int:
    if isinstance(value, str):
        return _json_string_len(value)
    if isinstance(value, bool):
        return 4 if value else 5
    if isinstance(value, int):
        return len(str(value))
    size = 2 + (len(value) - 1 if len(value) > 1 else 0)
    return size + sum(_json_value_len(item) for item in value)


def build_context(sources: Sequence[Mapping[str, Any]],
                  pinned: Optional[Mapping[str, Any]] = None
                  ) -> Tuple[Dict[str, Any], List[str]]:
    """(context, left out). `pinned` pairs are the operator's own (REVA_CONTEXT_MAP): they
    replace a body pair of the same name and are first in line for the 64 pairs / 512 bytes."""
    merged: Dict[str, Any] = {}
    chosen: Dict[str, Any] = {}
    dropped: List[str] = []
    extra = [0]
    for source in sources:
        if isinstance(source, dict) and source:
            _flatten(source, "", merged, dropped, extra, 1)
    if pinned:
        _flatten(dict(pinned), "", chosen, dropped, extra, 1)
        for name in chosen:
            merged.pop(name, None)

    context: Dict[str, Any] = {}
    size = 2
    for group in (chosen, merged):
        for name in sorted(group):
            value = group[name]
            added = (_json_string_len(name) + 1 + _json_value_len(value)
                     + (1 if context else 0))
            if len(context) < MAX_PAIRS and size + added <= MAX_BYTES:
                context[name] = value
                size += added
            else:
                _note(dropped, f"{name} (does not fit)", extra)
    if extra[0]:
        dropped.append(f"and {extra[0]} more")
    return context, dropped
