"""Small helpers shared by the modules. Stdlib only."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Optional, Union


def sha256_hex(value: Union[str, bytes]) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    """Stable text for hashing: same object, same string, whatever the key order."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def clip_utf8(text: str, max_bytes: int) -> str:
    """Cut to at most `max_bytes` UTF-8 bytes without splitting a character.

    Bytes, not characters: the RTG limits are in bytes, and a character count
    lets a multi-byte prompt through at several times the limit.
    """
    if max_bytes <= 0:
        return ""
    data = text.encode("utf-8")
    if len(data) <= max_bytes:
        return text
    return data[:max_bytes].decode("utf-8", "ignore")


def iso_now(epoch: Optional[float] = None) -> str:
    """RFC 3339 UTC with microseconds. The RTG orders history events by time."""
    moment = datetime.fromtimestamp(time.time() if epoch is None else epoch,
                                    tz=timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
