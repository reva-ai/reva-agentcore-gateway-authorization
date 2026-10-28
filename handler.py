"""AWS Lambda entry point for the AgentCore Gateway interceptor.

Handler string: `handler.lambda_handler`. Nothing is raised past this function:
the gateway does not document what it does when an interceptor Lambda errors, so
an unexpected exception is turned into a deny here rather than left to chance.
"""

from __future__ import annotations

import json
import traceback
from typing import Any, Dict, Optional

from interceptor import decide, respond
from interceptor.config import Settings

_SETTINGS: Optional[Settings] = None
DEFAULT_MESSAGE = "Blocked by your organization's security policy."


def _settings() -> Settings:
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = Settings.from_env()
    return _SETTINGS


def lambda_handler(event: Any, context: Any) -> Dict[str, Any]:
    message, status = DEFAULT_MESSAGE, 403
    try:
        cfg = _settings()
        message, status = cfg.deny_message, cfg.deny_status
        return decide.handle(event, context, cfg)
    except Exception as exc:  # noqa: BLE001 - the one place that must catch everything
        # The type and the frames, never the event: it carries the caller's token.
        print(json.dumps({"event": "error", "code": "internal_error",
                          "type": type(exc).__name__,
                          "trace": traceback.format_exc(limit=6)[-1500:]}))
        return respond.emergency_deny(event, message, "internal_error", status)
