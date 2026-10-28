"""The RTG credential, read from AWS Secrets Manager.

The secret holds either the token itself (a plaintext secret) or a JSON object with the token under
`REVA_TOKEN_SECRET_KEY` (default `RTG_TOKEN`). It is read on the first call that needs it and again every
`CACHE_SECONDS`, so rotating the secret needs no redeploy. If a refresh fails the last value keeps
being used; if there is no value yet the call is denied. The secret's value is never logged and never
put in an error.
"""

from __future__ import annotations

import dataclasses
import json
import re
import time
from typing import Any, Dict, Tuple

from .config import Settings

CACHE_SECONDS = 300
ARN_REGION = re.compile(r"^arn:aws[a-z-]*:secretsmanager:([a-z0-9-]+):")
_CACHE: Dict[Tuple[str, str], Tuple[float, str]] = {}    # (secret, key) -> (read at, token)
_clock = time.monotonic                                  # a name of its own so tests can move time


class SecretError(Exception):
    pass


def _client(secret_id: str) -> Any:
    """boto3 is preinstalled in the Lambda runtime. A secret named by ARN is asked for in the
    ARN's region (a secret in another account is reached this way); a name uses the function's own."""
    import boto3
    from botocore.config import Config

    found = ARN_REGION.match(secret_id)
    options = {"region_name": found.group(1)} if found else {}
    return boto3.client("secretsmanager", config=Config(
        connect_timeout=2, read_timeout=3, retries={"max_attempts": 2}), **options)


def _extract(secret: str, key: str) -> str:
    text = secret.strip()
    if not text:
        raise SecretError("the secret is empty")
    try:
        data = json.loads(text)
    except ValueError:
        return text                                      # a bare token
    if isinstance(data, dict):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        raise SecretError(f"the secret is a JSON object with no text field {key!r} "
                          "(REVA_TOKEN_SECRET_KEY)")
    return text


def _read(cfg: Settings) -> str:
    try:
        response = _client(cfg.token_secret).get_secret_value(SecretId=cfg.token_secret)
    except Exception as exc:  # noqa: BLE001 - not found, denied, throttled, unreachable
        raise SecretError(f"cannot read secret {cfg.token_secret!r}: {str(exc)[:300]}") from exc
    value = response.get("SecretString")
    if not isinstance(value, str):
        raise SecretError(f"secret {cfg.token_secret!r} has no text value "
                          "(binary secrets are not supported)")
    return _extract(value, cfg.token_secret_key)


def get_token(cfg: Settings) -> str:
    key = (cfg.token_secret, cfg.token_secret_key)
    now = _clock()
    cached = _CACHE.get(key)
    if cached and now - cached[0] < CACHE_SECONDS:
        return cached[1]
    try:
        token = _read(cfg)
    except SecretError as exc:
        if not cached:
            raise
        # Keep working through a Secrets Manager hiccup; try again after CACHE_SECONDS.
        print(json.dumps({"event": "warn", "code": "token_refresh_failed", "reason": str(exc)},
                         separators=(",", ":")))
        _CACHE[key] = (now, cached[1])
        return cached[1]
    _CACHE[key] = (now, token)
    return token


def with_token(cfg: Settings) -> Settings:
    """`cfg` with the RTG token in place. A token already on the settings wins; the deployed
    function never has one, because `Settings.from_env` does not read it from the environment."""
    return cfg if cfg.token else dataclasses.replace(cfg, token=get_token(cfg))
