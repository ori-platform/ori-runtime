# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Canonical bytes and HMAC signing for ``runtime.telemetry.v1``."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from typing import Any

JSON_SAFE_INT_MAX = 9_007_199_254_740_991


class TelemetryCanonicalizationError(ValueError):
    """Raised when telemetry cannot be represented byte-identically."""


def _check_numbers(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        if abs(value) > JSON_SAFE_INT_MAX:
            raise TelemetryCanonicalizationError(
                f"integer outside JSON-safe range at {path}"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise TelemetryCanonicalizationError(f"non-finite number at {path}")
        magnitude = abs(value)
        if magnitude != 0.0 and not (1e-4 <= magnitude < 1e16):
            raise TelemetryCanonicalizationError(
                f"float outside cross-language canonical zone at {path}"
            )
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TelemetryCanonicalizationError(f"non-string object key at {path}")
            _check_numbers(item, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _check_numbers(item, f"{path}[{index}]")


def canonical_telemetry_bytes(payload: object) -> bytes:
    """Return the canonical UTF-8 bytes defined by runtime-telemetry/v1."""

    _check_numbers(payload)
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise TelemetryCanonicalizationError(str(exc)) from exc


def telemetry_hmac_sha256(
    api_key: str | bytes, timestamp_ms: int | str | bytes, body: bytes
) -> str:
    """Return the lowercase hex HMAC for an already-canonical body."""

    key = api_key.encode("utf-8") if isinstance(api_key, str) else api_key
    if isinstance(timestamp_ms, int):
        timestamp = str(timestamp_ms).encode("ascii")
    elif isinstance(timestamp_ms, str):
        timestamp = timestamp_ms.encode("ascii")
    else:
        timestamp = timestamp_ms
    return hmac.new(key, timestamp + b"." + body, hashlib.sha256).hexdigest()
