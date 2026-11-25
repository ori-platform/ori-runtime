# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Position tokens for the paged gateway exports (gateway-api/v2 Page Order).

A token names the position of the last row a page returned, bound to the
device, the export type, the window and the `params` it was issued under, and
carries a MAC under a key the issuing responder draws at start and never
stores. Only a token this responder issued verifies: one built by anyone else
from the public inputs, one altered, a count from a runtime that paged by
offset, one from before a restart, or one sent with other filters is refused,
always with the one error `page_token_invalid`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
from typing import Any

from ori.utils.strict_json import unique_members

PAGE_TOKEN_INVALID = "page_token_invalid"

_PREFIX = "p1."
_MAC_BYTES = 16
#: Far above any token this module issues; a longer one is refused unread.
_MAX_TOKEN_CHARS = 1024
_BODY = re.compile(r"[A-Za-z0-9_-]+")
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


def new_key() -> bytes:
    """A responder's token key: random, held in memory, never stored."""
    return os.urandom(32)


class PageTokenInvalidError(ValueError):
    """A token this runtime does not accept; answered `page_token_invalid`."""


def filter_digest(
    export_type: str,
    since_ms: int | None,
    until_ms: int | None,
    params: dict[str, Any],
) -> str:
    """The digest a token is bound to: the export type, window and `params`."""
    canonical = json.dumps(
        [export_type, since_ms, until_ms, params],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def issue(key: bytes, device_id: str, digest: str, position: tuple[int, ...]) -> str:
    """The token naming *position*, bound to *device_id* and *digest*, under *key*."""
    body = json.dumps(
        [device_id, digest, list(position)],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    mac = hmac.new(key, body, hashlib.sha256).digest()[:_MAC_BYTES]
    return _PREFIX + _b64(body) + "." + _b64(mac)


def _unb64(encoded: str) -> bytes:
    return base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))


def read(
    token: Any, *, key: bytes, device_id: str, digest: str, arity: int
) -> tuple[int, ...] | None:
    """The position *token* names, or None for an empty token (the start).

    Raises PageTokenInvalidError for anything this runtime would not have issued
    for this device and these filters, in exactly this form.
    """
    if token == "":
        return None
    if not isinstance(token, str) or len(token) > _MAX_TOKEN_CHARS:
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID)
    if not token.startswith(_PREFIX):
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID)
    parts = token[len(_PREFIX) :].split(".")
    if len(parts) != 2 or not all(_BODY.fullmatch(part) for part in parts):
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID)
    try:
        raw = _unb64(parts[0])
        _unb64(parts[1])
    except binascii.Error as exc:
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID) from exc
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_members())
    except (UnicodeDecodeError, ValueError) as exc:
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID) from exc
    if not (isinstance(value, list) and len(value) == 3):
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID)
    token_device, token_digest, position = value
    if token_device != device_id or token_digest != digest:
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID)
    if not (isinstance(position, list) and len(position) == arity):
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID)
    if not all(
        type(part) is int and _INT64_MIN <= part <= _INT64_MAX for part in position
    ):
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID)
    parsed = tuple(position)
    # Issuance is proved by issuing it again under the key: only the exact
    # token, MAC and spelling alike, verifies.
    if not hmac.compare_digest(issue(key, device_id, digest, parsed), token):
        raise PageTokenInvalidError(PAGE_TOKEN_INVALID)
    return parsed
