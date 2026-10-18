# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The one place a repeated JSON member is refused.

Which occurrence of a repeated name a parser keeps is the library's choice,
not the contract's: Python's `json.loads` keeps the last, and a reader that
keeps the first sees another document under the same signature. Every reader
of signed, authenticated or operator-supplied JSON passes `unique_members` as
its `object_pairs_hook`, with the error its own contract names.

gateway-api/v2 payloads go further, through `ori.security.payload_members`,
which judges the bytes before any parse.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


def _not_json(name: str) -> Exception:
    # A JSONDecodeError is a ValueError: a caller's existing handler for
    # unparseable JSON catches the repeat as one.
    return json.JSONDecodeError(f"duplicate member {name!r}", "", 0)


def unique_members(
    error: Callable[[str], Exception] = _not_json,
) -> Callable[[list[tuple[str, Any]]], dict[str, Any]]:
    """An `object_pairs_hook` that raises ``error(name)`` for a repeated name.

    Applied by `json.loads` to every object at every depth, so a repeat inside
    a nested object or an array is refused too. Without *error*, the repeat is
    a `json.JSONDecodeError`.
    """

    def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        members: dict[str, Any] = {}
        for name, value in pairs:
            if name in members:
                raise error(name)
            members[name] = value
        return members

    return hook
