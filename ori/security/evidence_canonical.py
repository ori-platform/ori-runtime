# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Canonical JSON for the evidence chain, per `ori-specs/evidence/v2`.

Bytes are the signing contract. Two implementations that disagree on how a
value serialises produce signatures that verify on one side and not the other,
so this module refuses anything outside the range where the platform's
serialisers provably agree rather than emitting bytes a verifier cannot
reproduce.

That range is the D-011 agreement zone, already normative for Layer 1 in
`ori-specs/firmware-telemetry/v1.md` and implemented in C, Rust and Python.
Layer 1 and Layer 2 canonicalise identically, which is what lets a firmware
signer be cross-checked against a Layer 2 vector at all.
"""

from __future__ import annotations

import json
import math
from typing import Any

# 2^53 - 1. Above this an integer is not exactly representable as a double,
# and a consumer that parses JSON numbers as doubles would read a different
# value than the one signed.
INTEGER_MAX = 9007199254740991

# Where CPython and serde_json provably emit identical fixed-notation bytes.
# Outside it they diverge on exponent form: 0.00001 against 1e-05.
FLOAT_MIN_MAGNITUDE = 1e-4
FLOAT_MAX_MAGNITUDE = 1e16


class CanonicalisationError(ValueError):
    """A value cannot be canonicalised into bytes every verifier reproduces."""


def _reject(value: Any, path: str) -> None:
    """Walk the whole value. Canonicalisation is recursive, so this must be.

    A top-level-only check accepts ``{"a": [1e-5]}`` and then emits bytes no
    other implementation reproduces, which is the failure the zone prevents.
    """
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, int):
        if abs(value) > INTEGER_MAX:
            raise CanonicalisationError(
                f"{path}: integer magnitude exceeds 2^53-1 and is not exactly "
                "representable by a double-precision consumer"
            )
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalisationError(f"{path}: NaN and infinities have no JSON form")
        magnitude = abs(value)
        if magnitude != 0.0 and not (
            FLOAT_MIN_MAGNITUDE <= magnitude < FLOAT_MAX_MAGNITUDE
        ):
            raise CanonicalisationError(
                f"{path}: float outside the cross-language agreement zone; "
                "serialisers disagree on exponent notation here"
            )
        return
    if isinstance(value, str):
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            if not isinstance(key, str):
                raise CanonicalisationError(
                    f"{path}: object keys must be strings; sorting a mixed-type "
                    "key set is undefined"
                )
            _reject(nested, f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _reject(nested, f"{path}[{index}]")
        return
    raise CanonicalisationError(f"{path}: {type(value).__name__} has no canonical form")


def canonical_json(value: Any) -> bytes:
    """The exact bytes a chain row is signed and hashed over.

    ``sort_keys`` sorts recursively, which is the property this relies on.
    Duplicate keys cannot arise here because the input is already a mapping;
    they are a parsing concern for whoever reads the bytes back.
    """
    _reject(value, "$")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
