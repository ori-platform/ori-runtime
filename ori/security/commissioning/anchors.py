# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Commissioning anchors: delivered out of band, compared as key material.

The locations are constants of commissioned-safety-binding/v1: the installer
writes them into the service environment, and no configuration document names
or overrides them. `anchor_collision` is decided here, at configuration load,
before any binding is seen.
"""

from __future__ import annotations

import base64
import binascii
import os
from dataclasses import dataclass
from typing import Any, Mapping

COMMISSIONING_ANCHOR_ENV = "ORI_COMMISSIONING_ANCHOR_PUBLIC_KEY_B64"
COMMISSIONING_ANCHOR_PREVIOUS_ENV = "ORI_COMMISSIONING_ANCHOR_PREVIOUS_PUBLIC_KEY_B64"


class AnchorError(ValueError):
    """An anchor that cannot be used; the message names which and why."""


@dataclass(frozen=True)
class CommissioningAnchors:
    current: bytes | None
    previous: bytes | None

    @property
    def configured(self) -> bool:
        return self.current is not None


def _decode_anchor(name: str, text: str) -> bytes:
    """Exactly one spelling of a 32-byte key, like the key inside a binding."""
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AnchorError(f"{name} is not base64") from exc
    if len(raw) != 32:
        raise AnchorError(f"{name} does not hold a 32-byte Ed25519 public key")
    if base64.b64encode(raw).decode("ascii") != text:
        raise AnchorError(f"{name} is not canonically encoded")
    return raw


def load_commissioning_anchors(
    environ: Mapping[str, str] | None = None,
) -> CommissioningAnchors:
    """Read both anchors from the environment; a previous without a current is an error."""
    env = os.environ if environ is None else environ
    current_text = (env.get(COMMISSIONING_ANCHOR_ENV) or "").strip()
    previous_text = (env.get(COMMISSIONING_ANCHOR_PREVIOUS_ENV) or "").strip()
    current = (
        _decode_anchor(COMMISSIONING_ANCHOR_ENV, current_text) if current_text else None
    )
    previous = (
        _decode_anchor(COMMISSIONING_ANCHOR_PREVIOUS_ENV, previous_text)
        if previous_text
        else None
    )
    if previous is not None and current is None:
        raise AnchorError(
            f"{COMMISSIONING_ANCHOR_PREVIOUS_ENV} is set without "
            f"{COMMISSIONING_ANCHOR_ENV}; a verify-only generation needs a current one"
        )
    if previous is not None and previous == current:
        raise AnchorError(
            "the previous commissioning anchor is the current one; rotation "
            "demotes a key, it does not duplicate it"
        )
    return CommissioningAnchors(current=current, previous=previous)


def provisioning_anchor(
    security: Mapping[str, Any], environ: Mapping[str, str] | None = None
) -> bytes | None:
    """The provisioning anchor as raw key material, from the environment it names.

    Material that is missing or not a 32-byte key reads as absent rather than
    raising. This value exists here only to be compared against the
    commissioning anchors, and something that is not a key cannot collide with
    one; whether a malformed provisioning anchor is itself an error belongs to
    the config-signing path that actually verifies with it.
    """
    env = os.environ if environ is None else environ
    signature = security.get("config_signature") or {}
    if not isinstance(signature, Mapping):
        return None
    name = str(signature.get("trust_anchor_env") or "").strip()
    text = (env.get(name) or "").strip() if name else ""
    if not text:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if len(raw) == 32 else None


def anchor_collision(
    anchors: CommissioningAnchors, provisioning_anchor: bytes | None
) -> bool:
    """Whether any commissioning anchor is the provisioning anchor's key material."""
    if provisioning_anchor is None:
        return False
    return provisioning_anchor in {anchors.current, anchors.previous}
