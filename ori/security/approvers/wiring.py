# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The registry's run context, from the verified configuration and the anchors.

- **Verified site.** `device.site_id` from a configuration whose signature
  verified under the current provisioning anchor. An unsigned development
  configuration's own value is accepted too, as tier-c-approvers/v1 allows for
  first setup and `local_seed`; such a run has no verified anchor, so it
  cannot apply a revocation. A hardened posture without a verified signature
  has no verified site, and every registry operation is `registry_unavailable`.
- **Anchors.** The provisioning anchor is read from where the configuration
  signature is verified, its previous generation from
  `ORI_CONFIG_TRUST_ANCHOR_PREVIOUS_PUBLIC_KEY_B64`, and every other configured
  anchor (commissioning, current and previous, and the entitlement key, from
  `ORI_DEVICE_POLICY_PUBLIC_KEY_B64` or `device_policy.public_key_b64`) is of
  another class.
- **Authenticated phone ingress.** None in this version: no phone text reaches
  the registry yet, so a phone candidate is refused `channel_unauthenticated`.
"""

from __future__ import annotations

import base64
import binascii
import logging
import os
import secrets
import time
from collections.abc import Mapping
from typing import TYPE_CHECKING, Final

from ori.security.approvers.forms import is_device_id
from ori.security.approvers.registry import Anchors, ApproverRegistry, RunContext
from ori.security.approvers.service import RegistryService
from ori.security.commissioning.anchors import (
    COMMISSIONING_ANCHOR_ENV,
    COMMISSIONING_ANCHOR_PREVIOUS_ENV,
)

if TYPE_CHECKING:
    from ori.config import Config
    from ori.state.store import StateStore

logger = logging.getLogger(__name__)

PREVIOUS_PROVISIONING_ANCHOR_ENV: Final = (
    "ORI_CONFIG_TRUST_ANCHOR_PREVIOUS_PUBLIC_KEY_B64"
)
#: runtime-config-orchestration/v1's fixed location for the entitlement key.
COMMERCIAL_ANCHOR_ENV: Final = "ORI_DEVICE_POLICY_PUBLIC_KEY_B64"


def _key(text: str | None) -> bytes | None:
    """A raw 32-byte key from its one canonical spelling, else None."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != text:
        return None
    return raw


def anchors_for(config: Config, environ: Mapping[str, str] | None = None) -> Anchors:
    env = os.environ if environ is None else environ
    signature = config.security.get("config_signature", {})
    verified = bool(signature.get("verified"))
    current_text = env.get(str(signature.get("trust_anchor_env") or ""), "")
    current = _key(current_text)
    configured = [
        env.get(PREVIOUS_PROVISIONING_ANCHOR_ENV, ""),
        env.get(COMMISSIONING_ANCHOR_ENV, ""),
        env.get(COMMISSIONING_ANCHOR_PREVIOUS_ENV, ""),
        env.get(COMMERCIAL_ANCHOR_ENV, ""),
        # Where this runtime reads the entitlement key today.
        str(getattr(config, "device_policy", {}).get("public_key_b64", "") or ""),
    ]
    # A set anchor that is not a key leaves no way to tell it from the current
    # one, so the whole set refuses: the current anchor is then unusable.
    malformed = any(text.strip() and _key(text) is None for text in configured)
    previous = _key(configured[0])
    others = tuple(k for k in (_key(t) for t in configured[1:]) if k is not None)
    return Anchors(
        current=None if malformed else current,
        previous=previous,
        other_class=others,
        verified_config=verified,
    )


def verified_site_for(config: Config) -> str | None:
    from ori.config import requires_production_posture

    site = config.device.site_id
    if not site or not is_device_id(config.device.id):
        # A device ID no challenge or revocation can carry binds no registry.
        return None
    if config.security.get("config_signature", {}).get("verified"):
        return site
    if requires_production_posture(device=config.device, security=config.security):
        return None
    return site


def run_context_for(
    config: Config, environ: Mapping[str, str] | None = None
) -> RunContext:
    return RunContext(
        device_id=config.device.id,
        verified_site_id=verified_site_for(config),
        authenticated_phone_channels=frozenset(),
        anchors=anchors_for(config, environ),
        run_id=secrets.token_hex(16),
    )


async def prepare_registry_service(
    store: StateStore | None, config: Config | None
) -> RegistryService | None:
    """The registry the operator socket serves, or None.

    None without a store or configuration, or when the store cannot prepare
    the registry: every registry operation then answers
    `registry_unavailable`. That fails Tier C closed and nothing else; the
    socket still serves reconciliation and commissioning, and the start
    completes. A run without a verified `device.site_id` holds a service
    whose operations all answer `registry_unavailable`.
    """
    if store is None or config is None:
        return None
    context = run_context_for(config)
    try:
        await store.retire_approver_runs(context.run_id)
    except Exception:
        logger.critical(
            "[runtime] the Tier C approver registry could not be prepared; "
            "every registry operation answers registry_unavailable and no "
            "reply can approve a Tier C action until a start prepares it",
            exc_info=True,
        )
        return None
    if context.verified_site_id is None:
        logger.info(
            "[runtime] no verified device.site_id: the Tier C approver "
            "registry is unavailable, and no reply can approve a Tier C action"
        )
    return RegistryService(
        store,
        ApproverRegistry(context, clock=lambda: int(time.monotonic() * 1000)),
    )
