# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""What the runtime's posture record says, read from the run."""

from __future__ import annotations

import functools
import sys
from pathlib import Path
from typing import Any

from ori.gateway.posture_publisher import PostureContent, installed_alert_classes
from ori.policy.alert_classes import alert_class_for_trigger
from ori.security.release_bundles import installed_release_version


@functools.cache
def installed_release(prefix: str = sys.prefix) -> str | None:
    """The verified release this interpreter's installation came from.

    An installed release runs from `<release>/venv`; anything else (a dev,
    editable or pip install) has no verified bundle, and so no release.
    """
    venv = Path(prefix)
    return installed_release_version(venv.parent) if venv.name == "venv" else None


def posture_content(
    config: Any, commissioning_state: Any, loaded_skills: list[Any]
) -> PostureContent | None:
    """The record's members, or None before the configuration is loaded."""
    if config is None:
        return None
    state = commissioning_state
    in_force = getattr(state, "in_force", None) if state is not None else None
    return PostureContent(
        device_id=str(config.device.id),
        release=installed_release(),
        deployment_profile=str(config.device.deployment_profile),
        commissioned_binding=(
            str(in_force.canonical_hash) if in_force is not None else None
        ),
        alert_classes=installed_alert_classes(
            list(loaded_skills or []),
            lambda skill, trigger: alert_class_for_trigger(
                skill, trigger, first_party=True
            ),
        ),
    )


def posture_key_readback(runtime: Any) -> tuple[str, bytes] | None:
    """The device and its posture key for operator-socket/v3's readback."""
    attestor = getattr(runtime, "_evidence_attestor", None)
    config = getattr(runtime, "_config", None)
    if attestor is None or config is None:
        return None
    key = attestor.posture_public_key()
    return None if key is None else (str(config.device.id), key)
