# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``evidence`` section."""

from dataclasses import dataclass
from typing import Any

from ori.config._env import ENV_NAME_RE
from ori.config._fields import ConfigValidationError
from ori.utils.bool_utils import is_truthy


@dataclass
class EvidenceConfig:
    """On-device Tier C/D evidence signing configuration."""

    enabled: bool = False
    db_path: str = "ori_evidence.db"
    key_path: str = "ori_evidence.key"
    device_secret_env: str = "ORI_EVIDENCE_DEVICE_SECRET"

    # Four things are deliberately absent from this surface, for one reason:
    # a site operator is the party evidence exists to constrain, so nothing an
    # operator can edit may weaken it.
    #
    # authority_keys_path -- the authority trust root arrives only in the signed
    # release. A path here would let an operator point the runtime at keys of
    # their choosing and make arbitrary receipts and epoch confirmations
    # trusted, which is the whole property the registry exists to provide.
    #
    # checkpoint_interval_s -- a checkpoint constrains the device and its
    # courier, so its cadence cannot be set by them. An operator who could
    # widen it could make the obligation meaningless without disabling
    # anything. The cadence is release-owned, and its permitted maximum is
    # still open in the contract.
    #
    # anchor_epoch_id and key_id -- derived per runtime-evidence-anchor/v2. They are derived per
    # runtime-evidence-anchor/v2 from the device identity, evidence key, custody
    # posture and capability profile. Both are sealed into immutable envelopes
    # and recomputed by the evidence authority, so a value an operator could set
    # is one that would eventually be set wrongly and could not be corrected.


def parse_evidence(data: Any) -> EvidenceConfig:
    if data is None:
        return EvidenceConfig()
    if not isinstance(data, dict):
        raise ConfigValidationError("'evidence' section must be a mapping.")
    enabled = is_truthy(data.get("enabled", False))
    db_path = str(data.get("db_path", "ori_evidence.db") or "").strip()
    key_path = str(data.get("key_path", "ori_evidence.key") or "").strip()
    device_secret_env = str(
        data.get("device_secret_env", "ORI_EVIDENCE_DEVICE_SECRET") or ""
    ).strip()
    if enabled:
        if not db_path:
            raise ConfigValidationError(
                "evidence.db_path is required when evidence.enabled is true"
            )
        if not key_path:
            raise ConfigValidationError(
                "evidence.key_path is required when evidence.enabled is true"
            )
        if not ENV_NAME_RE.match(device_secret_env):
            raise ConfigValidationError(
                "evidence.device_secret_env must be a valid environment variable name"
            )
        if db_path == key_path:
            raise ConfigValidationError(
                "evidence.db_path and evidence.key_path must differ"
            )
    for owned in ("authority_keys_path", "checkpoint_interval_s"):
        if owned in data:
            raise ConfigValidationError(
                f"'evidence.{owned}' is not a site setting. The authority trust "
                "root and the checkpoint cadence are owned by the signed "
                "release, because a site operator is the party evidence exists "
                "to constrain."
            )
    for carried in (
        "commissioning_reference",
        "commissioning_digest",
        "commissioning_authorization",
        "commissioning_authorisation",
    ):
        if carried in data:
            raise ConfigValidationError(
                f"'evidence.{carried}' cannot be configured. The commissioning "
                "reference reaches a device only through `evidence commission` "
                "at the device, and the authorisation never reaches it at all."
            )

    return EvidenceConfig(
        enabled=enabled,
        db_path=db_path,
        key_path=key_path,
        device_secret_env=device_secret_env,
    )
