# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``state`` section."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ori.config._fields import ConfigValidationError


@dataclass
class CompactionConfig:
    max_backward_skew_ms: int = 3600000


@dataclass
class StateEncryptionConfig:
    mode: str = "disabled"
    encrypted_path_prefixes: list[str] = field(default_factory=list)
    marker_file: str = ""


@dataclass
class StateConfig:
    compaction: CompactionConfig = field(default_factory=CompactionConfig)
    encryption: StateEncryptionConfig = field(default_factory=StateEncryptionConfig)


def parse_state(data: Any) -> StateConfig:
    if not isinstance(data, dict):
        return StateConfig()
    comp_data = data.get("compaction", {})
    if not isinstance(comp_data, dict):
        comp_data = {}
    encryption_data = data.get("encryption", {})
    if not isinstance(encryption_data, dict):
        raise ConfigValidationError("state.encryption must be a mapping.")

    try:
        max_skew = int(comp_data.get("max_backward_skew_ms", 3600000))
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "state.compaction.max_backward_skew_ms must be an integer."
        ) from exc

    if max_skew < 60000:
        raise ConfigValidationError(
            "state.compaction.max_backward_skew_ms must be >= 60000."
        )

    encryption = _parse_state_encryption(encryption_data)

    return StateConfig(
        compaction=CompactionConfig(max_backward_skew_ms=max_skew),
        encryption=encryption,
    )


def _parse_state_encryption(data: dict[str, Any]) -> StateEncryptionConfig:
    mode = str(data.get("mode", "disabled") or "disabled").strip().lower()
    if mode not in {"disabled", "filesystem_required"}:
        raise ConfigValidationError(
            "state.encryption.mode must be one of: disabled, filesystem_required."
        )

    prefixes_raw = data.get("encrypted_path_prefixes", [])
    if prefixes_raw is None:
        prefixes_raw = []
    if not isinstance(prefixes_raw, list):
        raise ConfigValidationError(
            "state.encryption.encrypted_path_prefixes must be a list."
        )
    prefixes = [str(item).strip() for item in prefixes_raw if str(item).strip()]
    for prefix in prefixes:
        prefix_path = Path(prefix).expanduser()
        if not prefix_path.is_absolute():
            raise ConfigValidationError(
                "state.encryption.encrypted_path_prefixes entries must be absolute paths."
            )
        resolved_prefix = prefix_path.resolve(strict=False)
        if str(resolved_prefix) == resolved_prefix.anchor:
            raise ConfigValidationError(
                "state.encryption.encrypted_path_prefixes must not contain a root path."
            )
    marker_file = str(data.get("marker_file", "") or "").strip()
    if marker_file and not Path(marker_file).expanduser().is_absolute():
        raise ConfigValidationError(
            "state.encryption.marker_file must be an absolute path."
        )

    if mode == "filesystem_required" and not prefixes and not marker_file:
        raise ConfigValidationError(
            "state.encryption.mode=filesystem_required requires "
            "encrypted_path_prefixes or marker_file."
        )

    return StateEncryptionConfig(
        mode=mode,
        encrypted_path_prefixes=prefixes,
        marker_file=marker_file,
    )
