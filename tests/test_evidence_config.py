# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Evidence configuration and attestor construction.

These invariants moved here when the private-artifact tests were retired. They
are not artifact-shaped: whether evidence is off by default, whether an empty
secret fails loudly, and whether the two storage paths must differ are
properties of the platform, and the deleted file was the only place they were
asserted.
"""

from __future__ import annotations

from typing import cast

import pytest

from ori.config import (
    Config,
    ConfigValidationError,
    EvidenceConfig,
    _parse_evidence,
)
from ori.runtime import _build_evidence_attestor


class _Device:
    id = "energy-monitor-ikeja-01"


class _Gateway:
    auth: dict = {}


class _Config:
    """The three attributes `_build_evidence_attestor` actually reads.

    Deliberately narrow rather than a full `Config`: constructing one would add
    a dozen unrelated sections whose values this test does not control and does
    not care about, which makes a failure harder to read, not easier. The cast
    at each call site records that the narrowness is intentional.
    """

    def __init__(self, evidence: EvidenceConfig) -> None:
        self.evidence = evidence
        self.device = _Device()
        self.gateway = _Gateway()


class TestEvidenceConfigParsing:
    def test_evidence_is_disabled_by_default(self) -> None:
        """Signing is opt-in. A device does not start keeping evidence unasked."""
        assert _parse_evidence(None).enabled is False
        assert _parse_evidence({}).enabled is False

    def test_an_absent_section_yields_safe_defaults(self) -> None:
        cfg = _parse_evidence(None)
        assert cfg.enabled is False
        assert cfg.db_path and cfg.key_path
        assert cfg.device_secret_env == "ORI_EVIDENCE_DEVICE_SECRET"

    def test_an_enabled_section_parses(self) -> None:
        cfg = _parse_evidence(
            {
                "enabled": True,
                "db_path": "/var/lib/ori/e.db",
                "key_path": "/var/lib/ori/e.key",
                "device_secret_env": "ORI_TEST_SECRET",
            }
        )
        assert cfg.enabled is True
        assert cfg.db_path == "/var/lib/ori/e.db"
        assert cfg.key_path == "/var/lib/ori/e.key"
        assert cfg.device_secret_env == "ORI_TEST_SECRET"

    def test_a_non_mapping_section_is_refused(self) -> None:
        with pytest.raises(ConfigValidationError):
            _parse_evidence(["enabled"])

    @pytest.mark.parametrize(
        "env_name", ["", "  ", "not a name", "1LEADING_DIGIT", "has-dash"]
    )
    def test_an_invalid_secret_env_name_is_refused(self, env_name: str) -> None:
        """A malformed name cannot resolve, so evidence would silently never key."""
        with pytest.raises(ConfigValidationError):
            _parse_evidence({"enabled": True, "device_secret_env": env_name})

    def test_the_database_and_key_paths_must_differ(self) -> None:
        """One file cannot be both the chain and the key that signs it."""
        with pytest.raises(ConfigValidationError, match="must differ"):
            _parse_evidence(
                {
                    "enabled": True,
                    "db_path": "/var/lib/ori/e",
                    "key_path": "/var/lib/ori/e",
                }
            )


class TestReleaseOwnedSettingsAreRefused:
    """A site operator is the party evidence exists to constrain.

    Both of these were briefly accepted as site configuration, which was a
    security regression: an operator who can choose the authority trust root can
    make arbitrary receipts trusted, and one who can widen the checkpoint cadence
    can make the obligation meaningless without disabling anything.
    """

    @pytest.mark.parametrize(
        "key, value",
        [
            ("authority_keys_path", "/tmp/keys.json"),
            ("checkpoint_interval_s", 900.0),
            ("checkpoint_interval_s", float("inf")),
        ],
    )
    def test_a_release_owned_setting_in_site_config_is_refused(
        self, key: str, value: object
    ) -> None:
        with pytest.raises(ConfigValidationError, match="not a site setting"):
            _parse_evidence({"enabled": True, key: value})

    def test_the_config_surface_carries_neither_field(self) -> None:
        """Refusing the key is not enough if the dataclass still holds one."""
        cfg = _parse_evidence({"enabled": True})
        assert not hasattr(cfg, "authority_keys_path")
        assert not hasattr(cfg, "checkpoint_interval_s")

    def test_the_derived_identifiers_are_not_configurable(self) -> None:
        """They are sealed into immutable envelopes; an operator-set value could
        not be corrected afterwards."""
        cfg = _parse_evidence({"enabled": True})
        assert not hasattr(cfg, "anchor_epoch_id")
        assert not hasattr(cfg, "key_id")


class TestAttestorConstruction:
    def test_disabled_config_builds_no_attestor(self) -> None:
        assert _build_evidence_attestor(cast(Config, _Config(EvidenceConfig()))) is None

    def test_enabled_without_a_secret_fails_loudly(self, monkeypatch) -> None:
        """A silently unkeyed chain would defeat the point of enabling it."""
        monkeypatch.delenv("ORI_TEST_EVIDENCE_SECRET", raising=False)
        cfg = _Config(
            EvidenceConfig(enabled=True, device_secret_env="ORI_TEST_EVIDENCE_SECRET")
        )
        with pytest.raises(ValueError, match="device-secret"):
            _build_evidence_attestor(cast(Config, cfg))

    def test_an_empty_secret_is_treated_as_missing(self, monkeypatch) -> None:
        monkeypatch.setenv("ORI_TEST_EVIDENCE_SECRET", "")
        cfg = _Config(
            EvidenceConfig(enabled=True, device_secret_env="ORI_TEST_EVIDENCE_SECRET")
        )
        with pytest.raises(ValueError):
            _build_evidence_attestor(cast(Config, cfg))

    def test_enabled_with_a_secret_builds_an_attestor(
        self, monkeypatch, tmp_path
    ) -> None:
        monkeypatch.setenv("ORI_TEST_EVIDENCE_SECRET", "install-secret")
        cfg = _Config(
            EvidenceConfig(
                enabled=True,
                db_path=str(tmp_path / "e.db"),
                key_path=str(tmp_path / "e.key"),
                device_secret_env="ORI_TEST_EVIDENCE_SECRET",
            )
        )
        attestor = _build_evidence_attestor(cast(Config, cfg))
        assert attestor is not None
        try:
            assert attestor.available is False, "construction must not open anything"
        finally:
            attestor.close()

    def test_no_authority_keys_ship_today(self, monkeypatch, tmp_path) -> None:
        """Absent is the correct posture, and it must fail closed rather than open.

        With no registry, a receipt or epoch confirmation is refused as
        unknown-key. If this ever returns keys without a release shipping them,
        something is resolving a trust root from somewhere it should not.
        """
        from ori.runtime import _load_authority_keys

        assert _load_authority_keys() == {}


class TestConfigLoadWiresTheEvidenceParser:
    """`_parse_evidence` being correct is not enough if nothing calls it.

    The retired test exercised `Config.load()` end to end. A replacement that
    only calls the parser directly cannot catch `load()` failing to invoke it,
    or assigning its result somewhere else — which would leave every parser
    assertion above true and the runtime reading a default nobody chose.
    """

    @staticmethod
    def _write(tmp_path, evidence_block: str) -> str:
        path = tmp_path / "ori.yaml"
        path.write_text(
            "device:\n"
            "  id: energy-monitor-ikeja-01\n"
            "  name: Test Device\n"
            "  location: Lagos\n"
            "sensors: []\n"
            "skills: []\n" + evidence_block,
            encoding="utf-8",
        )
        return str(path)

    def test_an_absent_section_loads_as_disabled(self, tmp_path) -> None:
        cfg = Config.load(self._write(tmp_path, ""))
        assert cfg.evidence.enabled is False

    def test_an_enabled_section_reaches_the_loaded_config(self, tmp_path) -> None:
        """Proves the parser's result is what `load()` actually assigns."""
        cfg = Config.load(
            self._write(
                tmp_path,
                "evidence:\n"
                "  enabled: true\n"
                "  db_path: /var/lib/ori/e.db\n"
                "  key_path: /var/lib/ori/e.key\n",
            )
        )
        assert cfg.evidence.enabled is True
        assert cfg.evidence.db_path == "/var/lib/ori/e.db"
        assert cfg.evidence.key_path == "/var/lib/ori/e.key"

    def test_a_release_owned_setting_is_refused_through_load(self, tmp_path) -> None:
        """The refusal must survive the real loading path, not only the parser."""
        with pytest.raises(ConfigValidationError, match="not a site setting"):
            Config.load(
                self._write(
                    tmp_path,
                    "evidence:\n  enabled: true\n  checkpoint_interval_s: 900\n",
                )
            )
