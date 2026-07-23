# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tier C/D evidence signing: attestor, dispatcher wiring, reconciliation.

The private evidence-chain artifact is a pinned prebuilt dependency that is
not installed in runtime CI, so these tests inject a fake module. What they pin
down is the runtime's side of the contract: Option B append-after-log
attestation statuses, gap visibility, reconciliation, and graceful degradation
when the artifact or chain is unavailable.
"""

import base64
import sys
import threading
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ori.config import Config, ConfigValidationError, EvidenceConfig, _parse_evidence
from ori.gateway.node_heartbeat import MqttRuntimeNodeHeartbeatPublisher
from ori.network.events import ActionResult, OriEvent, SensorReading
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.runtime import OriRuntime, _build_evidence_attestor
from ori.security.evidence import EvidenceAttestor, tier_requires_attestation
from ori.security.firmware_confirmation import FirmwareConfirmationCoordinator
from ori.state.store import StateStore

_FAKE_ARTIFACT_MODULE = "ori_private_evidence_test_artifact"

# ─── Fake private evidence artifact ───────────────────────────────────────────


class _FakeEvidenceChain:
    def __init__(self, db_path: str, key_path: str, device_secret: str) -> None:
        self.db_path = db_path
        self.appended: list[tuple] = []
        self.atomic_appended: list[tuple] = []
        self.layer1_devices: dict[str, dict] = {}
        self._seq_by_event_id: dict[str, int] = {}
        self._seq = 0
        self.fail_append = False

    def public_key_hex(self) -> str:
        return "ab" * 32

    def append_event(
        self,
        event_type: str,
        device_id: str,
        emitted_at_ms: int,
        payload_json: str,
        event_id: str | None = None,
    ) -> int:
        if self.fail_append:
            raise ValueError("chain unavailable")
        if event_id in self._seq_by_event_id:
            raise ValueError("UNIQUE constraint failed: evidence_chain.event_id")
        self._seq += 1
        if event_id:
            self._seq_by_event_id[event_id] = self._seq
        self.appended.append(
            (event_type, device_id, emitted_at_ms, payload_json, event_id)
        )
        return self._seq

    def append_event_with_freshness(
        self,
        event_type: str,
        device_id: str,
        emitted_at_ms: int,
        payload_json: str,
        source_device_id: str,
        boot_id: int,
        seq: int,
        event_id: str | None = None,
    ) -> int:
        if self.fail_append:
            raise ValueError("chain unavailable")
        if event_id in self._seq_by_event_id:
            raise ValueError("UNIQUE constraint failed: evidence_chain.event_id")
        self._seq += 1
        if event_id:
            self._seq_by_event_id[event_id] = self._seq
        self.atomic_appended.append(
            (
                event_type,
                device_id,
                emitted_at_ms,
                payload_json,
                source_device_id,
                boot_id,
                seq,
                event_id,
            )
        )
        return self._seq

    def seq_for_event_id(self, event_id: str) -> int | None:
        return self._seq_by_event_id.get(event_id)

    def register_layer1_device(
        self,
        device_id: str,
        public_key: str,
        alg: str,
        posture: str,
        capability_hash: str,
        hardware_profile: str,
        provisioned_at_ms: int,
        approved: bool = False,
        actor: str = "",
        reason: str = "",
    ) -> None:
        # The lifecycle FFI requires attribution when approved: a promotion
        # is an operator decision. The mock records it so tests can assert
        # the runtime forwarded the persisted provenance.
        if approved and (not actor.strip() or not reason.strip()):
            raise ValueError("approved registration requires actor and reason")
        self.layer1_devices[device_id] = {
            "device_id": device_id,
            "public_key": public_key,
            "alg": alg,
            "posture": posture,
            "capability_hash": capability_hash,
            "hardware_profile": hardware_profile,
            "approved": approved,
            "approval_actor": actor,
            "approval_reason": reason,
            "provisioned_at_ms": provisioned_at_ms,
            "last_boot_id": 0,
            "last_seq": 0,
            "revoked": False,
            "revoked_at_ms": None,
        }

    def registered_layer1_device(self, device_id: str) -> dict | None:
        return self.layer1_devices.get(device_id)

    def active_anchor_epoch_id(self, device_id: str) -> str | None:
        # Mirror the evidence store: derive the active anchor's epoch from
        # the stored, approved, unrevoked device, so the runtime's
        # evidence-acceptance gate sees agreement when the chain holds the
        # same anchor.
        dev = self.layer1_devices.get(device_id)
        if dev is None or not dev.get("approved") or dev.get("revoked"):
            return None
        from ori.security.firmware_telemetry import anchor_epoch_id

        return anchor_epoch_id(
            device_id=device_id,
            public_key_b64=base64.b64encode(
                bytes.fromhex(str(dev["public_key"]))
            ).decode(),
            posture=str(dev["posture"]),
            capability_hash=str(dev["capability_hash"]),
        )

    def chain_head_hash(self) -> str | None:
        return f"head-{self._seq}" if self._seq else None

    def pending_count(self) -> int:
        return self._seq


def _install_fake_artifact(
    monkeypatch,
    *,
    protocol_version: str = "evidence.v1",
    artifact_version: str = "0.1.0",
) -> type[_FakeEvidenceChain]:
    module = types.ModuleType(_FAKE_ARTIFACT_MODULE)
    module.EvidenceChain = _FakeEvidenceChain
    module.PROTOCOL_VERSION = protocol_version
    module.ARTIFACT_VERSION = artifact_version
    monkeypatch.setenv("ORI_EVIDENCE_ARTIFACT_MODULE", _FAKE_ARTIFACT_MODULE)
    monkeypatch.setenv("ORI_EVIDENCE_ARTIFACT_PROTOCOL_VERSION", "evidence.v1")
    monkeypatch.setitem(sys.modules, _FAKE_ARTIFACT_MODULE, module)
    return _FakeEvidenceChain


async def _started_attestor(
    monkeypatch, tmp_path, *, artifact_version: str = "0.1.0"
) -> EvidenceAttestor:
    _install_fake_artifact(monkeypatch, artifact_version=artifact_version)
    attestor = EvidenceAttestor(
        db_path=str(tmp_path / "evidence.db"),
        key_path=str(tmp_path / "evidence.key"),
        device_secret="install-secret",
        device_id="dev-01",
    )
    assert await attestor.start() is True
    return attestor


def _result(tier: str = "C", **overrides) -> ActionResult:
    fields = dict(
        action_name="open_safety_circuit",
        tier=tier,
        executed=True,
        approved=True if tier == "C" else None,
        action_taken="open_safety_circuit",
        timestamp=1_760_000_000_000,
        proposal_id="AB12CD34",
        correlation_id="corr-1",
    )
    fields.update(overrides)
    return ActionResult(**fields)


# ─── Config parsing ───────────────────────────────────────────────────────────


class TestEvidenceConfig:
    def test_defaults_disabled(self):
        cfg = _parse_evidence(None)
        assert cfg == EvidenceConfig()
        assert cfg.enabled is False

    def test_enabled_requires_valid_env_name(self):
        with pytest.raises(ConfigValidationError, match="device_secret_env"):
            _parse_evidence({"enabled": True, "device_secret_env": "not a valid name"})

    def test_enabled_requires_distinct_paths(self):
        with pytest.raises(ConfigValidationError, match="must differ"):
            _parse_evidence(
                {"enabled": True, "db_path": "same.db", "key_path": "same.db"}
            )

    def test_enabled_parses(self):
        cfg = _parse_evidence(
            {
                "enabled": True,
                "db_path": "/var/lib/ori/evidence.db",
                "key_path": "/etc/ori/evidence.key",
                "device_secret_env": "ORI_EVIDENCE_DEVICE_SECRET",
            }
        )
        assert cfg.enabled is True
        assert cfg.db_path == "/var/lib/ori/evidence.db"

    def test_config_load_defaults_when_section_absent(self, tmp_path):
        yaml_path = tmp_path / "ori.yaml"
        yaml_path.write_text(
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway: {}
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            """
        )
        cfg = Config.load(str(yaml_path))
        assert cfg.evidence.enabled is False


# ─── Attestor ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestEvidenceAttestor:
    async def test_start_provisions_key_and_exposes_anchor(self, monkeypatch, tmp_path):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        assert attestor.available is True
        assert attestor.public_key_hex == "ab" * 32
        attestor.close()

    async def test_missing_artifact_degrades_gracefully(self, monkeypatch, tmp_path):
        monkeypatch.setenv("ORI_EVIDENCE_ARTIFACT_MODULE", _FAKE_ARTIFACT_MODULE)
        monkeypatch.setitem(sys.modules, _FAKE_ARTIFACT_MODULE, None)
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "evidence.key"),
            device_secret="install-secret",
            device_id="dev-01",
        )
        assert await attestor.start() is False
        assert attestor.available is False
        assert await attestor.attest_action({"id": 1, "timestamp": 1}) is None
        assert await attestor.chain_head_hash() is None
        attestor.close()

    async def test_attest_action_signs_with_original_timestamp(
        self, monkeypatch, tmp_path
    ):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        seq = await attestor.attest_action(
            {
                "id": 7,
                "action_name": "emergency_cutoff",
                "tier": "D",
                "executed": True,
                "approved": None,
                "action_taken": "emergency_cutoff",
                "trigger_name": "dangerous_overcurrent",
                "timestamp": 1_760_000_000_123,
            }
        )
        assert seq == 1
        event_type, device_id, emitted_at_ms, payload_json, event_id = (
            attestor._chain.appended[0]
        )
        assert event_type == "MAINTENANCE_PERFORMED"
        assert device_id == "dev-01"
        assert emitted_at_ms == 1_760_000_000_123
        assert '"action_tier": "D"' in payload_json
        assert '"kind": "runtime_action"' in payload_json
        assert '"attestation": "at_emission"' in payload_json
        assert event_id == attestor.attestation_event_id(7)
        attestor.close()

    async def test_attest_action_downgrades_invalid_input_evidence(
        self, monkeypatch, tmp_path
    ):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            await attestor.attest_action(
                {
                    "id": 8,
                    "action_name": "emergency_cutoff",
                    "tier": "D",
                    "executed": True,
                    "action_taken": "emergency_cutoff",
                    "input_attestation_grade": "attested",
                    "input_posture": "",
                    "timestamp": 1,
                }
            )
            payload_json = attestor._chain.appended[0][3]
            assert '"input_attestation_grade": "unattested"' in payload_json
            assert '"input_posture": ""' in payload_json
        finally:
            attestor.close()

    async def test_append_failure_returns_none(self, monkeypatch, tmp_path):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        attestor._chain.fail_append = True
        assert await attestor.attest_action({"id": 1, "timestamp": 1}) is None
        attestor.close()


# ─── Event vocabulary selection ───────────────────────────────────────────────


@pytest.mark.asyncio
class TestActionEventVocabulary:
    """Artifacts >= 0.2.0 provide SAFETY_ACTION_EXECUTED; older or
    unreadable versions must stay on the legacy type every artifact
    accepts."""

    async def test_legacy_artifact_uses_maintenance_performed(
        self, monkeypatch, tmp_path
    ):
        attestor = await _started_attestor(
            monkeypatch, tmp_path, artifact_version="0.1.0"
        )
        assert attestor.action_event_type == "MAINTENANCE_PERFORMED"
        attestor.close()

    async def test_vocabulary_artifact_uses_safety_action_executed(
        self, monkeypatch, tmp_path
    ):
        attestor = await _started_attestor(
            monkeypatch, tmp_path, artifact_version="0.2.0"
        )
        assert attestor.action_event_type == "SAFETY_ACTION_EXECUTED"
        await attestor.attest_action({"id": 3, "tier": "D", "timestamp": 5})
        event_type, _, _, payload_json, _ = attestor._chain.appended[0]
        assert event_type == "SAFETY_ACTION_EXECUTED"
        # Payload stays identical across vocabularies so verifiers can
        # treat both forms uniformly.
        assert '"kind": "runtime_action"' in payload_json
        attestor.close()

    async def test_unparseable_artifact_version_falls_back_to_legacy(
        self, monkeypatch, tmp_path
    ):
        attestor = await _started_attestor(
            monkeypatch, tmp_path, artifact_version="dev"
        )
        assert attestor.action_event_type == "MAINTENANCE_PERFORMED"
        attestor.close()

    async def test_unavailable_attestor_reports_legacy_type(
        self, monkeypatch, tmp_path
    ):
        # Never started: the default must be the universally accepted type.
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "evidence.key"),
            device_secret="install-secret",
            device_id="dev-01",
        )
        assert attestor.action_event_type == "MAINTENANCE_PERFORMED"
        attestor.close()


@pytest.mark.asyncio
class TestChainReleaseThread:
    """The pyo3 chain is unsendable: every path that lets go of a chain
    object — close() and rejected starts alike — must drop it on the
    evidence thread, or the real extension raises at GC time."""

    @staticmethod
    def _tracking_chain_cls():
        class _TrackingChain(_FakeEvidenceChain):
            deleted_on: list[str] = []

            def __del__(self) -> None:
                _TrackingChain.deleted_on.append(threading.current_thread().name)

        return _TrackingChain

    async def test_close_drops_chain_on_evidence_thread(self, monkeypatch, tmp_path):
        cls = self._tracking_chain_cls()
        _install_fake_artifact(monkeypatch)
        sys.modules[_FAKE_ARTIFACT_MODULE].EvidenceChain = cls
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "evidence.key"),
            device_secret="install-secret",
            device_id="dev-01",
        )
        assert await attestor.start() is True
        attestor.close()
        assert len(cls.deleted_on) == 1
        assert cls.deleted_on[0].startswith("ori-evidence")

    async def test_rejected_start_drops_chain_on_evidence_thread(
        self, monkeypatch, tmp_path
    ):
        cls = self._tracking_chain_cls()
        _install_fake_artifact(monkeypatch, protocol_version="evidence.v0")
        sys.modules[_FAKE_ARTIFACT_MODULE].EvidenceChain = cls
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "evidence.key"),
            device_secret="install-secret",
            device_id="dev-01",
        )
        assert await attestor.start() is False
        assert len(cls.deleted_on) == 1
        assert cls.deleted_on[0].startswith("ori-evidence")
        attestor.close()


def test_version_gate_edge_cases():
    from ori.security.evidence import _artifact_supports_safety_event

    assert _artifact_supports_safety_event("0.2.0") is True
    assert _artifact_supports_safety_event("0.2.1") is True
    assert _artifact_supports_safety_event("0.10.0") is True
    assert _artifact_supports_safety_event("1.0.0") is True
    assert _artifact_supports_safety_event("0.1.9") is False
    assert _artifact_supports_safety_event("0.2") is False
    assert _artifact_supports_safety_event("0.2.0rc1") is False
    assert _artifact_supports_safety_event("") is False


# ─── Store attestation columns ────────────────────────────────────────────────


@pytest.mark.asyncio
class TestStoreAttestation:
    async def test_log_action_marks_pending_and_updates_status(self, tmp_path):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        try:
            row_id = await store.log_action(
                _result("C"), "critical_fault", attestation_pending=True
            )
            assert row_id >= 1
            pending = await store.get_actions_needing_attestation()
            assert [row["id"] for row in pending] == [row_id]

            await store.set_action_attestation(
                row_id, status="signed", attestation_seq=42
            )
            assert await store.get_actions_needing_attestation() == []
            summary = await store.get_attestation_summary()
            assert summary["last_attested_action_id"] == row_id
            assert summary["attestation_gap_count"] == 0
            assert summary["status_counts"] == {"signed": 1}
        finally:
            await store.close()

    async def test_rows_without_attestation_flag_stay_out_of_evidence(self, tmp_path):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        try:
            await store.log_action(_result("A", approved=None), "anomalous_draw")
            assert await store.get_actions_needing_attestation() == []
            summary = await store.get_attestation_summary()
            assert summary["status_counts"] == {}
            assert summary["attestation_gap_count"] == 0
        finally:
            await store.close()

    async def test_invalid_status_rejected(self, tmp_path):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        try:
            row_id = await store.log_action(
                _result("D", approved=None),
                "dangerous_overcurrent",
                attestation_pending=True,
            )
            with pytest.raises(ValueError, match="invalid attestation status"):
                await store.set_action_attestation(row_id, status="fabricated")
        finally:
            await store.close()


# ─── Dispatcher wiring ────────────────────────────────────────────────────────


@pytest.mark.asyncio
class TestDispatcherAttestation:
    def _dispatcher(self, store, attestor):
        return ActionDispatcher(
            state_store=store,
            alert_sender=AsyncMock(),
            config={"operator_contact": "+2348000000000"},
            evidence_attestor=attestor,
        )

    async def _register_and_confirm(
        self,
        store,
        attestor,
        device_id,
        *,
        public_key_b64,
        capability_hash,
        provisioned_at_ms=1,
    ):
        """Register, approve, and cross-store confirm a firmware device.

        Firmware-sourced evidence is only signed once its epoch is confirmed
        in the evidence store, so a dispatcher test that expects signing must
        first take the device through the coordinator, which pushes the
        anchor and resolves the obligation.
        """
        await store.upsert_firmware_device_anchor(
            device_id=device_id,
            public_key_b64=public_key_b64,
            posture="sealed_flash",
            capability_hash=capability_hash,
            manifest_json="{}",
            channel_map_json="{}",
            board_profile="esp32-s3-pzem-v1",
            provisioned_at_ms=provisioned_at_ms,
        )
        assert await store.approve_firmware_device(
            device_id, actor="test-operator", reason="test"
        )
        coordinator = FirmwareConfirmationCoordinator(
            store=store, chain=attestor.confirmation_chain()
        )
        assert await coordinator.confirm(device_id) == "confirmed"

    async def test_tier_c_action_is_signed_on_dispatch_path(
        self, monkeypatch, tmp_path
    ):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            dispatcher = self._dispatcher(store, attestor)
            context = SimpleNamespace(state_store=store, event=None)
            await dispatcher._log_action(_result("C"), context)

            rows = await store.get_action_log(limit=5)
            assert rows
            summary = await store.get_attestation_summary()
            assert summary["status_counts"] == {"signed": 1}
            assert summary["attestation_gap_count"] == 0
            assert len(attestor._chain.appended) == 1
            payload = attestor._chain.appended[0][3]
            assert '"input_attestation_grade": "unattested"' in payload
            assert '"input_posture": ""' in payload
        finally:
            attestor.close()
            await store.close()

    async def test_signed_action_carries_firmware_input_attestation_grade(
        self, monkeypatch, tmp_path
    ):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            await self._register_and_confirm(
                store,
                attestor,
                "ori-fw-7c9f2b3a",
                public_key_b64=base64.b64encode(bytes([0x11] * 32)).decode(),
                capability_hash="sha256:" + "ab" * 32,
            )
            dispatcher = self._dispatcher(store, attestor)
            reading = SensorReading(
                sensor_id="ori-fw-7c9f2b3a:ch0",
                sensor_type="current",
                value=21.0,
                unit="ampere",
                timestamp=1,
                quality=1.0,
                metadata={
                    "source": "firmware",
                    "attestation": "attested",
                    "posture": "sealed_flash",
                    "firmware_device_id": "ori-fw-7c9f2b3a",
                    "boot_id": 7,
                    "seq": 42,
                },
            )
            event = OriEvent.from_reading(reading, "runtime-01")
            context = SimpleNamespace(state_store=store, event=event)
            await dispatcher._log_action(_result("D", approved=None), context)

            row = (await store.get_action_log(limit=1))[0]
            assert row["input_attestation_grade"] == "attested"
            assert row["input_posture"] == "sealed_flash"
            assert row["input_firmware_device_id"] == "ori-fw-7c9f2b3a"
            assert row["input_firmware_boot_id"] == 7
            assert row["input_firmware_seq"] == 42
            payload = attestor._chain.appended[0][3]
            assert '"input_attestation_grade": "attested"' in payload
            assert '"input_posture": "sealed_flash"' in payload
            assert '"input_firmware_device_id": "ori-fw-7c9f2b3a"' in payload
            assert '"input_firmware_boot_id": 7' in payload
            assert '"input_firmware_seq": 42' in payload
        finally:
            attestor.close()
            await store.close()

    async def test_artifact_0_4_uses_atomic_freshness_append_for_firmware_input(
        self, monkeypatch, tmp_path
    ):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(
            monkeypatch, tmp_path, artifact_version="0.4.0"
        )
        try:
            assert attestor.atomic_freshness_available is True
            await self._register_and_confirm(
                store,
                attestor,
                "ori-fw-7c9f2b3a",
                public_key_b64=base64.b64encode(bytes([0x42]) * 32).decode("ascii"),
                capability_hash=(
                    "sha256:"
                    "13751b5335ccedcd4ffcc82bbda28ebfb7558859f36a74e710f1a0b0ab23da8d"
                ),
                provisioned_at_ms=1_760_000_000_000,
            )
            dispatcher = self._dispatcher(store, attestor)
            reading = SensorReading(
                sensor_id="ori-fw-7c9f2b3a:ch0",
                sensor_type="current",
                value=21.0,
                unit="ampere",
                timestamp=1,
                quality=1.0,
                metadata={
                    "source": "firmware",
                    "attestation": "attested",
                    "posture": "sealed_flash",
                    "firmware_device_id": "ori-fw-7c9f2b3a",
                    "boot_id": 7,
                    "seq": 42,
                },
            )
            event = OriEvent.from_reading(reading, "runtime-01")
            context = SimpleNamespace(state_store=store, event=event)
            await dispatcher._log_action(_result("D", approved=None), context)

            assert attestor._chain.appended == []
            assert len(attestor._chain.atomic_appended) == 1
            assert attestor._chain.layer1_devices["ori-fw-7c9f2b3a"]["public_key"] == (
                "42" * 32
            )
            atomic = attestor._chain.atomic_appended[0]
            assert atomic[4:7] == ("ori-fw-7c9f2b3a", 7, 42)
            payload = atomic[3]
            assert '"input_firmware_device_id": "ori-fw-7c9f2b3a"' in payload
        finally:
            attestor.close()
            await store.close()

    async def test_unconfirmed_firmware_evidence_is_withheld_on_immediate_path(
        self, monkeypatch, tmp_path
    ):
        # The immediate signing path must honour the cross-store gate too.
        # A device that is registered and approved but not yet confirmed --
        # or quarantined -- must not have its evidence signed at emission,
        # even on the non-atomic append path that never reaches the
        # attestor's own epoch check. The evidence stays a visible gap for
        # reconciliation to resolve through the coordinator.
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            # Default artifact: no atomic freshness, so signing would take the
            # generic append path with no epoch check of its own.
            assert attestor.atomic_freshness_available is False
            await store.upsert_firmware_device_anchor(
                device_id="ori-fw-7c9f2b3a",
                public_key_b64=base64.b64encode(bytes([0x11] * 32)).decode(),
                posture="sealed_flash",
                capability_hash="sha256:" + "ab" * 32,
                manifest_json="{}",
                channel_map_json="{}",
                board_profile="esp32-s3-pzem-v1",
                provisioned_at_ms=1,
            )
            await store.approve_firmware_device(
                "ori-fw-7c9f2b3a", actor="op", reason="commissioning"
            )
            dispatcher = self._dispatcher(store, attestor)

            def _reading():
                return SensorReading(
                    sensor_id="ori-fw-7c9f2b3a:ch0",
                    sensor_type="current",
                    value=21.0,
                    unit="ampere",
                    timestamp=1,
                    quality=1.0,
                    metadata={
                        "source": "firmware",
                        "attestation": "attested",
                        "posture": "sealed_flash",
                        "firmware_device_id": "ori-fw-7c9f2b3a",
                        "boot_id": 7,
                        "seq": 42,
                    },
                )

            # confirmation_pending: withheld.
            context = SimpleNamespace(
                state_store=store,
                event=OriEvent.from_reading(_reading(), "runtime-01"),
            )
            await dispatcher._log_action(_result("D", approved=None), context)

            # quarantined: also withheld.
            dev = await store.get_firmware_device("ori-fw-7c9f2b3a")
            await store.resolve_firmware_confirmation(
                "ori-fw-7c9f2b3a",
                dev["anchor_epoch_id"],
                status="quarantined",
                at_ms=1,
            )
            context = SimpleNamespace(
                state_store=store,
                event=OriEvent.from_reading(_reading(), "runtime-01"),
            )
            await dispatcher._log_action(_result("D", approved=None), context)

            summary = await store.get_attestation_summary()
            assert summary["status_counts"].get("signed", 0) == 0
            assert attestor._chain.appended == []
            assert attestor._chain.atomic_appended == []
        finally:
            attestor.close()
            await store.close()

    async def test_confirmation_lookup_failure_leaves_evidence_pending(
        self, monkeypatch, tmp_path
    ):
        # A transient failure reading the confirmation status must never
        # escape the evidence path or disturb action processing. It fails
        # closed: the row is left pending (not signed, not failed) for
        # reconciliation, and nothing is written to the chain.
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            await store.upsert_firmware_device_anchor(
                device_id="ori-fw-7c9f2b3a",
                public_key_b64=base64.b64encode(bytes([0x11] * 32)).decode(),
                posture="sealed_flash",
                capability_hash="sha256:" + "ab" * 32,
                manifest_json="{}",
                channel_map_json="{}",
                board_profile="esp32-s3-pzem-v1",
                provisioned_at_ms=1,
            )
            await store.approve_firmware_device(
                "ori-fw-7c9f2b3a", actor="op", reason="commissioning"
            )

            async def _boom(*args, **kwargs):
                raise RuntimeError("state store unavailable")

            monkeypatch.setattr(store, "get_firmware_confirmation_status", _boom)

            dispatcher = self._dispatcher(store, attestor)
            reading = SensorReading(
                sensor_id="ori-fw-7c9f2b3a:ch0",
                sensor_type="current",
                value=21.0,
                unit="ampere",
                timestamp=1,
                quality=1.0,
                metadata={
                    "source": "firmware",
                    "attestation": "attested",
                    "posture": "sealed_flash",
                    "firmware_device_id": "ori-fw-7c9f2b3a",
                    "boot_id": 7,
                    "seq": 42,
                },
            )
            event = OriEvent.from_reading(reading, "runtime-01")
            context = SimpleNamespace(state_store=store, event=event)
            # Does not raise despite the failing lookup.
            await dispatcher._log_action(_result("D", approved=None), context)

            # The action itself was logged; its evidence is a visible gap,
            # neither signed nor marked failed.
            assert (await store.get_action_log(limit=1))[0][
                "input_firmware_device_id"
            ] == "ori-fw-7c9f2b3a"
            summary = await store.get_attestation_summary()
            assert summary["status_counts"].get("signed", 0) == 0
            assert summary["status_counts"].get("failed", 0) == 0
            assert attestor._chain.appended == []
            assert attestor._chain.atomic_appended == []
        finally:
            attestor.close()
            await store.close()

    async def test_tier_a_action_is_not_signed(self, monkeypatch, tmp_path):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            dispatcher = self._dispatcher(store, attestor)
            context = SimpleNamespace(state_store=store, event=None)
            await dispatcher._log_action(_result("A", approved=None), context)

            summary = await store.get_attestation_summary()
            assert summary["status_counts"] == {}
            assert attestor._chain.appended == []
        finally:
            attestor.close()
            await store.close()

    async def test_signing_failure_marks_gap_but_never_breaks_action(
        self, monkeypatch, tmp_path
    ):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        attestor._chain.fail_append = True
        try:
            dispatcher = self._dispatcher(store, attestor)
            context = SimpleNamespace(state_store=store, event=None)
            await dispatcher._log_action(_result("D", approved=None), context)

            summary = await store.get_attestation_summary()
            assert summary["status_counts"] == {"failed": 1}
            assert summary["attestation_gap_count"] == 1
        finally:
            attestor.close()
            await store.close()


# ─── Startup reconciliation ───────────────────────────────────────────────────


@pytest.mark.asyncio
class TestReconciliation:
    async def test_reconciles_pending_rows_and_leaves_failures_visible(
        self, monkeypatch, tmp_path
    ):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            stuck_id = await store.log_action(
                _result("C"), "critical_fault", attestation_pending=True
            )
            runtime = OriRuntime(config_path="ori.yaml")
            runtime._state_store = store
            runtime._evidence_attestor = attestor

            await runtime._reconcile_pending_attestations()

            summary = await store.get_attestation_summary()
            assert summary["status_counts"] == {"reconciled": 1}
            assert summary["last_attested_action_id"] == stuck_id
        finally:
            attestor.close()
            await store.close()

    async def test_unrepairable_rows_stay_failed(self, monkeypatch, tmp_path):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        attestor._chain.fail_append = True
        try:
            await store.log_action(
                _result("D", approved=None),
                "dangerous_overcurrent",
                attestation_pending=True,
            )
            runtime = OriRuntime(config_path="ori.yaml")
            runtime._state_store = store
            runtime._evidence_attestor = attestor

            await runtime._reconcile_pending_attestations()

            summary = await store.get_attestation_summary()
            assert summary["status_counts"] == {"failed": 1}
            assert summary["attestation_gap_count"] == 1
        finally:
            attestor.close()
            await store.close()

    _GATE_KEY = base64.b64encode(bytes([0x11] * 32)).decode()
    _GATE_CAP = "sha256:" + "ab" * 32
    _GATE_DEVICE = "fw-gate-node"

    async def _firmware_source_row(self, store, *, approve: bool) -> None:
        """A pending Tier D action sourced from a firmware node, with the
        device registered (and optionally approved) in the runtime store."""
        import json as _json

        await store.upsert_firmware_device_anchor(
            device_id=self._GATE_DEVICE,
            public_key_b64=self._GATE_KEY,
            posture="sealed_flash",
            capability_hash=self._GATE_CAP,
            manifest_json="{}",
            channel_map_json="{}",
            board_profile="esp32-s3-pzem-v1",
            provisioned_at_ms=1,
        )
        if approve:
            await store.approve_firmware_device(
                self._GATE_DEVICE, actor="uid=7:carol", reason="commissioning"
            )
        snapshot = {
            "device_id": self._GATE_DEVICE,
            "public_key_b64": self._GATE_KEY,
            # Empty alg matches what the store holds and the coordinator
            # pushes, so the attestor's registry comparison agrees.
            "alg": "",
            "posture": "sealed_flash",
            "capability_hash": self._GATE_CAP,
            "board_profile": "esp32-s3-pzem-v1",
            "provisioned_at_ms": 1,
            "approved": True,
            "revoked": False,
            "approval_actor": "uid=7:carol",
            "approval_reason": "commissioning",
        }
        await store.log_action_for_event(
            _result("D", approved=None),
            trigger_name="dangerous_overcurrent",
            input_firmware_device_id=self._GATE_DEVICE,
            input_firmware_registration=_json.dumps(snapshot, sort_keys=True),
            attestation_pending=True,
        )

    async def test_firmware_evidence_is_signed_once_cross_store_confirmed(
        self, monkeypatch, tmp_path
    ):
        # The coordinator reconciles the two stores at the earliest
        # opportunity (this reconciliation pass): it pushes the anchor,
        # reads the identical active epoch back, and resolves the obligation
        # to confirmed. Only then is the firmware evidence signed.
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            await self._firmware_source_row(store, approve=True)
            runtime = OriRuntime(config_path="ori.yaml")
            runtime._state_store = store
            runtime._evidence_attestor = attestor
            runtime._firmware_confirmation_coordinator = (
                FirmwareConfirmationCoordinator(
                    store=store, chain=attestor.confirmation_chain()
                )
            )

            await runtime._reconcile_pending_attestations()

            summary = await store.get_attestation_summary()
            assert summary["status_counts"] == {"reconciled": 1}
            dev = await store.get_firmware_device(self._GATE_DEVICE)
            assert (
                await store.get_firmware_confirmation_status(
                    self._GATE_DEVICE, dev["anchor_epoch_id"]
                )
                == "confirmed"
            )
        finally:
            attestor.close()
            await store.close()

    async def test_firmware_evidence_withheld_until_cross_store_confirmed(
        self, monkeypatch, tmp_path
    ):
        # The device is not approved in the runtime store, so its epoch is
        # not cross-store confirmed. The action's registration snapshot
        # claims approval, but the STORED confirmation status -- not that
        # local snapshot -- is the authority. The evidence stays pending, a
        # visible gap, and nothing is written to the chain.
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            await self._firmware_source_row(store, approve=False)
            runtime = OriRuntime(config_path="ori.yaml")
            runtime._state_store = store
            runtime._evidence_attestor = attestor
            runtime._firmware_confirmation_coordinator = (
                FirmwareConfirmationCoordinator(
                    store=store, chain=attestor.confirmation_chain()
                )
            )

            await runtime._reconcile_pending_attestations()

            summary = await store.get_attestation_summary()
            assert summary["status_counts"].get("reconciled", 0) == 0
            assert attestor._chain.appended == []
            assert attestor._chain.atomic_appended == []
        finally:
            attestor.close()
            await store.close()

    async def test_startup_drain_confirms_a_plain_approval(self, monkeypatch, tmp_path):
        # A device approved with no firmware action waiting must still be
        # confirmed at startup, or it can never publish its approval or
        # receive commands. The drain runs the coordinator over every
        # outstanding obligation: push, readback, resolve.
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            await store.upsert_firmware_device_anchor(
                device_id="fw-drain",
                public_key_b64=self._GATE_KEY,
                posture="sealed_flash",
                capability_hash=self._GATE_CAP,
                manifest_json="{}",
                channel_map_json="{}",
                board_profile="esp32-s3-pzem-v1",
                provisioned_at_ms=1,
            )
            await store.approve_firmware_device(
                "fw-drain", actor="op", reason="commissioning"
            )
            dev = await store.get_firmware_device("fw-drain")
            active_epoch = dev["anchor_epoch_id"]
            # Approval alone leaves the grant unconfirmed: no command or
            # approval publish may proceed yet.
            assert (
                await store.get_firmware_confirmation_status("fw-drain", active_epoch)
                == "confirmation_pending"
            )

            runtime = OriRuntime(config_path="ori.yaml")
            runtime._state_store = store
            runtime._evidence_attestor = attestor
            runtime._firmware_confirmation_coordinator = (
                FirmwareConfirmationCoordinator(
                    store=store, chain=attestor.confirmation_chain()
                )
            )

            await runtime._drain_pending_firmware_confirmations()

            # Confirmed through a real push + readback; the evidence store now
            # holds the anchor, and the command/approval gates (which key off
            # this status) will permit the device.
            assert (
                await store.get_firmware_confirmation_status("fw-drain", active_epoch)
                == "confirmed"
            )
            assert "fw-drain" in attestor._chain.layer1_devices
            assert await store.list_pending_firmware_confirmations() == []
        finally:
            attestor.close()
            await store.close()


# ─── Health + heartbeat surfaces ──────────────────────────────────────────────

pyaho = pytest.importorskip("paho.mqtt.client", reason="paho-mqtt required")


@pytest.mark.asyncio
class TestEvidenceVisibility:
    async def test_evidence_health_disabled_by_default(self):
        runtime = OriRuntime(config_path="ori.yaml")
        health = await runtime._evidence_health()
        assert health["enabled"] is False
        assert health["available"] is False
        assert health["protocol_version"] == ""
        assert health["attestation_gap_count"] == 0
        assert health["action_event_type"] == ""

    async def test_evidence_health_reports_chain_state(self, monkeypatch, tmp_path):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            row_id = await store.log_action(
                _result("C"), "critical_fault", attestation_pending=True
            )
            seq = await attestor.attest_action({"id": row_id, "timestamp": 1})
            await store.set_action_attestation(
                row_id, status="signed", attestation_seq=seq
            )

            runtime = OriRuntime(config_path="ori.yaml")
            runtime._state_store = store
            runtime._evidence_attestor = attestor
            runtime._config = SimpleNamespace(evidence=SimpleNamespace(enabled=True))

            health = await runtime._evidence_health()
            assert health["enabled"] is True
            assert health["available"] is True
            assert health["public_key_hex"] == "ab" * 32
            assert health["protocol_version"] == "evidence.v1"
            assert health["chain_head_hash"] == "head-1"
            assert health["last_attested_action_id"] == row_id
            assert health["attestation_gap_count"] == 0
            # 0.1.0 fake artifact: legacy vocabulary, visible pre-action.
            assert health["action_event_type"] == "MAINTENANCE_PERFORMED"
        finally:
            attestor.close()
            await store.close()

    async def test_evidence_health_does_not_expose_artifact_protocol(
        self, monkeypatch, tmp_path
    ):
        _install_fake_artifact(monkeypatch, protocol_version="private-artifact.v1")
        monkeypatch.setenv(
            "ORI_EVIDENCE_ARTIFACT_PROTOCOL_VERSION", "private-artifact.v1"
        )
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "evidence.key"),
            device_secret="install-secret",
            device_id="dev-01",
        )
        assert await attestor.start() is True
        try:
            runtime = OriRuntime(config_path="ori.yaml")
            runtime._evidence_attestor = attestor
            runtime._config = SimpleNamespace(evidence=SimpleNamespace(enabled=True))

            health = await runtime._evidence_health()

            assert attestor.protocol_version == "private-artifact.v1"
            assert health["protocol_version"] == "evidence.v1"
        finally:
            attestor.close()

    async def test_node_heartbeat_carries_chain_head(self):
        class _FakeClient:
            def __init__(self):
                self.published = []

            def publish(self, topic, payload, qos=0, retain=False):
                self.published.append((topic, payload, qos, retain))

        snapshot = {
            "status": "healthy",
            "active_triggers": [],
            "evidence": {
                "enabled": True,
                "available": True,
                "chain_head_hash": "head-9",
                "attestation_gap_count": 2,
                "action_event_type": "SAFETY_ACTION_EXECUTED",
            },
        }

        async def _snapshot():
            return snapshot

        publisher = MqttRuntimeNodeHeartbeatPublisher(
            broker_url="mqtt://localhost",
            device_id="dev-01",
            health_snapshot_provider=_snapshot,
            interval_seconds=30,
            client_factory=lambda **_: _FakeClient(),
        )
        payload = await publisher._payload()
        assert payload["evidence"] == {
            "chain_head_hash": "head-9",
            "attestation_gap_count": 2,
            "available": True,
            "action_event_type": "SAFETY_ACTION_EXECUTED",
        }

    async def test_heartbeat_omits_evidence_when_disabled(self):
        async def _snapshot():
            return {"status": "healthy", "evidence": {"enabled": False}}

        publisher = MqttRuntimeNodeHeartbeatPublisher(
            broker_url="mqtt://localhost",
            device_id="dev-01",
            health_snapshot_provider=_snapshot,
            interval_seconds=30,
            client_factory=lambda **_: object(),
        )
        payload = await publisher._payload()
        assert "evidence" not in payload


# ─── Runtime builder ──────────────────────────────────────────────────────────


class TestBuildEvidenceAttestor:
    def test_disabled_returns_none(self):
        config = SimpleNamespace(
            evidence=EvidenceConfig(), device=SimpleNamespace(id="dev-01")
        )
        assert _build_evidence_attestor(config) is None

    def test_enabled_without_secret_fails_loudly(self, monkeypatch):
        monkeypatch.delenv("ORI_EVIDENCE_DEVICE_SECRET", raising=False)
        config = SimpleNamespace(
            evidence=EvidenceConfig(enabled=True),
            device=SimpleNamespace(id="dev-01"),
        )
        with pytest.raises(ValueError, match="install secret"):
            _build_evidence_attestor(config)

    def test_enabled_with_secret_builds(self, monkeypatch):
        monkeypatch.setenv("ORI_EVIDENCE_DEVICE_SECRET", "random-install-secret")
        config = SimpleNamespace(
            evidence=EvidenceConfig(enabled=True),
            device=SimpleNamespace(id="dev-01"),
        )
        attestor = _build_evidence_attestor(config)
        assert isinstance(attestor, EvidenceAttestor)
        assert attestor.available is False  # not started yet
        attestor.close()


def test_tier_requires_attestation_matrix():
    assert tier_requires_attestation("C") is True
    assert tier_requires_attestation("D") is True
    assert tier_requires_attestation("c") is True
    assert tier_requires_attestation("A") is False
    assert tier_requires_attestation("B") is False
    assert tier_requires_attestation("") is False


# ─── Review-finding regressions ───────────────────────────────────────────────


@pytest.mark.asyncio
class TestEvidenceTrustProperties:
    async def test_attestation_is_idempotent_across_lost_status_updates(
        self, monkeypatch, tmp_path
    ):
        """Chain append succeeded but the status update was lost: retrying
        the same action_log row must return the existing seq, not append a
        second event for the same business fact."""
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            row = {"id": 11, "tier": "C", "timestamp": 1_760_000_000_000}
            first = await attestor.attest_action(row)
            second = await attestor.attest_action(dict(row), reconciled=True)
            assert first == second
            assert len(attestor._chain.appended) == 1
        finally:
            attestor.close()

    async def test_reconciled_evidence_is_explicitly_marked_late(
        self, monkeypatch, tmp_path
    ):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            await attestor.attest_action(
                {"id": 12, "tier": "D", "timestamp": 5}, reconciled=True
            )
            payload_json = attestor._chain.appended[0][3]
            assert '"attestation": "reconciled_late"' in payload_json
        finally:
            attestor.close()

    async def test_reconciliation_signs_late_marked_evidence(
        self, monkeypatch, tmp_path
    ):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        attestor = await _started_attestor(monkeypatch, tmp_path)
        try:
            await store.log_action(
                _result("C"), "critical_fault", attestation_pending=True
            )
            runtime = OriRuntime(config_path="ori.yaml")
            runtime._state_store = store
            runtime._evidence_attestor = attestor

            await runtime._reconcile_pending_attestations()

            payload_json = attestor._chain.appended[0][3]
            assert '"attestation": "reconciled_late"' in payload_json
        finally:
            attestor.close()
            await store.close()

    async def test_protocol_mismatch_keeps_evidence_unavailable(
        self, monkeypatch, tmp_path
    ):
        _install_fake_artifact(monkeypatch, protocol_version="evidence.v999")
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "evidence.db"),
            key_path=str(tmp_path / "evidence.key"),
            device_secret="install-secret",
            device_id="dev-01",
        )
        assert await attestor.start() is False
        assert attestor.available is False
        assert attestor.protocol_version == "evidence.v999"
        attestor.close()

    async def test_artifact_identity_reported_when_available(
        self, monkeypatch, tmp_path
    ):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        assert attestor.protocol_version == "evidence.v1"
        assert attestor.artifact_version == "0.1.0"
        attestor.close()

    async def test_action_log_reads_and_exports_carry_attestation_linkage(
        self, tmp_path
    ):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        try:
            row_id = await store.log_action_for_event(
                _result("C"),
                trigger_name="critical_fault",
                device_id="dev-01",
                input_attestation_grade="attested_dev",
                input_posture="development",
                attestation_pending=True,
            )
            await store.set_action_attestation(
                row_id, status="signed", attestation_seq=9
            )

            read = (await store.get_action_log(limit=1))[0]
            assert read["attestation_status"] == "signed"
            assert read["attestation_seq"] == 9
            assert read["input_attestation_grade"] == "attested_dev"
            assert read["input_posture"] == "development"

            exported = (await store.export_action_log(device_id="dev-01"))[0]
            assert exported["attestation_status"] == "signed"
            assert exported["attestation_seq"] == 9
            assert exported["input_attestation_grade"] == "attested_dev"
            assert exported["input_posture"] == "development"
        finally:
            await store.close()


class TestLayer1RegistrationVerification:
    """The attestor only VERIFIES that the evidence chain already holds the
    confirmed source anchor. Promotion into the chain belongs solely to the
    runtime confirmation coordinator, so a device the coordinator has not
    confirmed cannot acquire authority through the signing path."""

    def _registration(self, **overrides) -> dict:
        reg = {
            "device_id": "fw-node-01",
            "public_key_b64": "ERERERERERERERERERERERERERERERERERERERERERE=",
            "alg": "ed25519",
            "posture": "sealed_flash",
            "capability_hash": "sha256:" + "ab" * 32,
            "board_profile": "esp32-s3-pzem-v1",
            "provisioned_at_ms": 1_751_500_900_000,
            "approved": True,
            "revoked": False,
            "approval_actor": "uid=42:alice",
            "approval_reason": "bench bring-up",
        }
        reg.update(overrides)
        return reg

    async def _attestor(self, monkeypatch, tmp_path):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        attestor._chain = _FakeEvidenceChain(
            str(tmp_path / "chain.db"), str(tmp_path / "chain.key"), "secret"
        )
        return attestor

    def _prime_chain(self, attestor, reg: dict) -> None:
        """Simulate the coordinator having already pushed the anchor."""
        attestor._chain.register_layer1_device(
            reg["device_id"],
            "11" * 32,
            reg["alg"],
            reg["posture"],
            reg["capability_hash"],
            reg["board_profile"],
            reg["provisioned_at_ms"],
            True,
            reg["approval_actor"],
            reg["approval_reason"],
        )

    async def test_confirmed_anchor_is_accepted(self, monkeypatch, tmp_path):
        attestor = await self._attestor(monkeypatch, tmp_path)
        try:
            reg = self._registration()
            self._prime_chain(attestor, reg)
            # Does not raise: the chain already holds the same, approved anchor.
            await attestor._sync_layer1_device_registration(
                {
                    "input_firmware_device_id": "fw-node-01",
                    "input_firmware_registration": reg,
                }
            )
        finally:
            attestor.close()

    async def test_unregistered_device_is_refused(self, monkeypatch, tmp_path):
        # The coordinator has not confirmed this anchor, so the chain holds
        # nothing for it. The attestor must NOT register it itself.
        attestor = await self._attestor(monkeypatch, tmp_path)
        try:
            with pytest.raises(ValueError, match="not registered in the evidence"):
                await attestor._sync_layer1_device_registration(
                    {
                        "input_firmware_device_id": "fw-node-01",
                        "input_firmware_registration": self._registration(),
                    }
                )
            # Nothing was written to the chain.
            assert "fw-node-01" not in attestor._chain.layer1_devices
        finally:
            attestor.close()

    async def test_registry_field_mismatch_is_refused(self, monkeypatch, tmp_path):
        attestor = await self._attestor(monkeypatch, tmp_path)
        try:
            reg = self._registration()
            self._prime_chain(attestor, reg)
            # The action now presents a DIFFERENT capability hash than the
            # chain holds: a registry disagreement the gate must catch.
            with pytest.raises(ValueError, match="Layer 1 registry mismatch"):
                await attestor._sync_layer1_device_registration(
                    {
                        "input_firmware_device_id": "fw-node-01",
                        "input_firmware_registration": self._registration(
                            capability_hash="sha256:" + "cd" * 32
                        ),
                    }
                )
        finally:
            attestor.close()


class TestReconciliationProvenanceRecovery:
    """A failed attestation of firmware-sourced evidence must stay
    recoverable: the registration snapshot and its approval provenance
    are persisted with the action row, not held only in memory."""

    async def test_persisted_snapshot_survives_reload(self, tmp_path):
        import json as _json

        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        try:
            snapshot = {
                "device_id": "fw-node-01",
                "public_key_b64": "ERERERERERERERERERERERERERERERERERERERERERE=",
                "alg": "ed25519",
                "posture": "sealed_flash",
                "capability_hash": "sha256:" + "ab" * 32,
                "board_profile": "esp32-s3-pzem-v1",
                "provisioned_at_ms": 1,
                "approved": True,
                "revoked": False,
                "approval_actor": "uid=7:carol",
                "approval_reason": "field commissioning",
            }
            # Logged atomically with the snapshot -- the same insert the
            # dispatcher uses, not a follow-up mutation.
            action_id = await store.log_action_for_event(
                _result("D"),
                trigger_name="dangerous_overcurrent",
                input_firmware_device_id="fw-node-01",
                input_firmware_registration=_json.dumps(snapshot, sort_keys=True),
                attestation_pending=True,
            )

            # Reconciliation reloads from the database, not memory.
            reloaded = await store.get_actions_needing_attestation()
            row = next(r for r in reloaded if r["id"] == action_id)
            reg = row["input_firmware_registration"]
            assert reg is not None, "snapshot must survive the reload"
            assert reg["approval_actor"] == "uid=7:carol"
            assert reg["approval_reason"] == "field commissioning"
        finally:
            await store.close()

    async def test_actions_without_firmware_reload_with_no_snapshot(self, tmp_path):
        store = StateStore(db_path=str(tmp_path / "state.db"))
        await store.open()
        try:
            action_id = await store.log_action(
                _result("C"), "trigger", attestation_pending=True
            )
            reloaded = await store.get_actions_needing_attestation()
            row = next(r for r in reloaded if r["id"] == action_id)
            assert row["input_firmware_registration"] is None
        finally:
            await store.close()


class TestEvidenceAcceptanceGate:
    """Firmware evidence is accepted only when the evidence chain holds the
    same anchor_epoch_id the runtime approved (ori-runtime#250)."""

    def _registration(self) -> dict:
        return {
            "device_id": "fw-gate-01",
            "public_key_b64": base64.b64encode(bytes([0x11] * 32)).decode(),
            "alg": "ed25519",
            "posture": "sealed_flash",
            "capability_hash": "sha256:" + "ab" * 32,
            "board_profile": "esp32-s3-pzem-v1",
            "provisioned_at_ms": 1,
            "approved": True,
            "revoked": False,
            "approval_actor": "uid=7:carol",
            "approval_reason": "commissioning",
        }

    async def _attestor(self, monkeypatch, tmp_path):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        attestor._chain = _FakeEvidenceChain(
            str(tmp_path / "c.db"), str(tmp_path / "c.key"), "s"
        )
        return attestor

    def _prime_chain(self, attestor, reg: dict) -> None:
        """Simulate the coordinator having already confirmed the anchor."""
        attestor._chain.register_layer1_device(
            reg["device_id"],
            bytes([0x11] * 32).hex(),
            reg["alg"],
            reg["posture"],
            reg["capability_hash"],
            reg["board_profile"],
            reg["provisioned_at_ms"],
            True,
            reg["approval_actor"],
            reg["approval_reason"],
        )

    async def test_matching_epoch_is_accepted(self, monkeypatch, tmp_path):
        attestor = await self._attestor(monkeypatch, tmp_path)
        try:
            reg = self._registration()
            self._prime_chain(attestor, reg)
            await attestor._sync_layer1_device_registration(
                {
                    "input_firmware_device_id": "fw-gate-01",
                    "input_firmware_registration": reg,
                }
            )  # does not raise: the chain holds the same active epoch
        finally:
            attestor.close()

    async def test_disagreed_epoch_is_refused(self, monkeypatch, tmp_path):
        attestor = await self._attestor(monkeypatch, tmp_path)
        try:
            reg = self._registration()
            self._prime_chain(attestor, reg)
            # The registry fields still match, but the evidence store's ACTIVE
            # anchor is a different epoch (e.g. it holds a superseded or other
            # anchor as active). The epoch gate must catch this even though
            # the registry-field comparison passes.
            attestor._chain.active_anchor_epoch_id = (  # type: ignore[method-assign]
                lambda device_id: "sha256:" + "ff" * 32
            )
            with pytest.raises(ValueError, match="not cross-store confirmed"):
                await attestor._sync_layer1_device_registration(
                    {
                        "input_firmware_device_id": "fw-gate-01",
                        "input_firmware_registration": reg,
                    }
                )
        finally:
            attestor.close()
