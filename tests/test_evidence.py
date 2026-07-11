# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tier C/D evidence signing: attestor, dispatcher wiring, reconciliation.

The Verity chain artifact (``ori_verity``) is a pinned prebuilt dependency
that is not installed in runtime CI, so these tests inject a fake module.
What they pin down is the runtime's side of the contract: Option B
append-after-log attestation statuses, gap visibility, reconciliation, and
graceful degradation when the artifact or chain is unavailable.
"""

import sys
import threading
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from ori.config import Config, ConfigValidationError, EvidenceConfig, _parse_evidence
from ori.gateway.node_heartbeat import MqttRuntimeNodeHeartbeatPublisher
from ori.network.events import ActionResult
from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.runtime import OriRuntime, _build_evidence_attestor
from ori.security.evidence import EvidenceAttestor, tier_requires_attestation
from ori.state.store import StateStore

# ─── Fake ori_verity artifact ─────────────────────────────────────────────────


class _FakeVerityChain:
    def __init__(self, db_path: str, key_path: str, device_secret: str) -> None:
        self.db_path = db_path
        self.appended: list[tuple] = []
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
            raise ValueError("UNIQUE constraint failed: verity_chain.event_id")
        self._seq += 1
        if event_id:
            self._seq_by_event_id[event_id] = self._seq
        self.appended.append(
            (event_type, device_id, emitted_at_ms, payload_json, event_id)
        )
        return self._seq

    def seq_for_event_id(self, event_id: str) -> int | None:
        return self._seq_by_event_id.get(event_id)

    def chain_head_hash(self) -> str | None:
        return f"head-{self._seq}" if self._seq else None

    def pending_count(self) -> int:
        return self._seq


def _install_fake_verity(
    monkeypatch,
    *,
    protocol_version: str = "verity.v1",
    artifact_version: str = "0.1.0",
) -> type[_FakeVerityChain]:
    module = types.ModuleType("ori_verity")
    module.VerityChain = _FakeVerityChain
    module.PROTOCOL_VERSION = protocol_version
    module.ARTIFACT_VERSION = artifact_version
    monkeypatch.setitem(sys.modules, "ori_verity", module)
    return _FakeVerityChain


async def _started_attestor(
    monkeypatch, tmp_path, *, artifact_version: str = "0.1.0"
) -> EvidenceAttestor:
    _install_fake_verity(monkeypatch, artifact_version=artifact_version)
    attestor = EvidenceAttestor(
        db_path=str(tmp_path / "verity.db"),
        key_path=str(tmp_path / "verity.key"),
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
                "db_path": "/var/lib/ori/verity.db",
                "key_path": "/etc/ori/verity.key",
                "device_secret_env": "ORI_EVIDENCE_DEVICE_SECRET",
            }
        )
        assert cfg.enabled is True
        assert cfg.db_path == "/var/lib/ori/verity.db"

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
        monkeypatch.setitem(sys.modules, "ori_verity", None)  # import -> error
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "verity.db"),
            key_path=str(tmp_path / "verity.key"),
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
            db_path=str(tmp_path / "verity.db"),
            key_path=str(tmp_path / "verity.key"),
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
        class _TrackingChain(_FakeVerityChain):
            deleted_on: list[str] = []

            def __del__(self) -> None:
                _TrackingChain.deleted_on.append(threading.current_thread().name)

        return _TrackingChain

    async def test_close_drops_chain_on_evidence_thread(self, monkeypatch, tmp_path):
        cls = self._tracking_chain_cls()
        _install_fake_verity(monkeypatch)
        sys.modules["ori_verity"].VerityChain = cls
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "verity.db"),
            key_path=str(tmp_path / "verity.key"),
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
        _install_fake_verity(monkeypatch, protocol_version="verity.v0")
        sys.modules["ori_verity"].VerityChain = cls
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "verity.db"),
            key_path=str(tmp_path / "verity.key"),
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


# ─── Health + heartbeat surfaces ──────────────────────────────────────────────

pyaho = pytest.importorskip("paho.mqtt.client", reason="paho-mqtt required")


@pytest.mark.asyncio
class TestEvidenceVisibility:
    async def test_evidence_health_disabled_by_default(self):
        runtime = OriRuntime(config_path="ori.yaml")
        health = await runtime._evidence_health()
        assert health["enabled"] is False
        assert health["available"] is False
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
            assert health["chain_head_hash"] == "head-1"
            assert health["last_attested_action_id"] == row_id
            assert health["attestation_gap_count"] == 0
            # 0.1.0 fake artifact: legacy vocabulary, visible pre-action.
            assert health["action_event_type"] == "MAINTENANCE_PERFORMED"
        finally:
            attestor.close()
            await store.close()

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
        _install_fake_verity(monkeypatch, protocol_version="verity.v999")
        attestor = EvidenceAttestor(
            db_path=str(tmp_path / "verity.db"),
            key_path=str(tmp_path / "verity.key"),
            device_secret="install-secret",
            device_id="dev-01",
        )
        assert await attestor.start() is False
        assert attestor.available is False
        assert attestor.protocol_version == "verity.v999"
        attestor.close()

    async def test_artifact_identity_reported_when_available(
        self, monkeypatch, tmp_path
    ):
        attestor = await _started_attestor(monkeypatch, tmp_path)
        assert attestor.protocol_version == "verity.v1"
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
                attestation_pending=True,
            )
            await store.set_action_attestation(
                row_id, status="signed", attestation_seq=9
            )

            read = (await store.get_action_log(limit=1))[0]
            assert read["attestation_status"] == "signed"
            assert read["attestation_seq"] == 9

            exported = (await store.export_action_log(device_id="dev-01"))[0]
            assert exported["attestation_status"] == "signed"
            assert exported["attestation_seq"] == 9
        finally:
            await store.close()
