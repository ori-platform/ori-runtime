# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Startup reconciliation, the firmware confirmation gate, and evidence health.

These drive the real runtime methods against a minimal object carrying only the
attributes each reads. Constructing a whole `OriRuntime` would pull in a dozen
subsystems whose behaviour these tests do not control, which makes a failure
harder to read rather than easier.
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import AsyncMock

import pytest

from ori.runtime import OriRuntime
from ori.security.firmware_confirmation import CONFIRMED


class _Attestor:
    """Records what reconciliation asked it to sign, and how."""

    available = True
    public_key_hex = "ab" * 32
    protocol_version = "ori.evidence.v2"
    action_event_type = "SAFETY_ACTION_EXECUTED"
    atomic_freshness_available = False

    def __init__(self, *, seq: int | None = 1) -> None:
        self.calls: list[tuple[int, bool]] = []
        self._seq = seq
        self.head = "cd" * 32
        self.pending = 2

    async def attest_action(self, row, *, reconciled: bool = False):
        self.calls.append((int(row["id"]), reconciled))
        return self._seq

    async def chain_head_hash(self):
        return self.head

    async def pending_export_count(self):
        return self.pending


class _Runtime:
    """The attributes the reconciliation and health paths actually read."""

    def __init__(self, *, attestor=None, store=None, coordinator=None, enabled=True):
        self._evidence_attestor = attestor
        self._state_store = store
        self._firmware_confirmation_coordinator = coordinator
        self._config = type(
            "_Cfg", (), {"evidence": type("_Ev", (), {"enabled": enabled})()}
        )()

    async def _firmware_source_confirmed(self, row) -> bool:
        """The real gate, not a stub.

        Reconciliation consults this, so substituting a stub here would let the
        reconciliation tests pass while the gate itself was broken -- and the
        gate is the thing standing between an unconfirmed anchor and a signature.
        """
        return await OriRuntime._firmware_source_confirmed(cast(OriRuntime, self), row)


def _store(rows: list[dict]):
    s = AsyncMock()
    s.get_actions_needing_attestation = AsyncMock(return_value=rows)
    s.set_action_attestation = AsyncMock(return_value=None)
    s.get_attestation_summary = AsyncMock(
        return_value={
            "last_attested_action_id": 9,
            "attestation_gap_count": 1,
            "status_counts": {"signed": 3, "failed": 1},
        }
    )
    return s


def _row(action_id: int, **kw) -> dict:
    row = {"id": action_id, "tier": "D", "action_name": "emergency_cutoff"}
    row.update(kw)
    return row


async def _reconcile(runtime: _Runtime) -> None:
    """Drive the real method against the stub carrying what it reads.

    The cast records that the stub is deliberately narrow: a full `OriRuntime`
    would pull in subsystems whose behaviour these tests neither control nor
    care about.
    """
    await OriRuntime._reconcile_pending_attestations(cast(OriRuntime, runtime))


class TestStartupReconciliation:
    async def test_pending_rows_are_re_signed_and_marked_reconciled(self) -> None:
        attestor = _Attestor(seq=5)
        store = _store([_row(1), _row(2)])
        await _reconcile(_Runtime(attestor=attestor, store=store))

        assert [c[0] for c in attestor.calls] == [1, 2]
        statuses = [
            c.kwargs["status"] for c in store.set_action_attestation.await_args_list
        ]
        assert statuses == ["reconciled", "reconciled"]

    async def test_reconciled_signing_is_marked_late(self) -> None:
        """A verifier must never mistake repair for emission-time signing."""
        attestor = _Attestor()
        await _reconcile(_Runtime(attestor=attestor, store=_store([_row(1)])))
        assert attestor.calls == [(1, True)], (
            "reconciliation did not mark evidence late"
        )

    async def test_a_row_that_still_cannot_be_signed_stays_failed(self) -> None:
        """Never fabricated: an unrepairable gap remains a visible gap."""
        attestor = _Attestor(seq=None)
        store = _store([_row(1)])
        await _reconcile(_Runtime(attestor=attestor, store=store))
        call = store.set_action_attestation.await_args_list[0]
        assert call.kwargs["status"] == "failed"
        assert call.kwargs["attestation_seq"] is None

    async def test_a_failing_scan_does_not_raise(self) -> None:
        """Startup must not be blocked by a store that cannot be read."""
        store = _store([])
        store.get_actions_needing_attestation = AsyncMock(
            side_effect=RuntimeError("db")
        )
        await _reconcile(_Runtime(attestor=_Attestor(), store=store))

    async def test_nothing_happens_without_an_attestor(self) -> None:
        store = _store([_row(1)])
        await _reconcile(_Runtime(attestor=None, store=store))
        store.set_action_attestation.assert_not_awaited()


class TestFirmwareConfirmationGate:
    """Firmware-sourced evidence is signed only under a confirmed epoch."""

    @staticmethod
    async def _confirmed(runtime, row) -> bool:
        return await OriRuntime._firmware_source_confirmed(runtime, row)

    async def test_a_row_with_no_firmware_source_is_not_gated(self) -> None:
        """There is no cross-store anchor to confirm, so nothing to wait for."""
        assert await self._confirmed(_Runtime(), _row(1)) is True

    async def test_a_confirmed_source_permits_signing(self) -> None:
        coordinator = AsyncMock()
        coordinator.confirm = AsyncMock(return_value=CONFIRMED)
        runtime = _Runtime(coordinator=coordinator)
        assert (
            await self._confirmed(runtime, _row(1, input_firmware_device_id="fw-01"))
            is True
        )
        coordinator.confirm.assert_awaited_with("fw-01")

    @pytest.mark.parametrize("status", ["pending", "quarantined", "", "confirmed_"])
    async def test_anything_short_of_confirmed_withholds_signing(self, status) -> None:
        """Fail closed. Signing under authority the store cannot back is worse
        than an unsigned row, because it looks like proof."""
        coordinator = AsyncMock()
        coordinator.confirm = AsyncMock(return_value=status)
        runtime = _Runtime(coordinator=coordinator)
        assert (
            await self._confirmed(runtime, _row(1, input_firmware_device_id="fw-01"))
            is False
        )

    async def test_a_failing_lookup_leaves_evidence_pending(self) -> None:
        """An error reading the status is not permission to sign."""
        coordinator = AsyncMock()
        coordinator.confirm = AsyncMock(side_effect=RuntimeError("unreachable"))
        runtime = _Runtime(coordinator=coordinator)
        assert (
            await self._confirmed(runtime, _row(1, input_firmware_device_id="fw-01"))
            is False
        )

    async def test_no_coordinator_fails_closed(self) -> None:
        runtime = _Runtime(coordinator=None)
        assert (
            await self._confirmed(runtime, _row(1, input_firmware_device_id="fw-01"))
            is False
        )

    async def test_reconciliation_skips_an_unconfirmed_firmware_row(self) -> None:
        """The gate applies on the reconciliation path, not only at emission."""
        coordinator = AsyncMock()
        coordinator.confirm = AsyncMock(return_value="pending")
        attestor = _Attestor()
        store = _store([_row(1, input_firmware_device_id="fw-01"), _row(2)])
        await _reconcile(
            _Runtime(attestor=attestor, store=store, coordinator=coordinator)
        )
        assert [c[0] for c in attestor.calls] == [2], (
            "an unconfirmed firmware row was signed during reconciliation"
        )

    async def test_reconciliation_signs_a_confirmed_firmware_row(self) -> None:
        coordinator = AsyncMock()
        coordinator.confirm = AsyncMock(return_value=CONFIRMED)
        attestor = _Attestor()
        store = _store([_row(1, input_firmware_device_id="fw-01")])
        await _reconcile(
            _Runtime(attestor=attestor, store=store, coordinator=coordinator)
        )
        assert attestor.calls == [(1, True)]


class TestEvidenceHealth:
    @staticmethod
    async def _health(runtime) -> dict[str, Any]:
        return await OriRuntime._evidence_health(runtime)

    async def test_health_reports_disabled_when_evidence_is_off(self) -> None:
        health = await self._health(_Runtime(enabled=False))
        assert health["enabled"] is False
        assert health["available"] is False

    async def test_health_reports_true_chain_state_when_available(self) -> None:
        """These are read by an operator deciding whether the device is sound.

        Reporting a head or a count the chain does not hold would make a
        degraded device look healthy, which is worse than reporting nothing.
        """
        attestor = _Attestor()
        attestor.head = "ef" * 32
        attestor.pending = 4
        health = await self._health(_Runtime(attestor=attestor, store=_store([])))
        assert health["enabled"] is True
        assert health["available"] is True
        assert health["chain_head_hash"] == "ef" * 32
        assert health["pending_export_count"] == 4
        assert health["public_key_hex"] == "ab" * 32
        assert health["protocol_version"] == "ori.evidence.v2"

    async def test_health_reports_nothing_when_the_attestor_is_absent(self) -> None:
        health = await self._health(_Runtime(attestor=None, enabled=True))
        assert health["available"] is False
        assert health["chain_head_hash"] is None
        assert health["pending_export_count"] is None
        assert health["action_event_type"] == ""

    async def test_health_carries_the_attestation_gap_count(self) -> None:
        """The gap count is the signal that evidence is incomplete."""
        health = await self._health(_Runtime(attestor=_Attestor(), store=_store([])))
        assert health["attestation_gap_count"] == 1
        assert health["last_attested_action_id"] == 9
        assert health["status_counts"] == {"signed": 3, "failed": 1}

    async def test_a_failing_summary_read_does_not_break_health(self) -> None:
        """Health must degrade to partial rather than to nothing."""
        store = _store([])
        store.get_attestation_summary = AsyncMock(side_effect=RuntimeError("db"))
        health = await self._health(_Runtime(attestor=_Attestor(), store=store))
        assert health["available"] is True
        assert health["chain_head_hash"] is not None
        assert health["attestation_gap_count"] == 0


class TestHeartbeatEvidenceProjection:
    """The heartbeat carries the chain head as a truncation signal.

    It is not the evidence object -- the persisted chain is. What it provides is
    near-real-time visibility that a local chain was truncated or reset, which
    would otherwise only surface when someone tried to verify it.
    """

    @staticmethod
    async def _payload(snapshot: dict) -> dict:
        from ori.gateway.node_heartbeat import MqttRuntimeNodeHeartbeatPublisher

        publisher = object.__new__(MqttRuntimeNodeHeartbeatPublisher)
        publisher._health_snapshot_provider = lambda: snapshot
        publisher._device_id = "energy-monitor-ikeja-01"
        return await MqttRuntimeNodeHeartbeatPublisher._payload(publisher)

    async def test_the_heartbeat_carries_the_chain_head_and_gap_count(self) -> None:
        payload = await self._payload(
            {
                "evidence": {
                    "enabled": True,
                    "available": True,
                    "chain_head_hash": "ab" * 32,
                    "attestation_gap_count": 3,
                    "action_event_type": "SAFETY_ACTION_EXECUTED",
                }
            }
        )
        assert payload["evidence"]["chain_head_hash"] == "ab" * 32
        assert payload["evidence"]["attestation_gap_count"] == 3
        assert payload["evidence"]["available"] is True
        assert payload["evidence"]["action_event_type"] == "SAFETY_ACTION_EXECUTED"

    async def test_the_heartbeat_omits_evidence_when_it_is_disabled(self) -> None:
        """A device not keeping evidence must not appear to be keeping it."""
        payload = await self._payload({"evidence": {"enabled": False}})
        assert "evidence" not in payload

    async def test_the_heartbeat_omits_evidence_when_absent_entirely(self) -> None:
        payload = await self._payload({})
        assert "evidence" not in payload

    async def test_an_unavailable_chain_reports_available_false(self) -> None:
        """Enabled but unavailable is a real state, and must be distinguishable
        from both disabled and healthy."""
        payload = await self._payload(
            {
                "evidence": {
                    "enabled": True,
                    "available": False,
                    "chain_head_hash": "",
                    "attestation_gap_count": 7,
                    "action_event_type": "",
                }
            }
        )
        assert payload["evidence"]["available"] is False
        assert payload["evidence"]["chain_head_hash"] == ""
        assert payload["evidence"]["attestation_gap_count"] == 7


class TestFirmwareRegistrationSnapshot:
    """The registration snapshot travels with the row it justifies.

    It is captured into the action row's own insert, so what is attested is
    exactly what was logged. Re-querying at signing time would attest a
    registration that may have changed since the action fired.
    """

    async def test_a_firmware_row_carries_its_registration_snapshot(
        self, tmp_path
    ) -> None:
        from ori.network.events import ActionResult
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "snap.db"))
        await store.open()
        try:
            await store.log_action_for_event(
                ActionResult(
                    action_name="emergency_cutoff",
                    tier="D",
                    executed=True,
                    approved=None,
                    action_taken="emergency_cutoff",
                    timestamp=1787000000000,
                ),
                trigger_name="dangerous_overcurrent",
                input_firmware_device_id="fw-01",
                input_firmware_boot_id=7,
                input_firmware_seq=42,
                input_firmware_registration='{"anchor_epoch_id":"sha256:aa"}',
                attestation_pending=True,
            )
            rows = await store.get_actions_needing_attestation()
            assert rows, "the row was not queued for attestation"
            row = rows[0]
            assert row["input_firmware_device_id"] == "fw-01"
            assert int(row["input_firmware_boot_id"]) == 7
            assert int(row["input_firmware_seq"]) == 42
            assert "sha256:aa" in str(row["input_firmware_registration"])
        finally:
            await store.close()

    async def test_a_non_firmware_row_carries_no_snapshot(self, tmp_path) -> None:
        """An empty snapshot must not read as a registration nobody made."""
        from ori.network.events import ActionResult
        from ori.state.store import StateStore

        store = StateStore(db_path=str(tmp_path / "snap2.db"))
        await store.open()
        try:
            await store.log_action_for_event(
                ActionResult(
                    action_name="emergency_cutoff",
                    tier="D",
                    executed=True,
                    approved=None,
                    action_taken="emergency_cutoff",
                    timestamp=1787000000000,
                ),
                trigger_name="dangerous_overcurrent",
                attestation_pending=True,
            )
            row = (await store.get_actions_needing_attestation())[0]
            assert not str(row.get("input_firmware_device_id") or "")
            assert not str(row.get("input_firmware_registration") or "")
        finally:
            await store.close()

    async def test_the_snapshot_survives_a_store_reopen(self, tmp_path) -> None:
        """Reconciliation runs after a restart and reads this row."""
        from ori.network.events import ActionResult
        from ori.state.store import StateStore

        db = str(tmp_path / "snap3.db")
        store = StateStore(db_path=db)
        await store.open()
        await store.log_action_for_event(
            ActionResult(
                action_name="emergency_cutoff",
                tier="D",
                executed=True,
                approved=None,
                action_taken="emergency_cutoff",
                timestamp=1787000000000,
            ),
            trigger_name="dangerous_overcurrent",
            input_firmware_device_id="fw-01",
            input_firmware_boot_id=7,
            input_firmware_seq=42,
            input_firmware_registration='{"anchor_epoch_id":"sha256:aa"}',
            attestation_pending=True,
        )
        await store.close()

        reopened = StateStore(db_path=db)
        await reopened.open()
        try:
            row = (await reopened.get_actions_needing_attestation())[0]
            assert row["input_firmware_device_id"] == "fw-01"
            assert "sha256:aa" in str(row["input_firmware_registration"])
        finally:
            await reopened.close()
