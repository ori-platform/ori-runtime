# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Attestation state on action rows, and its survival through exports.

These are store-layer platform invariants, not properties of whatever signs the
evidence. The retired private-artifact tests were the only place they were
asserted, so a signed action could have lost its chain linkage on the way out
and nothing would have noticed.
"""

from __future__ import annotations

import time

import pytest

from ori.network.events import ActionResult
from ori.state.store import StateStore


@pytest.fixture
async def store(tmp_path):
    s = StateStore(db_path=str(tmp_path / "attestation.db"))
    await s.open()
    yield s
    await s.close()


def _result(action_name: str = "open_safety_circuit", tier: str = "C") -> ActionResult:
    return ActionResult(
        action_name=action_name,
        tier=tier,
        executed=True,
        approved=True if tier == "C" else None,
        action_taken=action_name,
        timestamp=int(time.time() * 1000),
    )


async def _log(store: StateStore, tier: str = "C", **kw) -> int | None:
    """Log one action the way the dispatcher does, and return its row id.

    `attestation_pending` is the dispatcher's decision, not the store's: the
    store records what it is told. Passing it here for attested tiers reproduces
    the production path rather than asserting against a default the dispatcher
    never uses.

    The id comes from the attestation queue, since `get_action_log` does not
    project it. Non-attested tiers are never queued and return None, which is
    itself the behaviour the tier tests below assert.
    """
    kw.setdefault("attestation_pending", tier in ("C", "D"))
    await store.log_action_for_event(
        _result(tier=tier), trigger_name="dangerous_overcurrent", **kw
    )
    pending = await store.get_actions_needing_attestation()
    if not pending:
        return None
    return int(pending[-1]["id"])


class TestAttestationStatusLifecycle:
    async def test_an_attested_tier_row_is_written_pending(self, store) -> None:
        """Append-after-log: the row exists before anything signs it.

        The order is the point. A row written only after signing would be lost
        entirely if the process died between the action and the signature, and
        the action has already happened by then.
        """
        await _log(store, tier="C")
        rows = await store.get_action_log(limit=1)
        assert rows[0]["attestation_status"] == "pending"
        assert rows[0]["attestation_seq"] is None

    async def test_signing_updates_the_row_in_place(self, store) -> None:
        action_id = await _log(store, tier="D")
        await store.set_action_attestation(
            action_id, status="signed", attestation_seq=7
        )
        rows = await store.get_action_log(limit=1)
        assert rows[0]["attestation_status"] == "signed"
        assert rows[0]["attestation_seq"] == 7

    async def test_a_failed_attestation_is_visible_not_silent(self, store) -> None:
        """A gap that cannot be seen is indistinguishable from no gap."""
        action_id = await _log(store, tier="D")
        await store.set_action_attestation(
            action_id, status="failed", attestation_seq=None
        )
        rows = await store.get_action_log(limit=1)
        assert rows[0]["attestation_status"] == "failed"

    @pytest.mark.parametrize("status", ["", "unknown", "SIGNED", "ok", "done"])
    async def test_an_unrecognised_status_is_refused(self, store, status) -> None:
        """An unknown status would make the gap count silently wrong."""
        action_id = await _log(store, tier="D")
        with pytest.raises(ValueError, match="invalid attestation status"):
            await store.set_action_attestation(
                action_id, status=status, attestation_seq=None
            )

    async def test_a_non_attested_tier_never_enters_the_attestation_queue(
        self, store
    ) -> None:
        """Tier A and B are not signed, so they must not read as missing evidence.

        The dispatcher does not mark them pending; this asserts the store honours
        that rather than queueing everything it is given.
        """
        await _log(store, tier="A")
        await _log(store, tier="B")
        pending = await store.get_actions_needing_attestation()
        assert pending == [], "a non-attested tier was queued for signing"

    async def test_attested_tiers_are_queued_until_they_are_signed(self, store) -> None:
        c_id = await _log(store, tier="C")
        await _log(store, tier="D")
        assert len(await store.get_actions_needing_attestation()) == 2
        await store.set_action_attestation(c_id, status="signed", attestation_seq=1)
        remaining = await store.get_actions_needing_attestation()
        assert [int(r["id"]) for r in remaining] != [c_id]
        assert len(remaining) == 1

    async def test_a_failed_row_is_retried_not_abandoned(self, store) -> None:
        action_id = await _log(store, tier="D")
        await store.set_action_attestation(
            action_id, status="failed", attestation_seq=None
        )
        pending = await store.get_actions_needing_attestation()
        assert [int(r["id"]) for r in pending] == [action_id]


class TestAttestationSummary:
    async def test_the_gap_count_counts_unsigned_attested_rows(self, store) -> None:
        await _log(store, tier="D")
        signed_id = await _log(store, tier="D")
        await store.set_action_attestation(
            signed_id, status="signed", attestation_seq=1
        )
        summary = await store.get_attestation_summary()
        assert summary["attestation_gap_count"] == 1
        assert summary["last_attested_action_id"] == signed_id

    async def test_a_reconciled_row_counts_as_attested(self, store) -> None:
        """Late evidence is still evidence; it must close the gap it left."""
        action_id = await _log(store, tier="D")
        await store.set_action_attestation(
            action_id, status="reconciled", attestation_seq=4
        )
        summary = await store.get_attestation_summary()
        assert summary["attestation_gap_count"] == 0
        assert summary["last_attested_action_id"] == action_id


class TestExportLinkage:
    async def test_action_log_exports_retain_attestation_linkage(self, store) -> None:
        """Without the linkage an exported action cannot be tied to its evidence.

        The export is what a reader off the device sees. A row that arrives
        without `attestation_seq` cannot be matched to the chain entry proving
        it happened, which makes the evidence unverifiable at exactly the point
        it matters.
        """
        action_id = await _log(store, tier="D")
        await store.set_action_attestation(
            action_id, status="signed", attestation_seq=11
        )
        exported = await store.export_action_log(limit=10)
        assert exported, "the export returned nothing"
        row = exported[0]
        assert row["attestation_status"] == "signed"
        assert row["attestation_seq"] == 11

    async def test_local_reads_carry_the_same_linkage_as_exports(self, store) -> None:
        """A divergence here would mean the device and a reader disagree."""
        action_id = await _log(store, tier="D")
        await store.set_action_attestation(
            action_id, status="signed", attestation_seq=11
        )
        local = (await store.get_action_log(limit=1))[0]
        exported = (await store.export_action_log(limit=1))[0]
        for field in ("attestation_status", "attestation_seq"):
            assert local[field] == exported[field], f"{field} differs from the export"

    async def test_a_pending_row_exports_as_pending(self, store) -> None:
        """An unsigned action must not export as though it were attested."""
        await _log(store, tier="D")
        row = (await store.export_action_log(limit=1))[0]
        assert row["attestation_status"] == "pending"
        assert row["attestation_seq"] is None
