# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The proposal row: created before the ask, admitted in one transaction.

Every answer below comes from a real SQLite file. The admission transaction
holds the binding match, the same-outcome block, the reservation ceiling and
the token claim together, so no reply can leave a claimed token beside an
unadmitted approval, or an approval beside an unclaimed token.
"""

from __future__ import annotations

import sqlite3
from typing import Any

import pytest

from ori.reasoning import tier_c_admission as adm
from ori.state.store import StateStore

PROPOSAL: dict[str, Any] = {
    "proposal_id": "AB12CD34",
    "device_id": "energy-monitor-ikeja-01",
    "action": "trip_relay",
    "target": "relay-gpio-26",
    "zone_id": "zone-feeder-a",
    "outcome": "open_protected_circuit",
    "safe_default_action": "log_to_dashboard",
    "binding_digest": "sha256:" + "b" * 64,
    "authority_json": '{"v":1}',
    "created_at_ms": 1_787_000_000_000,
    "expires_at_ms": 1_787_000_300_000,
}
CEILING = 4


def _admit(store: StateStore, proposal_id: str = "AB12CD34", **over: Any) -> Any:
    fields: dict[str, Any] = {
        "binding_digest": PROPOSAL["binding_digest"],
        "authority_json": PROPOSAL["authority_json"],
        "reservation_ceiling": CEILING,
        "ingress_channel": "sms",
        "ingress_from": "+234",
        "operator_response": "YES-AB12CD34",
    }
    fields.update(over)
    return store.admit_tier_c_approval(proposal_id, **fields)


@pytest.fixture
async def store(tmp_path: Any) -> Any:
    s = StateStore(str(tmp_path / "s.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


async def test_a_proposal_is_a_committed_row_with_its_first_record(store: Any) -> None:
    assert await store.create_tier_c_proposal(**PROPOSAL) == "committed"
    assert await store.create_tier_c_proposal(**PROPOSAL) == "duplicate"
    row = await store.get_tier_c_proposal("AB12CD34")
    assert row["decision_state"] == adm.PROPOSED
    assert await store.get_tier_c_proposal_records("AB12CD34") == [adm.PROPOSED]


async def test_admission_is_one_forward_step_and_a_repeat_is_idempotent(
    store: Any,
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    assert await _admit(store) == "committed"
    assert await _admit(store) == "duplicate"
    row = await store.get_tier_c_proposal("AB12CD34")
    assert row["decision_state"] == adm.APPROVED_PENDING_DISPATCH
    assert row["ingress_channel"] == "sms" and row["committed_at_ms"]
    assert await store.get_tier_c_proposal_records("AB12CD34") == [
        adm.PROPOSED,
        adm.APPROVED_PENDING_DISPATCH,
    ]


async def test_a_reply_to_a_closed_proposal_says_which_state_closed_it(
    store: Any,
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    assert await store.advance_tier_c_proposal(
        "AB12CD34", adm.PROPOSAL_EXPIRED, from_states=(adm.PROPOSED,)
    )
    assert await _admit(store) == f"closed:{adm.PROPOSAL_EXPIRED}"
    assert await _admit(store, proposal_id="nope") == "closed:none"


async def test_a_changed_binding_or_authority_closes_the_proposal(store: Any) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    assert await _admit(store, binding_digest="sha256:" + "c" * 64) == "binding_changed"
    row = await store.get_tier_c_proposal("AB12CD34")
    assert row["decision_state"] == adm.APPROVAL_BINDING_CHANGED
    # Changing back revives nothing.
    assert await _admit(store) == f"closed:{adm.APPROVAL_BINDING_CHANGED}"

    second = {**PROPOSAL, "proposal_id": "P2"}
    await store.create_tier_c_proposal(**second)
    assert await _admit(store, "P2", authority_json='{"v":2}') == "binding_changed"


async def test_an_unresolved_approval_blocks_only_the_same_outcome_on_the_same_zone(
    store: Any,
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    assert await _admit(store) == "committed"
    assert await store.advance_tier_c_proposal(
        "AB12CD34",
        adm.DISPATCH_OUTCOME_UNKNOWN,
        from_states=(adm.APPROVED_PENDING_DISPATCH,),
    )
    same = {**PROPOSAL, "proposal_id": "P2"}
    assert await store.create_tier_c_proposal(**same) == "blocked"
    other_outcome = {
        **PROPOSAL,
        "proposal_id": "P3",
        "outcome": "close_protected_circuit",
    }
    assert await store.create_tier_c_proposal(**other_outcome) == "committed"
    other_zone = {**PROPOSAL, "proposal_id": "P4", "zone_id": "zone-b"}
    assert await store.create_tier_c_proposal(**other_zone) == "committed"
    assert await store.tier_c_outcome_blocked("zone-feeder-a", "open_protected_circuit")
    assert not await store.tier_c_outcome_blocked(
        "zone-feeder-a", "close_protected_circuit"
    )


async def test_an_uncertainty_arising_after_creation_blocks_the_reply_inside_the_commit(
    store: Any,
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    later = {**PROPOSAL, "proposal_id": "P2"}
    await store.create_tier_c_proposal(**later)
    assert await _admit(store) == "committed"
    assert await store.advance_tier_c_proposal(
        "AB12CD34", adm.DISPATCH_STARTED, from_states=(adm.APPROVED_PENDING_DISPATCH,)
    )
    assert await _admit(store, "P2") == "blocked"
    row = await store.get_tier_c_proposal("P2")
    assert row["decision_state"] == adm.PROPOSAL_BLOCKED_UNCERTAIN_OUTCOME
    # An executed outcome releases the block for a fresh proposal.
    assert await store.advance_tier_c_proposal(
        "AB12CD34", adm.EXECUTED, from_states=(adm.DISPATCH_STARTED,)
    )
    fresh = {**PROPOSAL, "proposal_id": "P3"}
    assert await store.create_tier_c_proposal(**fresh) == "committed"
    assert await _admit(store, "P3") == "committed"


async def test_the_reservation_ceiling_leaves_the_proposal_open(store: Any) -> None:
    for index in range(CEILING):
        row = {
            **PROPOSAL,
            "proposal_id": f"P{index}",
            "zone_id": f"zone-{index}",
        }
        await store.create_tier_c_proposal(**row)
        assert await _admit(store, f"P{index}") == "committed"
    over = {**PROPOSAL, "proposal_id": "OVER", "zone_id": "zone-x"}
    await store.create_tier_c_proposal(**over)
    assert await _admit(store, "OVER") == "reservation_unavailable"
    assert (await store.get_tier_c_proposal("OVER"))["decision_state"] == adm.PROPOSED
    assert await store.advance_tier_c_proposal(
        "P0", adm.EXECUTED, from_states=(adm.APPROVED_PENDING_DISPATCH,)
    )
    assert await _admit(store, "OVER") == "committed"


async def test_the_token_claim_and_the_approval_commit_are_one_transaction(
    store: Any, tmp_path: Any
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    other = {**PROPOSAL, "proposal_id": "P2", "zone_id": "zone-b"}
    await store.create_tier_c_proposal(**other)
    # A commit refused for another reason leaves the token unclaimed.
    assert (
        await _admit(
            store, offline_token_id="tok-1", binding_digest="sha256:" + "d" * 64
        )
        == "binding_changed"
    )
    with sqlite3.connect(str(tmp_path / "s.db")) as reader:
        claimed = reader.execute(
            "SELECT token_id FROM offline_token_consumption"
        ).fetchall()
    assert claimed == []
    assert await _admit(store, "P2", offline_token_id="tok-1") == "committed"
    third = {**PROPOSAL, "proposal_id": "P3", "zone_id": "zone-c"}
    await store.create_tier_c_proposal(**third)
    assert await _admit(store, "P3", offline_token_id="tok-1") == "token_replayed"
    assert (await store.get_tier_c_proposal("P3"))["decision_state"] == adm.PROPOSED
    with sqlite3.connect(str(tmp_path / "s.db")) as reader:
        claimed = reader.execute(
            "SELECT token_id, action FROM offline_token_consumption"
        ).fetchall()
    assert claimed == [("tok-1", "trip_relay")]


async def test_an_advance_never_moves_back_and_records_each_step(store: Any) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    assert not await store.advance_tier_c_proposal(
        "AB12CD34", adm.EXECUTED, from_states=(adm.DISPATCH_STARTED,)
    )
    await _admit(store)
    assert await store.advance_tier_c_proposal(
        "AB12CD34",
        adm.DISPATCH_STARTED,
        from_states=(adm.APPROVED_PENDING_DISPATCH,),
    )
    assert await store.advance_tier_c_proposal(
        "AB12CD34",
        adm.EXECUTED,
        from_states=(adm.DISPATCH_STARTED,),
        outcome_json='{"executed": true}',
    )
    row = await store.get_tier_c_proposal("AB12CD34")
    assert row["outcome_json"] == '{"executed": true}'
    assert await store.get_tier_c_proposal_records("AB12CD34") == [
        adm.PROPOSED,
        adm.APPROVED_PENDING_DISPATCH,
        adm.DISPATCH_STARTED,
        adm.EXECUTED,
    ]


async def test_one_safe_default_intent_per_proposal(store: Any) -> None:
    assert await store.create_tier_c_safe_default_intent("AB12CD34", "log_to_dashboard")
    assert not await store.create_tier_c_safe_default_intent(
        "AB12CD34", "log_to_dashboard"
    )
    await store.mark_tier_c_safe_default_intent("AB12CD34", "executed")
    intents = await store.get_tier_c_safe_default_intents("AB12CD34")
    assert [(i["action"], i["outcome"]) for i in intents] == [
        ("log_to_dashboard", "executed")
    ]


def _reconcile(store: Any, **over: Any) -> Any:
    req: dict[str, Any] = {
        "proposal_id": "AB12CD34",
        "device_id": PROPOSAL["device_id"],
        "runtime_device_id": PROPOSAL["device_id"],
        "zone_id": "zone-feeder-a",
        "outcome": "executed",
        "reason": "site_inspection",
        "note": None,
        "source": "operator_local",
        "entry_point": "local_operator_socket",
        "principal_uid": 1001,
        "principal_account": "installer",
        "principal_login_uid": 1001,
    }
    req.update(over)
    return store.reconcile_tier_c(**req)


async def test_reconciliation_refuses_in_the_contracts_order_and_appends_once(
    store: Any, tmp_path: Any
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    await _admit(store)
    assert (await _reconcile(store, device_id="other"))["error"] == "device_mismatch"
    assert (await _reconcile(store, proposal_id="nope"))["error"] == "unknown_proposal"
    assert (await _reconcile(store, zone_id="zone-b"))["error"] == "zone_mismatch"
    assert (await _reconcile(store))["error"] == "not_uncertain"
    await store.advance_tier_c_proposal(
        "AB12CD34",
        adm.DISPATCH_NOT_PROVEN,
        from_states=(adm.APPROVED_PENDING_DISPATCH,),
    )
    first = await _reconcile(store)
    assert first["ok"] and first["already_recorded"] is False
    assert first["record"]["decision_state"] == adm.RECONCILED_EXECUTED
    row = await store.get_tier_c_proposal("AB12CD34")
    assert row["decision_state"] == adm.RECONCILED_EXECUTED
    assert not await store.tier_c_outcome_blocked(
        "zone-feeder-a", "open_protected_circuit"
    )
    # An identical repeat by the same principal appends nothing.
    again = await _reconcile(store)
    assert again["ok"] and again["already_recorded"] is True
    # By another principal it is audited, and still appends no reconciliation.
    other = await _reconcile(store, principal_uid=0, principal_login_uid=1002)
    assert other["ok"] and other["already_recorded"] is True
    # A different request is refused.
    assert (await _reconcile(store, outcome="not-executed"))[
        "error"
    ] == "already_reconciled"
    with sqlite3.connect(str(tmp_path / "s.db")) as reader:
        records = reader.execute(
            "SELECT count(*) FROM tier_c_reconciliations"
        ).fetchone()
        attempts = reader.execute(
            "SELECT kind, principal_uid FROM tier_c_reconcile_attempts"
        ).fetchall()
    assert records == (1,)
    assert attempts == [("identical_repeat", 0)]
    assert await store.get_tier_c_proposal_records("AB12CD34") == [
        adm.PROPOSED,
        adm.APPROVED_PENDING_DISPATCH,
        adm.DISPATCH_NOT_PROVEN,
        adm.RECONCILED_EXECUTED,
    ]


async def test_the_store_refuses_a_target_outside_the_closed_states(store: Any) -> None:
    from ori.state.store import _TIER_C_DECISION_STATES

    assert _TIER_C_DECISION_STATES == adm.DECISION_STATES
    await store.create_tier_c_proposal(**PROPOSAL)
    await _admit(store)
    assert not await store.advance_tier_c_proposal(
        "AB12CD34",
        "totally_unknown_state",
        from_states=(adm.APPROVED_PENDING_DISPATCH,),
    )
    assert not await store.advance_tier_c_proposal(
        "AB12CD34", adm.PROPOSED, from_states=(adm.APPROVED_PENDING_DISPATCH,)
    )
    assert (await store.get_tier_c_proposal("AB12CD34"))["decision_state"] == (
        adm.APPROVED_PENDING_DISPATCH
    )
    assert await store.get_tier_c_proposal_records("AB12CD34") == [
        adm.PROPOSED,
        adm.APPROVED_PENDING_DISPATCH,
    ]


async def test_the_store_refuses_a_reconcile_outcome_it_does_not_define(
    store: Any,
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    await _admit(store)
    await store.advance_tier_c_proposal(
        "AB12CD34",
        adm.DISPATCH_NOT_PROVEN,
        from_states=(adm.APPROVED_PENDING_DISPATCH,),
    )
    answer = await _reconcile(store, outcome="maybe")
    assert answer == {"ok": False, "error": "invalid_arguments"}
    assert (await store.get_tier_c_proposal("AB12CD34"))["decision_state"] == (
        adm.DISPATCH_NOT_PROVEN
    )


async def test_a_close_that_applies_a_safe_default_creates_its_intent_in_one_transaction(
    store: Any, monkeypatch: Any
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    assert await store.advance_tier_c_proposal(
        "AB12CD34",
        adm.REJECTED,
        from_states=(adm.PROPOSED,),
        reason="operator_no",
        safe_default_action="log_to_dashboard",
    )
    intents = await store.get_tier_c_safe_default_intents("AB12CD34")
    assert [(i["action"], i["outcome"], i["reason"]) for i in intents] == [
        ("log_to_dashboard", "pending", "operator_no")
    ]
    # The intent is the obligation; a close that cannot record it does not land.
    await store.create_tier_c_proposal(**{**PROPOSAL, "proposal_id": "EF56GH78"})

    def _refuse(*_a: Any, **_k: Any) -> bool:
        raise sqlite3.OperationalError("intents table unavailable")

    monkeypatch.setattr(StateStore, "_insert_tier_c_intent", staticmethod(_refuse))
    with pytest.raises(sqlite3.OperationalError):
        await store.advance_tier_c_proposal(
            "EF56GH78",
            adm.REJECTED,
            from_states=(adm.PROPOSED,),
            safe_default_action="log_to_dashboard",
        )
    assert (await store.get_tier_c_proposal("EF56GH78"))["decision_state"] == (
        adm.PROPOSED
    )
    assert await store.get_tier_c_proposal_records("EF56GH78") == [adm.PROPOSED]
    assert await store.get_tier_c_safe_default_intents("EF56GH78") == []


async def test_a_refusing_admission_carries_the_intent_and_a_pending_intent_is_read_back(
    store: Any,
) -> None:
    await store.create_tier_c_proposal(**PROPOSAL)
    assert (
        await store.admit_tier_c_approval(
            "AB12CD34",
            binding_digest="sha256:" + "c" * 64,
            authority_json=PROPOSAL["authority_json"],
            reservation_ceiling=64,
        )
        == "binding_changed"
    )
    pending = await store.get_pending_tier_c_safe_default_intents()
    assert [
        (p["proposal_id"], p["safe_default_action"], p["action"]) for p in pending
    ] == [("AB12CD34", "log_to_dashboard", "trip_relay")]
    # Ensuring finds the pending obligation; marking it done retires it.
    assert (
        await store.ensure_tier_c_safe_default_intent(
            "AB12CD34", "log_to_dashboard", reason="x"
        )
        == "pending"
    )
    await store.mark_tier_c_safe_default_intent("AB12CD34", "executed")
    assert (
        await store.ensure_tier_c_safe_default_intent(
            "AB12CD34", "log_to_dashboard", reason="x"
        )
        == "executed"
    )
    assert await store.get_pending_tier_c_safe_default_intents() == []
    # A proposal with no intent yet: ensuring creates it, once.
    await store.create_tier_c_proposal(**{**PROPOSAL, "proposal_id": "EF56GH78"})
    assert (
        await store.ensure_tier_c_safe_default_intent(
            "EF56GH78", "alert_sms", reason="expired"
        )
        == "pending"
    )
    assert len(await store.get_tier_c_safe_default_intents("EF56GH78")) == 1
