# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A request that joins an act another dispatch holds is a contributor, not an act.

Execution coalesces; authority never does. The contributor performed nothing
and holds no licence, so it is recorded with executed false, no approval and no
authority snapshot, is never attested, and names the holder it joined by the
key the holder reserved before acting. The holder's row is the only record of
the physical act.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from ori.reasoning.action_dispatcher import ActionDispatcher
from ori.reasoning.resource_gate import ResourceGate
from ori.state.store import StateStore, _check_action_record_shape
from tests.test_tier_d_never_waits_on_evidence import (
    BOUND,
    _context,
    _reasoning,
    _Signer,
    _Skill,
)

PROMPT = 2.0


class _Approver:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, *args: Any, **kwargs: Any) -> Any:
        self.sent.append(str(args or kwargs))
        return None


async def _rig(
    tmp_path: Path, outcome: Any
) -> tuple[StateStore, ActionDispatcher, Any]:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    signer = _Signer()
    dispatcher = ActionDispatcher(
        state_store=store,
        evidence_attestor=signer,
        config={"relay_enabled": True, "operator_contact": "+2348000000000"},
    )
    dispatcher.bind_resource_gate(ResourceGate(), BOUND)
    release = asyncio.Event()
    calls: list[str] = []

    async def trip(*_args: Any, **_kwargs: Any) -> bool:
        calls.append("trip_relay")
        await release.wait()
        if isinstance(outcome, BaseException):
            raise outcome
        return bool(outcome)

    dispatcher.register_executor("trip_relay", trip)
    return store, dispatcher, (signer, release, calls)


def _rows(store: StateStore) -> list[dict[str, Any]]:
    assert store._conn is not None
    store._conn.row_factory = sqlite3.Row
    return [
        dict(r)
        for r in store._conn.execute(
            "SELECT id, tier, executed, approved, action_taken, authority_json,"
            " attestation_status, record_kind, record_key, contributed_to"
            " FROM action_log ORDER BY id"
        )
    ]


@pytest.mark.parametrize("joiner_tier", ["C", "D"])
@pytest.mark.parametrize(
    "holder_outcome", [True, False], ids=["holder-succeeds", "holder-fails"]
)
async def test_a_request_joining_a_held_trip_is_a_contributor(
    tmp_path: Path, joiner_tier: str, holder_outcome: bool
) -> None:
    store, dispatcher, (signer, release, calls) = await _rig(tmp_path, holder_outcome)
    try:
        holder = asyncio.create_task(
            dispatcher.dispatch(
                action="trip_relay",
                tier="D",
                context=_context(store, _Skill("protector", "D", ["trip_relay"])),
                result=_reasoning(),
            )
        )
        while not calls:
            await asyncio.sleep(0)
        joiner_skill = _Skill("watcher", joiner_tier, ["trip_relay"])
        # Returns at once: it does not wait on the holder's outcome.
        joined = await asyncio.wait_for(
            dispatcher.dispatch(
                action="trip_relay",
                tier=joiner_tier,
                context=_context(store, joiner_skill),
                result=_reasoning(),
            ),
            PROMPT,
        )
        assert (joined.executed, joined.approved, joined.action_taken) == (
            False,
            None,
            "coalesced",
        )
        assert not joined.proposal_id
        release.set()
        await asyncio.wait_for(holder, PROMPT)
        await dispatcher.drain_records(timeout=PROMPT)
        assert calls == ["trip_relay"], "a second executor ran"
        rows = _rows(store)
        dispatches = [r for r in rows if r["record_kind"] == "dispatch"]
        contributors = [r for r in rows if r["record_kind"] == "contributor"]
        assert len(dispatches) == 1 and len(contributors) == 1, rows
        held, contributor = dispatches[0], contributors[0]
        assert held["executed"] == int(holder_outcome)
        assert (
            held["record_key"] and contributor["contributed_to"] == held["record_key"]
        )
        assert contributor["executed"] == 0 and contributor["approved"] is None
        assert contributor["authority_json"] is None
        assert contributor["attestation_status"] == ""
        assert contributor["tier"] == joiner_tier
        # Selected for attestation: the holder alone. (A firmware-sourced
        # reading waits on source confirmation before it is signed.)
        assert held["attestation_status"] in ("pending", "signed")
        assert contributor["id"] not in signer.signed
    finally:
        await store.close()


async def test_an_approval_gated_tier_b_joiner_asks_no_operator(tmp_path: Path) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    approver_calls: list[str] = []
    try:
        dispatcher = ActionDispatcher(
            state_store=store,
            config={"relay_enabled": True, "operator_contact": "+2348000000000"},
        )
        dispatcher.bind_resource_gate(ResourceGate(), BOUND)
        release = asyncio.Event()
        calls: list[str] = []

        async def terminate(*_args: Any, **_kwargs: Any) -> bool:
            calls.append("terminate_process")
            await release.wait()
            return True

        dispatcher.register_executor("terminate_process", terminate)
        dispatcher.register_resource_resolver(
            "terminate_process", lambda _context: {"target": "pid:4242"}
        )

        async def no_operator(*_args: Any, **_kwargs: Any) -> Any:
            approver_calls.append("asked")
            raise AssertionError("a contributor asked the operator")

        dispatcher._approval_workflow = no_operator  # type: ignore[method-assign]
        holder = asyncio.create_task(
            dispatcher.dispatch(
                action="terminate_process",
                tier="B",
                context=_context(store, _Skill("first", "B", ["terminate_process"])),
                result=_reasoning(),
            )
        )
        while not calls:
            await asyncio.sleep(0)
        gated = _Skill("second", "B", ["terminate_process"])
        gated.triggers[0].requires_approval = True
        joined = await asyncio.wait_for(
            dispatcher.dispatch(
                action="terminate_process",
                tier="B",
                context=_context(store, gated),
                result=_reasoning(),
            ),
            PROMPT,
        )
        assert (joined.executed, joined.approved, joined.action_taken) == (
            False,
            None,
            "coalesced",
        )
        release.set()
        await asyncio.wait_for(holder, PROMPT)
        await dispatcher.drain_records(timeout=PROMPT)
        assert calls == ["terminate_process"] and approver_calls == []
        kinds = sorted((r["record_kind"], r["executed"]) for r in _rows(store))
        assert kinds == [("contributor", 0), ("dispatch", 1)]
    finally:
        await store.close()


async def test_a_request_joining_an_uncertain_holder_does_not_wait(
    tmp_path: Path,
) -> None:
    store, dispatcher, (_signer, release, calls) = await _rig(tmp_path, True)
    try:
        holder = asyncio.create_task(
            dispatcher.dispatch(
                action="trip_relay",
                tier="D",
                context=_context(store, _Skill("protector", "D", ["trip_relay"])),
                result=_reasoning(),
            )
        )
        while not calls:
            await asyncio.sleep(0)
        # The holder's await is cancelled while its executor still drives: the
        # command is uncertain and its gate record never settles on its own.
        holder.cancel()
        await asyncio.gather(holder, return_exceptions=True)
        joined = await asyncio.wait_for(
            dispatcher.dispatch(
                action="trip_relay",
                tier="C",
                context=_context(store, _Skill("watcher", "C", ["trip_relay"])),
                result=_reasoning(),
            ),
            PROMPT,
        )
        assert joined.executed is False
        release.set()
        await dispatcher.drain_records(timeout=PROMPT)
        assert calls == ["trip_relay"]
    finally:
        await store.close()


async def test_a_coalesced_row_from_the_previous_release_is_a_legacy_contributor(
    tmp_path: Path,
) -> None:
    db = tmp_path / "state.db"
    conn = sqlite3.connect(str(db))
    conn.executescript(
        """
        CREATE TABLE action_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_name TEXT NOT NULL, tier TEXT NOT NULL, executed INTEGER NOT NULL,
            approved INTEGER, action_taken TEXT NOT NULL, operator_response TEXT,
            trigger_name TEXT NOT NULL, timestamp INTEGER NOT NULL
        );
        INSERT INTO action_log (action_name, tier, executed, action_taken,
                                trigger_name, timestamp)
        VALUES ('trip_relay', 'C', 1, 'coalesced', 't', 1),
               ('trip_relay', 'D', 1, 'trip_relay', 't', 1);
        """
    )
    conn.commit()
    conn.close()
    store = StateStore(str(db))
    await store.open()
    try:
        assert store._conn is not None
        kinds = store._conn.execute(
            "SELECT action_taken, record_kind, contributed_to FROM action_log"
            " ORDER BY id"
        ).fetchall()
        assert [tuple(k) for k in kinds] == [
            ("coalesced", "contributor_legacy", None),
            ("trip_relay", "dispatch", None),
        ]
    finally:
        await store.close()


@pytest.mark.parametrize(
    ("kind", "fields", "message"),
    [
        ("bogus", {}, "unknown action record kind"),
        ("dispatch", {"contributed_to": "k"}, "names no holder"),
        ("dispatch", {"contributed_to": None}, "is a contributor"),
        ("contributor_legacy", {"contributed_to": None}, "only ever migrated"),
        ("contributor", {"executed": True}, "performs nothing"),
        ("contributor", {"approved": True}, "performs nothing"),
        ("contributor", {"authority_json": "{}"}, "performs nothing"),
        ("contributor", {"attestation_status": "pending"}, "performs nothing"),
        ("contributor", {"action_taken": "trip_relay"}, "performs nothing"),
        ("contributor", {"contributed_to": ""}, "performs nothing"),
    ],
)
def test_the_writer_refuses_a_record_whose_shape_disagrees(
    kind: str, fields: dict[str, Any], message: str
) -> None:
    shape: dict[str, Any] = {
        "executed": False,
        "approved": None,
        "action_taken": "coalesced",
        "authority_json": None,
        "attestation_status": "",
        "contributed_to": "holder-key",
    }
    if kind == "dispatch":
        shape["contributed_to"] = None
    shape.update(fields)
    with pytest.raises(ValueError, match=message):
        _check_action_record_shape(kind, **shape)


async def test_a_fresh_table_refuses_a_contributor_that_claims_execution(
    tmp_path: Path,
) -> None:
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        assert store._conn is not None
        with pytest.raises(sqlite3.IntegrityError):
            store._conn.execute(
                "INSERT INTO action_log (action_name, tier, executed, action_taken,"
                " trigger_name, timestamp, record_kind, contributed_to)"
                " VALUES ('trip_relay', 'C', 1, 'coalesced', 't', 1, 'contributor',"
                " 'k')"
            )
    finally:
        await store.close()


async def test_a_contributor_cannot_be_marked_attested(tmp_path: Path) -> None:
    from ori.network.events import ActionResult

    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        row = await store.log_action(
            ActionResult(
                action_name="trip_relay",
                tier="C",
                executed=False,
                approved=None,
                action_taken="coalesced",
                timestamp=1,
            ),
            "t",
            record_kind="contributor",
            record_key="mine",
            contributed_to="holder",
        )
        with pytest.raises(ValueError, match="never attested"):
            await store.set_action_attestation(row, status="signed")
        await store.set_action_attestation(row, status="refused", reason="x")
    finally:
        await store.close()


async def test_a_holder_row_that_never_appeared_is_reported(tmp_path: Path) -> None:
    from ori.network.events import ActionResult

    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        await store.log_action(
            ActionResult(
                action_name="trip_relay",
                tier="C",
                executed=False,
                approved=None,
                action_taken="coalesced",
                timestamp=1,
            ),
            "t",
            record_kind="contributor",
            record_key="mine",
            contributed_to="a-holder-whose-row-was-lost",
        )
        summary = await store.get_attestation_summary()
        assert summary["contributor_links_unresolved"] == 1
    finally:
        await store.close()


async def test_reconciliation_refuses_a_contributor_found_pending(
    tmp_path: Path,
) -> None:
    """Never signed, never skipped silently: refused and reported."""
    from ori.network.events import ActionResult
    from ori.runtime import OriRuntime

    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        row = await store.log_action(
            ActionResult(
                action_name="trip_relay",
                tier="C",
                executed=False,
                approved=None,
                action_taken="coalesced",
                timestamp=1,
            ),
            "t",
            record_kind="contributor",
            record_key="mine",
            contributed_to="holder",
        )
        assert store._conn is not None
        # A corrupt row: nothing the runtime writes ever marks a contributor.
        store._conn.execute(
            "UPDATE action_log SET attestation_status = 'pending' WHERE id = ?", (row,)
        )
        store._conn.commit()
        signer = _Signer()
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = store
        runtime._evidence_attestor = signer  # type: ignore[assignment]
        await runtime._reconcile_pending_attestations()
        assert signer.signed == []
        status = store._conn.execute(
            "SELECT attestation_status, attestation_reason FROM action_log WHERE id = ?",
            (row,),
        ).fetchone()
        assert tuple(status) == ("refused", "not_a_dispatch_record")
    finally:
        await store.close()


async def test_a_roll_forward_reclassifies_joined_rows_a_rolled_back_release_wrote(
    tmp_path: Path,
) -> None:
    """The migration holds on every open, not only the first."""
    db = tmp_path / "state.db"
    store = StateStore(str(db))
    await store.open()
    await store.close()
    # The previous release, running after a rollback, writes a joined row with
    # its own INSERT, which names none of the new columns, and marks it for
    # attestation. The table this release created must accept that write.
    conn = sqlite3.connect(str(db))
    conn.execute(
        "INSERT INTO action_log (action_name, tier, executed, action_taken,"
        " trigger_name, timestamp, attestation_status)"
        " VALUES ('trip_relay', 'C', 1, 'coalesced', 't', 1, 'pending')"
    )
    conn.commit()
    conn.close()
    store = StateStore(str(db))
    await store.open()
    try:
        assert store._conn is not None
        row = store._conn.execute(
            "SELECT record_kind, attestation_status, attestation_reason"
            " FROM action_log WHERE action_taken = 'coalesced'"
        ).fetchone()
        assert tuple(row) == ("contributor_legacy", "refused", "legacy_contributor")
        index = store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'index'"
            " AND name = 'idx_action_log_record_key'"
        ).fetchone()
        assert index is not None
        assert (await store.get_actions_needing_attestation()) == []
    finally:
        await store.close()


async def test_a_holder_still_running_is_not_reported_missing(tmp_path: Path) -> None:
    store, dispatcher, (_signer, release, calls) = await _rig(tmp_path, True)
    try:
        holder = asyncio.create_task(
            dispatcher.dispatch(
                action="trip_relay",
                tier="D",
                context=_context(store, _Skill("protector", "D", ["trip_relay"])),
                result=_reasoning(),
            )
        )
        while not calls:
            await asyncio.sleep(0)
        await dispatcher.dispatch(
            action="trip_relay",
            tier="C",
            context=_context(store, _Skill("watcher", "C", ["trip_relay"])),
            result=_reasoning(),
        )
        await asyncio.sleep(0.05)
        # The holder is still driving its executor: neither row is written yet.
        assert _rows(store) == []
        assert (await store.get_attestation_summary())[
            "contributor_links_unresolved"
        ] == 0
        release.set()
        await asyncio.wait_for(holder, PROMPT)
        await dispatcher.drain_records(timeout=PROMPT)
        kinds = [r["record_kind"] for r in _rows(store)]
        assert kinds == ["dispatch", "contributor"], "the holder's row is first"
        assert (await store.get_attestation_summary())[
            "contributor_links_unresolved"
        ] == 0
    finally:
        await store.close()


async def test_a_dispatch_cancelled_at_the_gate_leaves_no_record_unsettled(
    tmp_path: Path,
) -> None:
    """Its record has no result to write, and must not wedge the writer."""
    store, dispatcher, (_signer, _release, calls) = await _rig(tmp_path, True)
    try:
        gate = dispatcher._resource_gate
        assert gate is not None
        await gate._lock.acquire()
        task = asyncio.create_task(
            dispatcher.dispatch(
                action="trip_relay",
                tier="D",
                context=_context(store, _Skill("protector", "D", ["trip_relay"])),
                result=_reasoning(),
            )
        )
        await asyncio.sleep(0.02)
        assert dispatcher.record_backlog()["unsettled"] >= 1
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        gate._lock.release()
        await dispatcher.drain_records(timeout=PROMPT)
        assert dispatcher.record_backlog()["unsettled"] == 0
        assert calls == []
    finally:
        await store.close()


async def test_only_a_dispatch_row_resolves_a_contributor_link(tmp_path: Path) -> None:
    """A contributor's own key is not a holder; a chain of contributors resolves nothing."""
    from ori.network.events import ActionResult

    joined = ActionResult(
        action_name="trip_relay",
        tier="C",
        executed=False,
        approved=None,
        action_taken="coalesced",
        timestamp=1,
    )
    store = StateStore(str(tmp_path / "state.db"))
    await store.open()
    try:
        await store.log_action(
            joined,
            "t",
            record_kind="contributor",
            record_key="k1",
            contributed_to="gone",
        )
        await store.log_action(
            joined, "t", record_kind="contributor", record_key="k2", contributed_to="k1"
        )
        summary = await store.get_attestation_summary()
        assert summary["contributor_links_unresolved"] == 2
    finally:
        await store.close()
