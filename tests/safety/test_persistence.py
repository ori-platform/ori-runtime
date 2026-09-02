# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The durable trip journal, round-tripped through the real machine.

Every load is judged by ZoneTripState itself: the store's derived durable
state and journal shape are correct exactly when the machine accepts them
and lands in the state the contract requires, so a divergence in either
direction raises rather than passing quietly.
"""

from pathlib import Path

import pytest

from ori.safety.trip_state import DurableStateError, ZoneTripState
from ori.state.store import StateStore, TripJournal

PAIR = ("main-distribution", "electrical.overcurrent.v1")


async def _append_intent(
    journal: TripJournal, zone_id: str = PAIR[0], *, attempt_id: str = "a-1"
) -> None:
    await journal.append_intent(
        zone_id,
        PAIR[1],
        attempt_id=attempt_id,
        binding_seq=4,
        outcome="open_protected_circuit",
        created_at_ms=1756684800000,
    )


@pytest.fixture
async def journal(tmp_path: Path):
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        yield TripJournal(store)
    finally:
        await store.close()


async def _load_machine(
    journal: TripJournal, *, binding_seq_in_force: int = 4
) -> ZoneTripState:
    durable_state, entries = await journal.load(*PAIR)
    machine = ZoneTripState(*PAIR)
    machine.startup(durable_state, entries, binding_seq_in_force=binding_seq_in_force)
    return machine


async def test_intent_only_loads_tripped_pending(journal: TripJournal) -> None:
    """The crash between command and record: the intent alone carries the
    latch, command_pending, retryable."""
    await _append_intent(journal)
    machine = await _load_machine(journal)
    assert machine.state == "tripped"
    assert machine.command_status == "command_pending"
    assert machine.outcome_retry().retry == "attempted"


async def test_record_commits_before_the_resolution_mark(journal: TripJournal) -> None:
    """The contract's write ordering, end to end: intent, record commit,
    then the mark — loading as the justified-resolution shape with the
    record's status governing."""
    await _append_intent(journal)
    await journal.append_record(*PAIR, command_status="command_issued", created_at_ms=1)
    await journal.mark_resolved(*PAIR)
    durable_state, entries = await journal.load(*PAIR)
    assert durable_state == "tripped"
    assert entries[0]["intent"]["resolved"] is True
    machine = await _load_machine(journal)
    assert machine.state == "tripped"
    assert machine.command_status == "command_issued"


async def test_crash_between_record_and_mark_is_benign(journal: TripJournal) -> None:
    """The mark never ran; the record still governs at load, resolving the
    older intent exactly as the corpus's record_resolves_only_older case."""
    await _append_intent(journal)
    await journal.append_record(*PAIR, command_status="command_issued", created_at_ms=1)
    machine = await _load_machine(journal)
    assert machine.state == "tripped"
    assert machine.command_status == "command_issued"


async def test_mark_without_a_record_resolves_nothing(journal: TripJournal) -> None:
    """The store is structurally unable to write an unwitnessed resolution:
    a mark with no committed record or clear is a no-op, and the intent
    still carries the latch."""
    await _append_intent(journal)
    await journal.mark_resolved(*PAIR)
    durable_state, entries = await journal.load(*PAIR)
    assert entries[0]["intent"]["resolved"] is False
    machine = await _load_machine(journal)
    assert machine.state == "tripped"
    assert machine.command_status == "command_pending"


async def test_mark_never_touches_intents_after_the_record(
    journal: TripJournal,
) -> None:
    """A second trip's intent appended after the record survives the mark
    unresolved and governs the load as command_pending."""
    await _append_intent(journal)
    await journal.append_record(*PAIR, command_status="command_issued", created_at_ms=1)
    await _append_intent(journal, attempt_id="a-2")
    await journal.mark_resolved(*PAIR)
    durable_state, entries = await journal.load(*PAIR)
    assert entries[0]["intent"]["resolved"] is True
    assert entries[2]["intent"]["resolved"] is False
    machine = await _load_machine(journal)
    assert machine.command_status == "command_pending"


async def test_clear_returns_the_pair_to_inactive(journal: TripJournal) -> None:
    """Reset's durable clear: record, clear, mark — the pair restarts
    inactive with the whole history justified."""
    await _append_intent(journal)
    await journal.append_record(*PAIR, command_status="command_issued", created_at_ms=1)
    await journal.mark_resolved(*PAIR)
    await journal.append_clear(*PAIR, created_at_ms=2)
    await journal.mark_resolved(*PAIR)
    durable_state, entries = await journal.load(*PAIR)
    assert durable_state is None
    machine = await _load_machine(journal)
    assert machine.state == "inactive"


async def test_binding_mismatch_survives_the_round_trip(journal: TripJournal) -> None:
    await _append_intent(journal)
    machine = await _load_machine(journal, binding_seq_in_force=9)
    assert machine.state == "tripped"
    assert machine.orphaned is True
    assert machine.outcome_retry().retry == "skipped"


async def test_pairs_enumeration_is_distinct_and_ordered(journal: TripJournal) -> None:
    await _append_intent(journal)
    await _append_intent(journal, "borehole-pump", attempt_id="b-1")
    await journal.append_record(*PAIR, command_status="command_issued", created_at_ms=1)
    assert await journal.pairs() == [
        ("borehole-pump", PAIR[1]),
        PAIR,
    ]


@pytest.mark.parametrize("status", ["", "none", "legacy", "executed"])
async def test_append_record_refuses_out_of_vocabulary_status(
    journal: TripJournal, status: str
) -> None:
    with pytest.raises(ValueError):
        await journal.append_record(*PAIR, command_status=status, created_at_ms=1)


async def test_malformed_record_row_refuses_at_load(journal: TripJournal) -> None:
    """A NULL-status record row injected beneath the API must refuse the
    journal at load, never launder into retryable legacy: the journal table
    has no legacy rows by construction, so a malformed current row is
    corruption."""
    await _append_intent(journal)
    store = journal._store
    assert store._conn is not None
    store._conn.execute(
        "INSERT INTO safety_trip_journal "
        "(zone_id, profile_id, entry_kind, created_at_ms) "
        "VALUES (?, ?, 'record', 1)",
        PAIR,
    )
    store._conn.commit()
    durable_state, entries = await journal.load(*PAIR)
    machine = ZoneTripState(*PAIR)
    with pytest.raises(DurableStateError):
        machine.startup(durable_state, entries)


async def test_empty_status_record_row_refuses_at_load(journal: TripJournal) -> None:
    """The empty-string sibling of the NULL row: a truthiness fallback would
    silently replace it, so it must refuse instead."""
    await _append_intent(journal)
    store = journal._store
    assert store._conn is not None
    store._conn.execute(
        "INSERT INTO safety_trip_journal "
        "(zone_id, profile_id, entry_kind, command_status, created_at_ms) "
        "VALUES (?, ?, 'record', '', 1)",
        PAIR,
    )
    store._conn.commit()
    durable_state, entries = await journal.load(*PAIR)
    machine = ZoneTripState(*PAIR)
    with pytest.raises(DurableStateError):
        machine.startup(durable_state, entries)
