# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The signing clock: gateway-api/v2 Senders for every runtime signer.

A value is issued only from a range whose claim committed, so no value repeats
in a run, across a restart, or between two clocks on one store; a stalled or
failing store refuses signing rather than blocking or signing uncovered.
"""

from __future__ import annotations

import ast
import sqlite3
import threading
from pathlib import Path
from typing import Any

import pytest

from ori.security.signing_clock import (
    MARK_CEILING,
    SigningClock,
    SigningClockUnavailableError,
    reservation_for_skew,
)
from tests.waiting import wait_until

ORI = Path(__file__).resolve().parent.parent / "ori"


class _Clock:
    def __init__(self, at_ms: int) -> None:
        self.at_ms = at_ms

    def __call__(self) -> int:
        return self.at_ms


class _Ticking(_Clock):
    """A wall clock that moves a millisecond each time it is read, so many
    issues do not outrun it as they would a clock standing still."""

    def __call__(self) -> int:
        self.at_ms += 1
        return self.at_ms


async def _ready(clock: SigningClock) -> None:
    await wait_until(lambda: bool(clock._ranges), what="the first claim to land")


def _claimed_past(clock: SigningClock, value: int | None) -> bool:
    ranges = clock._ranges
    return bool(ranges) and (value is None or ranges[-1][1] > value)


def _issue(clock: SigningClock, count: int) -> list[int]:
    return [clock.issue() for _ in range(count)]


def _stored_mark(db: Path) -> int | None:
    with sqlite3.connect(db) as connection:
        try:
            row = connection.execute(
                "SELECT mark_ms FROM gateway_signing_clock"
            ).fetchone()
        except sqlite3.OperationalError:
            return None  # The writer has not created its table yet.
    return None if row is None else int(row[0])


async def test_values_never_repeat_while_the_wall_clock_stands_still(tmp_path):
    wall = _Clock(1_000_000)
    clock = SigningClock(str(tmp_path / "state.db"), clock=wall)
    await _ready(clock)
    issued = _issue(clock, 400)
    assert issued == sorted(set(issued)) and len(issued) == 400
    # Every value issued is covered by the stored mark.
    assert max(issued) <= (_stored_mark(tmp_path / "state.db") or 0)
    clock.stop()


async def test_a_restart_issues_above_everything_the_last_run_claimed(tmp_path):
    db = tmp_path / "state.db"
    wall = _Clock(5_000_000)
    first = SigningClock(str(db), clock=wall)
    await _ready(first)
    before = _issue(first, 50)
    first.stop()
    # The clock stepped back across the restart, as a Pi with no battery does:
    # nothing is signed until it is back within a reservation of the mark.
    wall.at_ms = 1_000
    second = SigningClock(str(db), clock=wall)
    with pytest.raises(SigningClockUnavailableError):
        second.issue()
    # Back within a reservation of the stored mark.
    wall.at_ms = 5_001_000
    await _ready(second)
    after = _issue(second, 50)
    assert min(after) > max(before)
    second.stop()


async def test_two_clocks_on_one_store_never_issue_the_same_value(tmp_path):
    db = tmp_path / "state.db"
    wall = _Ticking(9_000_000)
    one = SigningClock(str(db), clock=wall, reservation_ms=20)
    two = SigningClock(str(db), clock=wall, reservation_ms=20)
    await _ready(one)
    await _ready(two)
    issued: list[int] = []
    for _ in range(200):
        for clock in (one, two):
            try:
                issued.append(clock.issue())
            except SigningClockUnavailableError:
                await wait_until(
                    lambda clock=clock: _claimed_past(clock, clock._last),
                    what="the next claim",
                )
    assert len(issued) == len(set(issued))
    one.stop()
    two.stop()


async def test_nothing_is_issued_before_the_first_claim_commits(tmp_path, monkeypatch):
    release = threading.Event()
    claims: list[int] = []
    original = SigningClock._claim

    def stalled(self: SigningClock, wanted: int) -> Any:
        claims.append(wanted)
        release.wait(30)
        return original(self, wanted)

    monkeypatch.setattr(SigningClock, "_claim", stalled)
    clock = SigningClock(str(tmp_path / "state.db"), clock=_Clock(1_000))
    await wait_until(lambda: claims, what="the first claim to start")
    with pytest.raises(SigningClockUnavailableError):
        clock.issue()
    assert clock.refusing()
    release.set()
    await _ready(clock)
    assert clock.issue() >= 1_000 and not clock.refusing()
    clock.stop()


async def test_a_stalled_claim_refuses_once_coverage_runs_out_and_never_doubles(
    tmp_path, monkeypatch
):
    wall = _Clock(2_000_000)
    clock = SigningClock(str(tmp_path / "state.db"), clock=wall, reservation_ms=10)
    await _ready(clock)
    release = threading.Event()
    in_flight = [0]
    peak = [0]
    original = SigningClock._claim

    def stalled(self: SigningClock, wanted: int) -> Any:
        in_flight[0] += 1
        peak[0] = max(peak[0], in_flight[0])
        release.wait(30)
        try:
            return original(self, wanted)
        finally:
            in_flight[0] -= 1

    monkeypatch.setattr(SigningClock, "_claim", stalled)
    claimed_to = clock._ranges[-1][1]
    issued: list[int] = []
    refused = 0
    for _ in range(100):
        try:
            issued.append(clock.issue())
        except SigningClockUnavailableError:
            refused += 1
    # Signed only within what was claimed, then refused at once, never blocked.
    assert issued and refused and max(issued) == claimed_to
    assert clock.refusing()
    release.set()
    # The issues ran ahead of a clock standing still; let it catch up.
    wall.at_ms += 1_000
    await wait_until(
        lambda: _claimed_past(clock, wall.at_ms), what="a claim past the moved clock"
    )
    assert peak[0] == 1
    assert clock.issue() > claimed_to and not clock.refusing()
    clock.stop()


async def test_a_late_lower_write_never_lowers_the_stored_mark(tmp_path):
    db = tmp_path / "state.db"
    clock = SigningClock(str(db), clock=_Clock(7_000_000))
    await _ready(clock)
    clock.stop()
    mark = _stored_mark(db)
    assert mark is not None
    # The claim's own statement, run late with a lower value.
    with sqlite3.connect(db) as connection:
        connection.execute(
            "INSERT INTO gateway_signing_clock (id, mark_ms) VALUES (1, ?) "
            "ON CONFLICT (id) DO UPDATE SET mark_ms = MAX("
            "gateway_signing_clock.mark_ms, excluded.mark_ms)",
            (mark - 500,),
        )
    assert _stored_mark(db) == mark


def test_a_store_that_cannot_open_refuses_every_signature(tmp_path):
    clock = SigningClock(str(tmp_path / "missing" / "state.db"))
    with pytest.raises(SigningClockUnavailableError):
        clock.issue()
    assert clock.refusing()
    clock.stop()
    assert clock._thread is not None and not clock._thread.is_alive()


async def test_the_mark_stays_inside_a_64_bit_column(tmp_path):
    clock = SigningClock(str(tmp_path / "state.db"), clock=_Clock(MARK_CEILING + 50))
    await _ready(clock)
    assert (_stored_mark(tmp_path / "state.db") or 0) <= MARK_CEILING
    clock.stop()


def test_without_a_store_values_still_never_repeat_in_the_process():
    clock = SigningClock(clock=_Clock(10))
    assert _issue(clock, 5) == [10, 11, 12, 13, 14]


def test_no_runtime_signer_chooses_its_own_signing_time():
    """Every runtime signer takes its time from the shared clock: a call to
    `.sign(...)` under ori/ passing `signed_at_ms` would bypass it."""
    offenders = []
    for path in ORI.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "sign"
                and any(k.arg == "signed_at_ms" for k in node.keywords)
            ):
                offenders.append(f"{path.relative_to(ORI.parent)}:{node.lineno}")
    assert offenders == []


async def test_the_mark_stays_inside_a_64_bit_column_across_restarts(tmp_path):
    db = tmp_path / "state.db"
    for _ in range(3):
        clock = SigningClock(str(db), clock=_Clock(MARK_CEILING))
        await wait_until(
            lambda: _stored_mark(db) is not None, what="the first claim to land"
        )
        clock.stop()
        assert (_stored_mark(db) or 0) <= MARK_CEILING


async def test_an_idle_signer_still_finds_a_claimed_value(tmp_path):
    """The writer claims ahead as the wall clock moves, not only on demand."""
    wall = _Clock(3_000_000)
    clock = SigningClock(str(tmp_path / "state.db"), clock=wall, reservation_ms=20)
    await _ready(clock)
    clock.issue()
    for _ in range(5):
        # Idle for many reservations: nothing signs meanwhile.
        wall.at_ms += 2_000
        await wait_until(
            lambda: clock._ranges[-1][1] >= wall.at_ms + 10,
            what="the writer to claim ahead of the moved wall clock",
        )
        assert clock.issue() >= wall.at_ms
        assert not clock.refusing()
    clock.stop()


async def test_a_store_locked_at_start_delays_nothing_and_recovers(
    tmp_path, monkeypatch
):
    db = tmp_path / "state.db"
    holder = sqlite3.connect(db, isolation_level=None)
    holder.execute("PRAGMA journal_mode = WAL")
    holder.execute("BEGIN IMMEDIATE")
    opened_on: list[int] = []
    real_connect = sqlite3.connect

    def connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        opened_on.append(threading.get_ident())
        return real_connect(*args, **kwargs)

    monkeypatch.setattr("ori.security.signing_clock.sqlite3.connect", connect)
    clock = SigningClock(str(db), clock=_Clock(4_000_000))
    # Construction touches no store, so a locked one cannot hold up a start.
    assert threading.get_ident() not in opened_on
    with pytest.raises(SigningClockUnavailableError):
        clock.issue()
    holder.execute("ROLLBACK")
    holder.close()
    await _ready(clock)
    assert clock.issue() >= 4_000_000 and not clock.refusing()
    clock.stop()


def test_the_runtime_sizes_the_reservation_from_the_skew():
    from ori.security.signing_clock import reservation_for_skew

    assert reservation_for_skew(300_000) == 30_000
    assert reservation_for_skew(20_000) == 2_000
    assert reservation_for_skew(2**53) == 30_000
    # Never more than half the skew, so the lead always passes the receiver.
    assert reservation_for_skew(1_000) == 500
    assert reservation_for_skew(1_500) == 750
    assert reservation_for_skew(0) == 1


@pytest.mark.parametrize("step_ms", [0, 100])
async def test_rapid_restarts_never_sign_more_than_a_reservation_ahead(
    tmp_path, monkeypatch, step_ms
):
    """A crash loop restarting faster than the wall clock moves, signing at
    each start: signing is refused before it runs further ahead."""
    db = tmp_path / "state.db"
    wall = _Clock(10_000_000)
    reservation = reservation_for_skew(300_000)
    bound = reservation + 1_000
    attempts = [0]
    original = SigningClock._claim

    def counted(self: SigningClock, wanted: int) -> Any:
        try:
            return original(self, wanted)
        finally:
            attempts[0] += 1

    monkeypatch.setattr(SigningClock, "_claim", counted)
    issued: list[int] = []
    refused = 0
    for _ in range(305):
        before = attempts[0]
        clock = SigningClock(str(db), clock=wall, reservation_ms=reservation)
        await wait_until(lambda: attempts[0] > before, what="a claim attempt")
        try:
            issued.append(clock.issue())
            assert issued[-1] - wall.at_ms <= bound
        except SigningClockUnavailableError:
            refused += 1
        clock.stop()
        wall.at_ms += step_ms
    assert issued == sorted(set(issued))
    assert max(issued) - wall.at_ms <= bound
    # Standing still, the crash loop runs out of room and is refused.
    assert refused > 0 if step_ms == 0 else True


async def test_a_failing_store_is_retried_at_its_own_pace(tmp_path, monkeypatch):
    """However often signers are refused, no claim is retried before its pause
    ends: with a pause longer than the test, the first attempt is the only one."""

    attempts = [0]

    def failing(self: SigningClock, wanted: int) -> None:
        attempts[0] += 1
        return None

    monkeypatch.setattr("ori.security.signing_clock._RETRY_S", 3_600.0)
    monkeypatch.setattr(SigningClock, "_claim", failing)
    clock = SigningClock(str(tmp_path / "state.db"), clock=_Clock(1_000))
    await wait_until(lambda: attempts[0] >= 1, what="the first claim attempt")
    for _ in range(200):
        with pytest.raises(SigningClockUnavailableError):
            clock.issue()
    # The writer is woken by each refusal; give it every chance to act on one.
    await wait_until(lambda: clock._refusing, what="the clock to report refusing")
    assert attempts[0] == 1
    clock.stop()


@pytest.mark.parametrize("mark", ["garbage", 1.5, None, 2**63 - 1])
async def test_a_corrupt_stored_mark_refuses_until_repaired(tmp_path, mark):
    db = tmp_path / "state.db"
    with sqlite3.connect(db) as connection:
        connection.execute(
            "CREATE TABLE gateway_signing_clock "
            "(id INTEGER PRIMARY KEY CHECK (id = 1), mark_ms)"
        )
        connection.execute("INSERT INTO gateway_signing_clock VALUES (1, ?)", (mark,))
    clock = SigningClock(str(db), clock=_Clock(2_000_000))
    with pytest.raises(SigningClockUnavailableError):
        clock.issue()
    assert clock._thread is not None and clock._thread.is_alive()
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE gateway_signing_clock SET mark_ms = 1000")
    await _ready(clock)
    assert clock.issue() > 1_000
    clock.stop()


@pytest.mark.parametrize("skew_ms", [1_000, 1_500, 20_000, 300_000])
async def test_every_signing_time_passes_a_receiver_under_the_same_skew(
    tmp_path, monkeypatch, skew_ms
):
    """Restarts with the wall clock moved a millisecond each time, at the
    smallest skew a configuration admits and others: every value issued is
    within the skew, so a matching receiver never refuses it as future."""
    db = tmp_path / "state.db"
    wall = _Clock(50_000_000)
    reservation = reservation_for_skew(skew_ms)
    attempts = [0]
    original = SigningClock._claim

    def counted(self: SigningClock, wanted: int) -> Any:
        try:
            return original(self, wanted)
        finally:
            attempts[0] += 1

    monkeypatch.setattr(SigningClock, "_claim", counted)
    issued: list[int] = []
    refused = 0
    for _ in range(40):
        before = attempts[0]
        clock = SigningClock(str(db), clock=wall, reservation_ms=reservation)
        await wait_until(lambda: attempts[0] > before, what="a claim attempt")
        for _ in range(3):
            try:
                issued.append(clock.issue() - wall.at_ms)
            except SigningClockUnavailableError:
                # Permitted: a start too soon after the last claims nothing.
                refused += 1
        clock.stop()
        wall.at_ms += 1
    assert issued and all(lead <= skew_ms for lead in issued)
    assert refused + len(issued) == 120


async def test_a_live_backward_clock_step_refuses_rather_than_signing_ahead(tmp_path):
    wall = _Clock(80_000_000)
    clock = SigningClock(str(tmp_path / "state.db"), clock=wall, reservation_ms=30_000)
    await _ready(clock)
    first = clock.issue()
    wall.at_ms -= 600_000
    with pytest.raises(SigningClockUnavailableError):
        clock.issue()
    assert clock.refusing()
    # Back within a reservation of what was issued: signing resumes above it.
    wall.at_ms = first - 29_000
    await wait_until(
        lambda: _claimed_past(clock, first), what="a claim past the issued value"
    )
    assert clock.issue() > first
    clock.stop()


def test_an_in_memory_database_is_not_a_durable_signing_store():
    from ori.security.signing_clock import durable_store

    assert durable_store(":memory:") is False
    assert durable_store("") is False and durable_store(None) is False
    assert durable_store("/var/lib/ori/state.db") is True
    clock = SigningClock(":memory:", clock=_Clock(10))
    assert clock.durable is False and clock._thread is None


def test_a_development_runtime_signs_nondurably_on_an_in_memory_database(
    monkeypatch, caplog
):
    """A hardened posture refuses this at config load (tests/test_config.py);
    a development one runs, saying the signing times are nondurable."""
    from types import SimpleNamespace

    from ori.config import DeviceConfig, GatewayConfig
    from ori.gateway.envelope_auth import build_gateway_envelope_state

    development: Any = SimpleNamespace(
        database_path=":memory:",
        gateway=GatewayConfig(
            enabled=True,
            broker_url="mqtt://broker.local",
            auth={"enabled": True, "shared_secret_env": "GATEWAY_SHARED_SECRET"},
        ),
        device=DeviceConfig(
            id="d", name="d", location="l", deployment_profile="development"
        ),
        security={},
    )
    with caplog.at_level("WARNING"):
        state = build_gateway_envelope_state(development)
    assert state is not None and state.signing_clock.durable is False
    assert state.replay_cache.persistent is False
    assert "nondurable" in caplog.text
    state.close()


async def test_two_clocks_through_an_alias_of_one_store_never_repeat(tmp_path):
    """SQLite serialises claims on the file itself, whatever name reaches it."""
    import os

    db = tmp_path / "state.db"
    alias = tmp_path / "alias.db"
    os.symlink(db, alias)
    wall = _Ticking(9_000_000)
    one = SigningClock(str(db), clock=wall, reservation_ms=20)
    await _ready(one)
    two = SigningClock(str(alias), clock=wall, reservation_ms=20)
    await _ready(two)
    issued: list[int] = []
    for _ in range(100):
        for clock in (one, two):
            try:
                issued.append(clock.issue())
            except SigningClockUnavailableError:
                await wait_until(
                    lambda clock=clock: _claimed_past(clock, clock._last),
                    what="the next claim",
                )
    assert len(issued) == len(set(issued))
    one.stop()
    two.stop()
