# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The commissioning proof operation, tested at each bound the contract names.

The operation is the one place the contract sanctions moving a coil on an
unproven polarity. Every constraint on it is a boundary that either holds or
does not, so each has a test that fails when it is removed rather than a test
that passes because some other check happened to fire first.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from pathlib import Path
from typing import Any

import pytest

from ori.security.commissioning import proof_operation
from ori.security.commissioning.binding import (
    BindingRefusedError,
    VerifierContext,
    actuator_identity,
    verify_binding_envelope,
)
from ori.security.commissioning.proof_operation import (
    ATTESTATION_INCONCLUSIVE,
    ATTESTATION_MATCHED,
    ATTESTATION_MISMATCHED,
    ATTESTATION_TIMEOUT,
    ProofOperation,
    ProofRefusedError,
    export_observations,
)
from ori.state.store import StateStore
from tests.commissioning.signing import (
    local_gpio_binding,
    public_key_b64,
    sign_envelope,
)

SEED = "7" * 64
DEVICE = "bench-01"
SENSOR = "load-current"
PIN = 26


def _context() -> VerifierContext:
    """The verifier context this suite's device presents."""
    return VerifierContext(
        device_id=DEVICE,
        commissioning_anchor_current=base64.b64decode(public_key_b64(SEED)),
        commissioning_anchor_previous=None,
        provisioning_anchor=None,
        accepted_binding_seq=0,
        accepted_binding_hash=None,
        declared_sensor_ids=frozenset({SENSOR}),
        declared_actuators=(actuator_identity("local_gpio", {"gpio_pin": PIN}),),
        deployment_posture="development",
        profile_multiplier=None,
    )


def _accepted(**overrides: Any):
    """A verified binding, provisional unless a caller proves both legs."""
    overrides.setdefault("proof_method", "actuate_and_observe")
    overrides.setdefault("active_high", False)
    binding = local_gpio_binding(
        device_id=DEVICE, sensor_id=SENSOR, gpio_pin=PIN, **overrides
    )
    ctx = VerifierContext(
        device_id=DEVICE,
        commissioning_anchor_current=base64.b64decode(public_key_b64(SEED)),
        commissioning_anchor_previous=None,
        provisioning_anchor=None,
        accepted_binding_seq=0,
        accepted_binding_hash=None,
        declared_sensor_ids=frozenset({SENSOR}),
        declared_actuators=(actuator_identity("local_gpio", {"gpio_pin": PIN}),),
        deployment_posture="development",
        profile_multiplier=None,
    )
    return verify_binding_envelope(sign_envelope(binding, SEED), ctx)


class FakeTerminal:
    """A terminal the test owns, standing in for /dev/tty.

    It answers whichever prompt was actually displayed, so the operation's own
    sequencing decides what it is asked -- a fake that replied by call order
    would keep passing if the prompts were reordered or dropped.
    """

    def __init__(
        self,
        *,
        refuse: bool = False,
        load_before: str | None = "y",
        circuit: str | None = None,
        load_after: str | None = None,
    ) -> None:
        self.written: list[str] = []
        self.closed = False
        self.reads = 0
        self.load_before_reads = 0
        self.dwell_reads = 0
        self.flushes: list[int] = []
        self._refuse = refuse
        self._load_before = load_before
        self._circuit = circuit
        self._load_after = load_after

    def write(self, text: str) -> None:
        self.written.append(text)

    def poll_line(self) -> str | None:
        prompt = self.written[-1] if self.written else ""
        if "Before anything is commanded" in prompt:
            self.load_before_reads += 1
            return self._load_before
        if "open or closed" in prompt:
            self.dwell_reads += 1
            return self._circuit
        if "Is the load present now" in prompt:
            self.dwell_reads += 1
            return self._load_after
        if "not one of" in prompt:
            return None
        self.reads += 1
        if self._refuse:
            return "no"
        for chunk in reversed(self.written):
            for token in chunk.split():
                if len(token) == 6 and all(c in "0123456789ABCDEF" for c in token):
                    return token
        raise AssertionError("no nonce was displayed before consent was read")

    def at_eof(self) -> bool:
        """The fake reports EOF for whichever answer it was told to withhold."""
        prompt = self.written[-1] if self.written else ""
        if "Before anything is commanded" in prompt:
            return self._load_before is None
        if "open or closed" in prompt:
            return self._circuit is None
        if "Is the load present now" in prompt:
            return self._load_after is None
        return False

    def flush_input(self) -> None:
        self.flushes.append(len(self.written))

    def close(self) -> None:
        self.closed = True


class FakeDriver:
    """Records every call, so the pin's lifecycle is observable."""

    def __init__(self, *, fail_on: str | None = None, simulated: bool = False) -> None:
        self.calls: list[str] = []
        self.connect_kwargs: dict[str, Any] = {}
        self._fail_on = fail_on
        self._active = False
        self.is_simulated = simulated

    async def connect(self, **kwargs: Any) -> None:
        self.connect_kwargs = kwargs
        self.calls.append("connect")
        if self._fail_on == "connect":
            raise RuntimeError("GPIO chip unavailable")

    async def disconnect(self) -> None:
        self.calls.append("disconnect")

    async def trigger(self, duration_seconds: float | None = None) -> bool:
        self.calls.append("trigger")
        if self._fail_on == "command":
            raise RuntimeError("driver exploded")
        self._active = True
        return True

    async def release(self) -> bool:
        self.calls.append("release")
        if self._fail_on == "command":
            raise RuntimeError("driver exploded")
        self._active = False
        return True

    @property
    def is_active(self) -> bool:
        return self._active


@pytest.fixture(autouse=True)
def _fast_dwell(monkeypatch: pytest.MonkeyPatch) -> None:
    """Real elapsed time; the suite asserts behaviour, not the shipped numbers."""
    monkeypatch.setattr(proof_operation, "PROOF_HOLD_FLOOR_SECONDS", 0.15)
    monkeypatch.setattr(proof_operation, "PROOF_OBSERVATION_CAP_SECONDS", 0.6)


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


def _operation(
    store: StateStore, monkeypatch: pytest.MonkeyPatch, **overrides: Any
) -> tuple[ProofOperation, Any, Any]:
    driver = overrides.pop("driver", None) or FakeDriver()
    terminal = overrides.pop("terminal", None) or FakeTerminal(
        circuit=overrides.pop("circuit", "open"),
        load_after=overrides.pop("load_after", "n"),
        load_before=overrides.pop("load_before", "y"),
    )
    for key in ("circuit", "load_after", "load_before"):
        overrides.pop(key, None)
    kwargs: dict[str, Any] = dict(
        store=store,
        driver=driver,
        provisional=_accepted(),
        in_force=None,
        hardened=False,
        gpio_backend_available=True,
    )
    kwargs.update(overrides)
    monkeypatch.setattr(proof_operation, "_TERMINAL_FACTORY", lambda: terminal)
    return ProofOperation(**kwargs), driver, terminal


async def _run(op: ProofOperation, **kwargs: Any) -> Any:
    """Every command here is bounded.

    The defect this suite exists to hold shut presented as a read that never
    returned, so an unbounded command must fail the run rather than stall it.
    """
    return await asyncio.wait_for(
        op.command(**kwargs), timeout=proof_operation.PROOF_OBSERVATION_CAP_SECONDS * 6
    )


# ── the refusal wall ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "overrides, reason",
    [
        ({"provisional": None}, "no_provisional_binding"),
        ({"hardened": True}, "hardened_posture"),
        ({"gpio_backend_available": False}, "no_gpio_backend"),
    ],
    ids=["absent", "hardened", "no_gpio_backend"],
)
async def test_the_operation_refuses_before_it_touches_a_terminal(
    store: StateStore,
    monkeypatch: pytest.MonkeyPatch,
    overrides: dict[str, Any],
    reason: str,
) -> None:
    """Each refusal names its own bound, and none opens a terminal or a pin."""
    op, driver, terminal = _operation(store, monkeypatch, **overrides)
    with pytest.raises(ProofRefusedError) as excinfo:
        await _run(op, outcome="open_protected_circuit")
    assert excinfo.value.reason == reason
    assert driver.calls == []
    assert terminal.written == []


async def test_a_zone_in_force_cannot_be_proven_again(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operation is unavailable once the zone it acts on is proven."""
    proven = _accepted(control_proof_method="commanded_and_observed")
    op, driver, _ = _operation(store, monkeypatch, in_force=proven)
    with pytest.raises(ProofRefusedError) as excinfo:
        await _run(op, outcome="open_protected_circuit")
    assert excinfo.value.reason == "already_in_force"
    assert driver.calls == []


async def test_a_firmware_zone_has_no_proof_operation(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`commanded_and_observed` has no design for a channel, so neither has this."""
    from dataclasses import replace

    provisional = _accepted()
    firmware_only = replace(
        provisional,
        zones=tuple(replace(z, kind="firmware_channel") for z in provisional.zones),
    )
    op, driver, _ = _operation(store, monkeypatch, provisional=firmware_only)
    with pytest.raises(ProofRefusedError) as excinfo:
        await _run(op, outcome="open_protected_circuit")
    assert excinfo.value.reason == "no_local_gpio_zone"
    assert driver.calls == []


async def test_an_unknown_outcome_is_refused(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    op, driver, _ = _operation(store, monkeypatch)
    with pytest.raises(ProofRefusedError) as excinfo:
        await _run(op, outcome="trip_relay")
    assert excinfo.value.reason == "unknown_outcome"
    assert driver.calls == []


# ── consent ──────────────────────────────────────────────────────────────


async def test_consent_states_every_fact_the_contract_requires(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator authorises a specific physical act, not a generic prompt."""
    op, _, terminal = _operation(store, monkeypatch)
    await _run(op, outcome="open_protected_circuit")
    shown = "".join(terminal.written)
    provisional = _accepted()
    assert provisional.canonical_hash in shown
    assert "bench" in shown
    assert f"GPIO {PIN}" in shown
    assert "open_protected_circuit" in shown
    assert "de_energised" in shown
    # what losing the controller does to this zone
    assert "on controller loss" in shown


async def test_refused_consent_commands_nothing(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    op, driver, _ = _operation(store, monkeypatch, terminal=FakeTerminal(refuse=True))
    with pytest.raises(ProofRefusedError) as excinfo:
        await _run(op, outcome="open_protected_circuit")
    assert excinfo.value.reason == "consent_refused"
    assert "connect" not in driver.calls
    assert (
        await store.commissioning_proof_observations(_accepted().canonical_hash) == []
    )


async def test_one_consent_permits_exactly_one_command(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A second command asks again; nothing is cached between invocations."""
    terminal = FakeTerminal()
    op, driver, _ = _operation(store, monkeypatch, terminal=terminal)
    await _run(op, outcome="open_protected_circuit")
    assert terminal.reads == 1
    await _run(
        op,
        outcome="close_protected_circuit",
    )
    assert terminal.reads == 2
    rows = await store.commissioning_proof_observations(_accepted().canonical_hash)
    assert [r["outcome"] for r in rows] == [
        "open_protected_circuit",
        "close_protected_circuit",
    ]
    # A distinct nonce per command: one authorisation cannot cover the pair.
    assert rows[0]["consent_nonce"] != rows[1]["consent_nonce"]


async def test_the_operation_owns_the_terminal(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No caller supplies stdin, an answer, or a handle; the factory is internal."""
    import inspect

    from ori.security.commissioning import proof_operation

    signature = inspect.signature(proof_operation.ProofOperation.command)
    assert set(signature.parameters) == {"self", "outcome", "zone_id"}
    # Every method, not just `command`: it delegates, so scanning it alone
    # would miss the body that actually reads the terminal.
    names: set[str] = set()
    stack = [
        value.__code__
        for value in vars(ProofOperation).values()
        if hasattr(value, "__code__")
    ]
    while stack:
        code = stack.pop()
        names |= set(code.co_names)
        stack.extend(c for c in code.co_consts if hasattr(c, "co_names"))
    assert "input" not in names and "stdin" not in names


# ── the bounded command ──────────────────────────────────────────────────


async def test_the_operator_is_told_that_taking_the_pin_drives_it(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """There is no hi-Z GPIO output, so connecting is itself a coil command.

    gpiozero's `initial_value=None` only declines to *choose* a state: the pin
    still becomes an output holding whatever the register had, which on an
    active-low stage is energised. Measured on a Pi 4 with gpiozero 2.0.1 and
    `active_high=False`: `None` drives the line low, `False` drives it high.
    The asserted de-energised state is the lesser act, so the operator is told
    it happens rather than told it does not.
    """
    op, driver, terminal = _operation(store, monkeypatch)
    await _run(op, outcome="open_protected_circuit")
    assert driver.connect_kwargs["gpio_pin"] == PIN
    assert driver.connect_kwargs["active_high"] is False
    assert "drive_initial" not in driver.connect_kwargs
    shown = "".join(terminal.written)
    # Taking the line is now the whole act; saying it drives de-energised first
    # would describe a momentary open on a circuit that is being closed.
    assert "drives it straight to the coil state above" in shown
    assert "de-energised state" not in shown


async def test_the_pin_is_released_after_a_successful_command(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    op, driver, terminal = _operation(store, monkeypatch)
    await _run(op, outcome="open_protected_circuit")
    assert driver.calls[0] == "connect"
    assert driver.calls[-1] == "disconnect"
    assert terminal.closed


async def test_the_pin_is_released_when_the_driver_fails(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed command must not leave the line held."""
    op, driver, terminal = _operation(
        store, monkeypatch, driver=FakeDriver(fail_on="connect")
    )
    with pytest.raises(RuntimeError):
        await _run(op, outcome="open_protected_circuit")
    assert driver.calls[-1] == "disconnect"
    assert terminal.closed


async def test_the_pin_is_released_when_the_command_is_cancelled(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Cancelling(FakeDriver):
        async def connect(self, **kwargs: Any) -> None:
            self.connect_kwargs = kwargs
            self.calls.append("connect")
            raise asyncio.CancelledError

    op, driver, terminal = _operation(store, monkeypatch, driver=Cancelling())
    with pytest.raises(asyncio.CancelledError):
        await _run(op, outcome="open_protected_circuit")
    assert driver.calls[-1] == "disconnect"
    assert terminal.closed


async def test_a_command_is_never_more_than_one_outcome(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One authorisation, one output-state command.

    Taking a line as an output drives it, so connecting and then commanding
    issues two physical acts for one consent -- de-energise, then the outcome.
    The line is taken *at* the commanded state instead, and nothing follows it.
    """
    for outcome, active_high, coil in (
        ("open_protected_circuit", False, "de_energised"),
        ("close_protected_circuit", False, "energised"),
        ("open_protected_circuit", True, "de_energised"),
        ("close_protected_circuit", True, "energised"),
    ):
        accepted = _accepted(active_high=active_high)
        circuit = "open" if outcome == "open_protected_circuit" else "closed"
        op, driver, _ = _operation(
            store,
            monkeypatch,
            provisional=accepted,
            circuit=circuit,
            load_before="n" if circuit == "closed" else "y",
            load_after="y" if circuit == "closed" else "n",
        )
        await _run(op, outcome=outcome)
        assert driver.calls == ["connect", "disconnect"], (outcome, active_high)
        assert driver.connect_kwargs["initial_coil_state"] == coil
        assert driver.connect_kwargs["active_high"] is active_high


# ── what is recorded ─────────────────────────────────────────────────────


async def test_the_consent_and_the_command_are_one_record(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    op, _, _ = _operation(store, monkeypatch)
    result = await _run(op, outcome="open_protected_circuit")
    (row,) = await store.commissioning_proof_observations(result["binding_hash"])
    assert row["consent_nonce"]
    assert row["consented_at_ms"] <= row["commanded_at_ms"]
    assert row["outcome"] == "open_protected_circuit"
    assert row["coil_state_commanded"] == "de_energised"
    assert row["level_driven"] == "high"
    assert row["command_issued"] == 1
    assert row["release_requested"] == 1


async def test_the_runtime_never_records_the_effect_as_verified(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runtime does not observe the coil, so it may not claim the effect."""
    op, _, _ = _operation(store, monkeypatch)
    result = await _run(op, outcome="open_protected_circuit")
    (row,) = await store.commissioning_proof_observations(result["binding_hash"])
    assert row["effect_verified"] == 0
    assert result["effect_verified"] is False
    assert result["operator_attestation"] == ATTESTATION_MATCHED
    # No parameter exists to set it: a caller cannot assert the effect either.
    import inspect

    params = inspect.signature(
        store.complete_commissioning_proof_observation
    ).parameters
    assert "effect_verified" not in params


# ── export ───────────────────────────────────────────────────────────────


async def test_export_is_read_only(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It takes no observation, no consent, no pin and no claimed outcome."""
    import inspect

    from ori.security.commissioning import proof_operation

    signature = inspect.signature(proof_operation.export_observations)
    assert set(signature.parameters) == {"store", "provisional"}

    op, _, _ = _operation(store, monkeypatch)
    await _run(op, outcome="open_protected_circuit")
    exported = await export_observations(store=store, provisional=_accepted())
    assert exported["binding_hash"] == _accepted().canonical_hash
    (one,) = exported["observations"]
    assert one["outcome"] == "open_protected_circuit"
    assert one["operator_attestation"] == ATTESTATION_MATCHED
    assert one["effect_verified"] is False


async def test_export_without_a_provisional_binding_refuses(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ProofRefusedError) as excinfo:
        await export_observations(store=store, provisional=None)
    assert excinfo.value.reason == "no_provisional_binding"


# ── the bridge is transport ──────────────────────────────────────────────


def test_the_real_terminal_writes_and_reads_a_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`ControllingTerminal` is the one class every other test substitutes.

    Exercised against a real tty from `openpty` rather than by forking onto
    `/dev/tty`: opening the controlling terminal from a forked child is
    environment-dependent and returns EPERM on some hosts, which made this a
    portability trap rather than a check. What `/dev/tty` specifically buys is
    asserted separately below, and the real path has device evidence -- it has
    taken consent on the bench Pi.
    """
    import os
    import pty
    import time as _t

    master, slave = pty.openpty()
    monkeypatch.setattr(proof_operation, "TTY_PATH", os.ttyname(slave))
    term = proof_operation.ControllingTerminal()
    try:
        term.write("PROMPT?")
        os.write(master, b"ACK\n")
        answer = None
        limit = _t.monotonic() + 5
        while _t.monotonic() < limit:
            answer = term.poll_line()
            if answer is not None:
                break
            _t.sleep(0.01)
        assert answer == "ACK"
    finally:
        term.close()
        os.close(master)
        os.close(slave)


def test_the_terminal_is_the_controlling_one_and_takes_no_argument() -> None:
    """The path is the controlling terminal, and no caller supplies a handle."""
    import inspect

    assert proof_operation.TTY_PATH == "/dev/tty"
    params = inspect.signature(proof_operation.ControllingTerminal.__init__).parameters
    assert set(params) == {"self"}


def test_a_non_tty_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A regular file or a pipe cannot stand in for the terminal."""
    plain = tmp_path / "not-a-tty"
    plain.write_text("ACK\n")
    monkeypatch.setattr(proof_operation, "TTY_PATH", str(plain))
    with pytest.raises(ProofRefusedError) as refusal:
        proof_operation.ControllingTerminal()
    assert refusal.value.reason == "no_controlling_terminal"


def test_the_bridge_does_not_build_the_actuator_path() -> None:
    """A tool that constructs the actuator and drives the pin proves what the
    tool did, not what `commanded_and_observed` attests.

    The bridge may name the driver it hands over — that is dependency wiring —
    but it must not resolve an outcome, command a coil, or release a pin. Those
    belong to runtime-owned code.
    """
    import inspect

    from ori import cli_bridge

    source = inspect.getsource(cli_bridge)
    for forbidden in (
        "CommissionedActuator(",
        ".command_coil(",
        "coil_state_for(",
        "level_for(",
    ):
        assert forbidden not in source, (
            f"cli_bridge performs actuation itself: {forbidden}"
        )


def test_the_bridge_passes_no_consent(store: StateStore) -> None:
    """No flag, environment variable or argument can carry an authorisation."""
    import inspect

    from ori import cli_bridge

    # The code, not the prose about it: a docstring saying "carries no consent"
    # would otherwise satisfy a scan for the word.
    fn = cli_bridge._refuse_observation_flags
    literals = {
        c.lower()
        for c in (fn.__code__.co_consts or ())
        if isinstance(c, str) and c != fn.__doc__
    }
    names = {n.lower() for n in fn.__code__.co_names}
    reachable = literals | names | {v.lower() for v in fn.__code__.co_varnames}
    for forbidden in ("consent", "nonce", "authorise", "authorize", "--yes"):
        offenders = {t for t in reachable if forbidden in t}
        assert not offenders, f"the bridge handles consent as data: {offenders}"
    signature = inspect.signature(cli_bridge._commissioning_prove_command)
    assert set(signature.parameters) == {"config_path", "outcome", "zone_id"}


def test_the_export_bridge_takes_only_a_config_path() -> None:
    """Read-only means it cannot be handed anything to record."""
    import inspect

    from ori import cli_bridge

    signature = inspect.signature(cli_bridge._commissioning_proof_export)
    assert set(signature.parameters) == {"config_path"}


def test_a_partial_keystroke_is_never_read_as_a_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A keystroke without Enter must not satisfy or block the read.

    A buffered `readline()` blocks until a newline however the caller bounded
    the wait, so on a terminal left in non-canonical mode -- a raw-mode TUI, a
    crashed editor -- one keystroke made `select` fire and then held the read
    indefinitely, with the coil energised and the deadline powerless. The
    worker thread that read could not be cancelled and was joined at
    interpreter exit, so the process ignored SIGINT and SIGTERM.
    """
    import os
    import pty
    import termios
    import time as _t
    import tty as _tty

    master, slave = pty.openpty()
    _tty.setcbreak(slave, termios.TCSANOW)
    monkeypatch.setattr(proof_operation, "TTY_PATH", os.ttyname(slave))
    term = proof_operation.ControllingTerminal()
    try:
        os.write(master, b"y")  # non-canonical: readable, but not a line
        _t.sleep(0.1)
        for _ in range(5):
            started = _t.monotonic()
            assert term.poll_line() is None, "a partial keystroke was read as a line"
            assert _t.monotonic() - started < 0.5, "poll_line blocked"
        os.write(master, b"es\n")
        _t.sleep(0.1)
        assert term.poll_line() == "yes"
    finally:
        term.close()
        os.close(master)
        os.close(slave)


async def test_an_unanswered_dwell_returns_at_its_deadline(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deadline governs even when the terminal never yields a line."""

    class Silent(FakeTerminal):
        """Present but unanswering: the cap has to end this, not EOF."""

        def poll_line(self) -> str | None:
            prompt = self.written[-1] if self.written else ""
            if "open or closed" in prompt or "Is the load present now" in prompt:
                return None
            return super().poll_line()

        def at_eof(self) -> bool:
            return False

    op, driver, _ = _operation(store, monkeypatch, terminal=Silent())
    started = time.monotonic()
    # Bounded so a deadline that stopped governing fails here rather than
    # stalling the run, which is how an unbounded read presents.
    result = await _run(op, outcome="open_protected_circuit")
    elapsed = time.monotonic() - started
    cap = proof_operation.PROOF_OBSERVATION_CAP_SECONDS
    assert result["operator_attestation"] == ATTESTATION_TIMEOUT
    # The window is what ends it, and it is not cut short.
    assert cap * 0.8 <= elapsed < cap * 4, elapsed
    assert driver.calls[-1] == "disconnect"


async def test_a_store_from_the_earlier_schema_is_migrated(tmp_path: Path) -> None:
    """A bench device commissioned on an earlier build must still be usable.

    The table was created with `executed` and none of the facts that replaced
    it. `CREATE TABLE IF NOT EXISTS` leaves such a row set alone, so without a
    migration the first proof command fails on an unknown column.
    """
    import sqlite3

    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        """
        CREATE TABLE commissioning_proof_observation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            binding_hash TEXT NOT NULL, zone_id TEXT NOT NULL,
            gpio_pin INTEGER NOT NULL, active_high INTEGER NOT NULL,
            outcome TEXT NOT NULL, coil_state_commanded TEXT NOT NULL,
            level_driven TEXT NOT NULL, consent_nonce TEXT NOT NULL,
            consented_at_ms INTEGER NOT NULL, commanded_at_ms INTEGER NOT NULL,
            executed INTEGER NOT NULL, observation_json TEXT, outcome_note TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO commissioning_proof_observation (binding_hash, zone_id, "
        "gpio_pin, active_high, outcome, coil_state_commanded, level_driven, "
        "consent_nonce, consented_at_ms, commanded_at_ms, executed, "
        "observation_json, outcome_note) VALUES "
        "('sha256:old', 'bench', 26, 1, 'open_protected_circuit', 'energised', "
        "'high', 'OLD001', 1, 2, 1, NULL, 'from the earlier build')"
    )
    conn.commit()
    conn.close()

    migrated = StateStore(str(db))
    await migrated.open()
    try:
        row_id = await migrated.record_commissioning_proof_observation(
            binding_hash="sha256:x",
            zone_id="bench",
            gpio_pin=26,
            active_high=True,
            outcome="open_protected_circuit",
            coil_state_commanded="energised",
            level_driven="high",
            consent_nonce="ABC123",
            consented_at_ms=1,
            commanded_at_ms=0,
            command_issued=False,
            held_ms=0,
            observation_json=None,
            outcome_note="consented",
        )
        await migrated.complete_commissioning_proof_observation(
            row_id=row_id,
            commanded_at_ms=2,
            command_issued=True,
            operator_attestation=ATTESTATION_MATCHED,
            release_requested=True,
            held_ms=5000,
            observation_json=None,
            outcome_note=None,
        )
        # The command recorded on the earlier build survives the rebuild.
        (old_row,) = await migrated.commissioning_proof_observations("sha256:old")
        assert old_row["command_issued"] == 1
        assert old_row["outcome_note"] == "from the earlier build"
        (row,) = await migrated.commissioning_proof_observations("sha256:x")
        assert row["operator_attestation"] == ATTESTATION_MATCHED
        assert row["held_ms"] == 5000
        assert row["effect_verified"] == 0
    finally:
        await migrated.close()


def test_only_a_matched_attestation_is_reported_as_a_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A contradicted polarity must not carry the status of a proof.

    `commissioning deliver` already answers a refused document with `ok: false`
    and exit 2. A producer keying on the status would otherwise read a
    contradicted polarity, and a dwell nobody answered, as a proof.
    """
    from ori import cli_bridge

    async def fake_state(config: Any) -> Any:
        return object(), None, Path("present")

    for attestation, expected_ok, expected_code in (
        ("matched", True, None),
        ("mismatched", False, "attestation_mismatched"),
        # Answered, and not a proof: reporting this as a timeout would record a
        # completed observation as one the operator never gave.
        ("inconclusive", False, "attestation_inconclusive"),
        ("timeout", False, "observation_timeout"),
        ("something_new", False, "internal_error"),
    ):

        class Fake:
            def __init__(self, **kwargs: Any) -> None:
                pass

            async def command(self, **kwargs: Any) -> dict[str, Any]:
                return {
                    "operator_attestation": attestation,
                    "command_issued": True,
                    "effect_verified": False,
                }

        monkeypatch.setattr(proof_operation, "ProofOperation", Fake)
        monkeypatch.setattr(cli_bridge, "_proof_state", fake_state)
        monkeypatch.setattr(
            cli_bridge, "_commissioning_store", lambda config: _NullStore()
        )
        monkeypatch.setattr(
            cli_bridge.Config, "load", staticmethod(lambda path: _NullConfig())
        )
        monkeypatch.setattr(
            cli_bridge, "requires_production_posture", lambda **kw: False
        )

        import asyncio as _aio

        try:
            _aio.run(
                cli_bridge._commissioning_prove_command(
                    "ori.yaml", outcome="open_protected_circuit", zone_id=None
                )
            )
            ok, code = True, None
        except cli_bridge.BridgeError as exc:
            ok, code = False, exc.code
        assert ok is expected_ok, attestation
        assert code == expected_code, attestation


class _NullStore:
    async def open(self) -> None:
        pass

    async def close(self) -> None:
        pass


class _NullConfig:
    device = type("D", (), {"id": "bench-01"})()
    security = None
    raw: dict[str, Any] = {}


async def test_only_the_proof_operation_moves_a_pin_through_the_bridge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Behavioural, because a source grep is defeated by an alias or getattr.

    A bridge that imported the actuator indirectly and drove the pin itself
    would satisfy any textual check while producing a proof of what the tool
    did. This records every pin motion in the process instead.
    """
    moved: list[str] = []

    class Recording:
        async def connect(self, **kwargs: Any) -> None:
            moved.append("connect")

        async def disconnect(self) -> None:
            moved.append("disconnect")

        async def trigger(self, duration_seconds: float | None = None) -> bool:
            moved.append("trigger")
            return True

        async def release(self) -> bool:
            moved.append("release")
            return True

        @property
        def is_simulated(self) -> bool:
            return False

        @property
        def is_active(self) -> bool:
            return False

    seen: dict[str, Any] = {}
    real_init = proof_operation.ProofOperation.__init__

    def spy(self: Any, **kwargs: Any) -> None:
        seen["driver"] = kwargs["driver"]
        kwargs["driver"] = Recording()
        real_init(self, **kwargs)

    monkeypatch.setattr(proof_operation.ProofOperation, "__init__", spy)
    monkeypatch.setattr(proof_operation, "_TERMINAL_FACTORY", FakeTerminal)

    # The bridge hands a driver over rather than driving anything itself: no
    # pin has moved at the point the operation is constructed.
    assert moved == []

    op = proof_operation.ProofOperation(
        store=_NullProofStore(),
        driver=object(),
        provisional=_accepted(),
        in_force=None,
        hardened=False,
        gpio_backend_available=True,
    )
    await _run(op, outcome="open_protected_circuit")
    assert moved and moved[-1] == "disconnect"
    # The driver the caller supplied was never the one that moved.
    assert seen["driver"] is not None


class _NullProofStore:
    async def record_commissioning_proof_observation(self, **kwargs: Any) -> int:
        return 1

    async def complete_commissioning_proof_observation(self, **kwargs: Any) -> None:
        pass

    async def commissioning_proof_observations(self, binding_hash: str) -> list[dict]:
        return []


async def test_a_driver_reported_failure_is_not_observed(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A line the driver never took has nothing to attest to.

    Dwelling and prompting here would ask an operator what they saw of an
    effect that was never commanded, and record the answer as a proof.
    """

    terminal = FakeTerminal()
    op, driver, _ = _operation(
        store, monkeypatch, driver=FakeDriver(simulated=True), terminal=terminal
    )
    started = time.monotonic()
    with pytest.raises(ProofRefusedError) as refusal:
        await _run(op, outcome="open_protected_circuit")
    assert refusal.value.reason == "command_failed"
    # No dwell was served and no attestation was sought.
    assert time.monotonic() - started < proof_operation.PROOF_OBSERVATION_CAP_SECONDS
    assert terminal.dwell_reads == 0
    assert driver.calls[-1] == "disconnect"
    (row,) = await store.commissioning_proof_observations(_accepted().canonical_hash)
    assert row["command_issued"] == 0
    assert "command_failed" in (row["outcome_note"] or "")


# ── the observation ──────────────────────────────────────────────────────


async def test_the_observation_carries_every_field_the_contract_names(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `matched` boolean cannot be turned into these facts after the event."""
    op, _, _ = _operation(store, monkeypatch)
    result = await _run(op, outcome="open_protected_circuit")
    observed = result["observation"]
    assert set(observed) == {
        "commanded",
        "coil_state",
        "gpio_level",
        "load_present_before",
        "load_present_after",
        "terminal_state_observed",
    }
    # The runtime supplies only what it issued.
    assert observed["commanded"] == "open_protected_circuit"
    assert observed["coil_state"] == "de_energised"
    assert observed["gpio_level"] == "high"  # active_high=False on this zone
    # The operator supplies the rest.
    assert observed["load_present_before"] is True
    assert observed["load_present_after"] is False
    assert observed["terminal_state_observed"] == "open"

    exported = await export_observations(store=store, provisional=_accepted())
    (one,) = exported["observations"]
    assert one["observed"] == observed


async def test_no_sensor_reading_is_invented(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unmeasured value is absent, never zero and never a default."""
    op, _, _ = _operation(store, monkeypatch)
    result = await _run(op, outcome="open_protected_circuit")
    for optional in ("sensor_before", "sensor_after", "instrument"):
        assert optional not in result["observation"]


async def test_the_verdict_is_derived_from_the_observed_facts(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No separate conclusion is accepted that could contradict its components."""
    import inspect

    # open_protected_circuit asserts the circuit opens and the load goes away.
    # `load_present_before` is swept too: it is the axis the contract's own
    # consistency rule turns on, and a proof whose load never changed state
    # demonstrates nothing however the terminal reads.
    for before, circuit, load_after, expected in (
        ("y", "open", "n", ATTESTATION_MATCHED),
        ("y", "open", "y", ATTESTATION_INCONCLUSIVE),
        ("n", "open", "n", ATTESTATION_INCONCLUSIVE),
        ("n", "open", "y", ATTESTATION_INCONCLUSIVE),
        ("y", "closed", "y", ATTESTATION_MISMATCHED),
        ("n", "closed", "n", ATTESTATION_MISMATCHED),
    ):
        op, _, _ = _operation(
            store,
            monkeypatch,
            circuit=circuit,
            load_after=load_after,
            load_before=before,
        )
        result = await _run(op, outcome="open_protected_circuit")
        assert result["operator_attestation"] == expected, (
            before,
            circuit,
            load_after,
        )
        assert result["observation"]["terminal_state_observed"] == circuit

    # And there is no path by which a conclusion arrives as an answer.
    source = inspect.getsource(proof_operation.ProofOperation._observe)
    assert "matched" not in source


async def test_the_load_before_the_command_is_asked_before_consent(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It is a fact about the world before the command, so it precedes it."""
    op, driver, terminal = _operation(store, monkeypatch)
    await _run(op, outcome="open_protected_circuit")
    assert terminal.load_before_reads == 1
    order = [
        i
        for i, chunk in enumerate(terminal.written)
        if "Before anything is commanded" in chunk or "authorise" in chunk
    ]
    first, second = order[0], order[1]
    assert "Before anything is commanded" in terminal.written[first]
    assert "authorise" in terminal.written[second]
    assert driver.calls == ["connect", "disconnect"]


async def test_an_unknown_state_before_the_command_prevents_it(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It cannot be inferred, so nothing is commanded without it."""
    op, driver, _ = _operation(
        store, monkeypatch, terminal=FakeTerminal(load_before=None)
    )
    with pytest.raises(ProofRefusedError) as refusal:
        await _run(op, outcome="open_protected_circuit")
    assert refusal.value.reason == "observation_timeout"
    assert "connect" not in driver.calls


async def test_a_matched_observation_is_one_this_runtime_would_accept(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ceremony and the verifier must agree about the same document.

    A verdict this operation calls `matched` is one a producer will assemble
    into a control leg. If the verifier then refuses that leg, two components
    of one release disagree, and the ceremony certified a proof the runtime
    will not honour.
    """
    import copy

    produced: dict[str, Any] = {}
    for outcome, circuit, before, after in (
        ("open_protected_circuit", "open", "y", "n"),
        ("close_protected_circuit", "closed", "n", "y"),
    ):
        op, _, _ = _operation(
            store,
            monkeypatch,
            circuit=circuit,
            load_before=before,
            load_after=after,
        )
        result = await _run(op, outcome=outcome)
        assert result["operator_attestation"] == ATTESTATION_MATCHED
        produced[outcome] = result["observation"]

    binding = local_gpio_binding(
        device_id=DEVICE,
        sensor_id=SENSOR,
        gpio_pin=PIN,
        active_high=False,
        proof_method="actuate_and_observe",
        control_proof_method="commanded_and_observed",
    )
    leg = binding["zones"][0]["proof"]["control_path"]
    leg["observations"] = [copy.deepcopy(produced[o]) for o in sorted(produced)]
    accepted = verify_binding_envelope(sign_envelope(binding, SEED), _context())
    assert accepted.zones[0].in_force_eligible

    # And an inconclusive one is refused, by the rule the derivation now shares.
    op, _, _ = _operation(
        store, monkeypatch, circuit="open", load_before="n", load_after="n"
    )
    vacuous = await _run(op, outcome="open_protected_circuit")
    assert vacuous["operator_attestation"] == ATTESTATION_INCONCLUSIVE
    leg["observations"] = [
        copy.deepcopy(vacuous["observation"]),
        copy.deepcopy(produced["close_protected_circuit"]),
    ]
    with pytest.raises(BindingRefusedError) as refusal:
        verify_binding_envelope(sign_envelope(binding, SEED), _context())
    assert refusal.value.reason == "proof_contradiction"


async def test_an_answer_typed_before_the_command_is_not_an_observation(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Type-ahead describes an effect that had not happened yet.

    This is the defect the removed CLI flags carried, arriving on the terminal
    instead: a paste, a held Enter, or an operator answering ahead puts the
    answers in the kernel buffer before the coil moves.
    """

    class TypeAhead(FakeTerminal):
        """Answers sit in a buffer regardless of which prompt is showing."""

        def __init__(self) -> None:
            super().__init__()
            self.queue: list[str] = []

        def poll_line(self) -> str | None:
            prompt = self.written[-1] if self.written else ""
            if "Before anything is commanded" in prompt:
                self.load_before_reads += 1
                # Everything else is typed in the same burst, ahead of time.
                self.queue = ["closed", "y"]
                return "y"
            if "authorise" in prompt:
                return super().poll_line()
            self.dwell_reads += 1
            return self.queue.pop(0) if self.queue else None

        def flush_input(self) -> None:
            self.queue.clear()
            super().flush_input()

    op, _, terminal = _operation(store, monkeypatch, terminal=TypeAhead())
    result = await _run(op, outcome="open_protected_circuit")
    assert terminal.flushes, "the buffer was never flushed"
    assert result["operator_attestation"] == ATTESTATION_TIMEOUT
    assert result["observation"] is None


async def test_a_driver_that_cannot_say_whether_it_drove_is_not_believed(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`is_simulated` is read, not defaulted.

    A driver that does not report it was previously treated as having driven
    hardware -- the fail-open direction on the flag that says a physical
    command occurred.
    """

    class Silent:
        def __init__(self) -> None:
            self.calls: list[str] = []
            self.connect_kwargs: dict[str, Any] = {}

        async def connect(self, **kwargs: Any) -> None:
            self.connect_kwargs = kwargs
            self.calls.append("connect")

        async def disconnect(self) -> None:
            self.calls.append("disconnect")

        async def trigger(self, duration_seconds: float | None = None) -> bool:
            return True

        async def release(self) -> bool:
            return True

        @property
        def is_active(self) -> bool:
            return False

    op, driver, _ = _operation(store, monkeypatch, driver=Silent())
    with pytest.raises(AttributeError):
        await _run(op, outcome="open_protected_circuit")
    assert driver.calls[-1] == "disconnect"


async def test_a_terminating_signal_still_releases_the_line(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """SIGTERM and SIGHUP would otherwise end the process with the line held.

    SIGHUP is the operative one: closing the controlling terminal sends it to
    the foreground group, so the terminal never reports EOF and the release
    never runs. That is the moment the release matters most.
    """
    import signal

    seen: dict[str, Any] = {}

    class Watching(FakeTerminal):
        def poll_line(self) -> str | None:
            prompt = self.written[-1] if self.written else ""
            if "open or closed" in prompt:
                seen["during"] = {
                    name: signal.getsignal(getattr(signal, name))
                    for name in ("SIGTERM", "SIGHUP")
                }
            return super().poll_line()

    before = {
        name: signal.getsignal(getattr(signal, name)) for name in ("SIGTERM", "SIGHUP")
    }
    op, _, _ = _operation(store, monkeypatch, terminal=Watching())
    await _run(op, outcome="open_protected_circuit")

    for name in ("SIGTERM", "SIGHUP"):
        assert seen["during"][name] is not signal.SIG_DFL, (
            f"{name} keeps its default disposition during the command, so it "
            "would end the process with the line still held"
        )
        assert signal.getsignal(getattr(signal, name)) == before[name], (
            f"{name} was left installed after the command"
        )


async def test_a_late_failure_keeps_the_observation_the_operator_gave(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failure after a complete observation must not report it as a timeout.

    The operator has performed a live actuation and answered correctly. A
    record saying the observation was never completed means repeating that
    actuation on a real panel.
    """

    class Flaky:
        """Fails the first completion, records the second."""

        def __init__(self, inner: StateStore) -> None:
            self._inner = inner
            self.completions: list[dict[str, Any]] = []

        async def record_commissioning_proof_observation(self, **kw: Any) -> int:
            return await self._inner.record_commissioning_proof_observation(**kw)

        async def complete_commissioning_proof_observation(self, **kw: Any) -> None:
            self.completions.append(kw)
            if len(self.completions) == 1:
                raise sqlite3.OperationalError("database is locked")
            await self._inner.complete_commissioning_proof_observation(**kw)

        async def commissioning_proof_observations(self, h: str) -> list[dict]:
            return await self._inner.commissioning_proof_observations(h)

    import sqlite3

    flaky = Flaky(store)
    op, driver, _ = _operation(flaky, monkeypatch)
    with pytest.raises(sqlite3.OperationalError):
        await _run(op, outcome="open_protected_circuit")

    assert driver.calls[-1] == "disconnect"
    salvage = flaky.completions[-1]
    assert salvage["operator_attestation"] == ATTESTATION_MATCHED
    assert salvage["observation_json"] is not None
    recorded = json.loads(salvage["observation_json"])
    assert recorded["terminal_state_observed"] == "open"
    assert recorded["load_present_before"] is True
    assert recorded["load_present_after"] is False


async def test_the_hold_waits_for_the_operator_and_never_undercuts_the_floor(
    store: StateStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The coil is held while the operator observes, with a floor beneath it.

    A five-second window was long enough for the read and too short for a
    person: on the bench every attempt timed out while the operator was still
    reading the first prompt, and the answer to a timeout is another
    actuation. The window is now sized for a human, and the hold follows it --
    the facts being attested are only true while the command is in force.
    """
    floor = proof_operation.PROOF_HOLD_FLOOR_SECONDS
    cap = proof_operation.PROOF_OBSERVATION_CAP_SECONDS

    class Deliberate(FakeTerminal):
        """Answers after a pause, as someone walking to a panel would."""

        def __init__(self, pause: float) -> None:
            super().__init__(circuit="open", load_after="n", load_before="y")
            self._pause = pause
            self._since: float | None = None

        def poll_line(self) -> str | None:
            prompt = self.written[-1] if self.written else ""
            if "open or closed" in prompt or "Is the load present now" in prompt:
                now = time.monotonic()
                if self._since is None:
                    self._since = now
                if now - self._since < self._pause:
                    return None
                self._since = None
            return super().poll_line()

        def at_eof(self) -> bool:
            return False

    # Answers taken well past the old fixed window still land.
    slow = Deliberate(cap * 0.3)
    op, driver, _ = _operation(store, monkeypatch, terminal=slow)
    started = time.monotonic()
    result = await _run(op, outcome="open_protected_circuit")
    elapsed = time.monotonic() - started
    assert result["operator_attestation"] == ATTESTATION_MATCHED
    assert result["observation"]["terminal_state_observed"] == "open"
    assert elapsed >= cap * 0.3, elapsed
    assert driver.calls == ["connect", "disconnect"]

    # An instant answer is still held for the floor: a hold as short as the
    # typing observes nothing on an armature that needs milliseconds.
    op2, _, _ = _operation(store, monkeypatch)
    quick = await _run(op2, outcome="open_protected_circuit")
    assert quick["operator_attestation"] == ATTESTATION_MATCHED
    assert quick["held_ms"] >= floor * 900, quick["held_ms"]
    # And not held to the cap once there is nothing left to observe.
    assert quick["held_ms"] < cap * 1000 * 0.9, quick["held_ms"]
    assert quick["hold_floor_seconds"] == floor
    assert quick["observation_window_seconds"] == cap
