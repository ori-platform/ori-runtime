# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The commissioning proof operation: one consented coil command, bounded.

The control leg cannot be proven without moving the coil once through the path
under test, and that command necessarily acts on a polarity that is still an
assertion. The contract calls this a bounded commissioning hazard, accepted
once under supervision, and constrains it: local only, runtime-owned,
provisional only, consented per command, single-use, carrying no authority, and
holding the output only for the command.

Every one of those is a boundary this module owns. A local tool may invoke the
operation; it may not perform it, because a tool that builds the actuator and
drives the pin proves what the tool did rather than what this method attests.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import secrets
import select
import signal
import termios
import time
from dataclasses import dataclass
from typing import Any, Protocol, TextIO

from ori.actions.commissioned_actuator import OUTCOMES, CommissionedActuator
from ori.security.commissioning.binding import AcceptedBinding, AcceptedZone
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

TTY_PATH = "/dev/tty"

#: The shortest the commanded level is held, however fast the operator answers.
#: Release-owned: not configurable, not overridable from the bridge or a flag.
#: Two hundred and fifty times the operate time measured on a bench SRD-05VDC
#: (between 2 and 4 ms), so a hold this long cannot fail to move an armature.
#: A hold that ended when the answer arrived was as short as the typing --
#: 0.29 ms in the steady state, which observes nothing.
PROOF_HOLD_FLOOR_SECONDS = 1.0

#: The longest the operator has to observe and answer, and therefore the
#: longest the coil is held. The two are the same number because
#: `terminal_state_observed` and `load_present_after` are only true while the
#: command is in force: releasing early would have the operator attest to a
#: circuit that has already reverted.
#:
#: Sized for a person, not for a machine. A five-second window -- long enough
#: for the read itself, measured -- was not long enough to read a prompt, look
#: at a panel and answer twice, so every attempt timed out and the response to
#: a timeout is another actuation. Bounding the hazard by shortening this makes
#: the proof unobtainable and the actuations more numerous.
#:
#: Both are runtime deadlines, not physical bounds: a wedged process can still
#: hold a line, and only hardware can limit that.
PROOF_OBSERVATION_CAP_SECONDS = 60.0

#: How often the coroutine looks for a completed line while it waits.
_POLL_INTERVAL_SECONDS = 0.05

#: Signals whose default disposition would end the process with the line still
#: held. SIGHUP is the operative one: closing the controlling terminal sends it
#: to the foreground group, so `at_eof` is never reached. SIGINT already
#: arrives as a cancellation through asyncio's own handler.
_RELEASING_SIGNALS = ("SIGTERM", "SIGHUP")


@contextlib.contextmanager
def _cancel_on_signal() -> Any:
    """Turn a terminating signal into a cancellation, so `finally` still runs.

    Scoped to the command: the bridge is a one-shot process, and the handlers
    are removed on the way out rather than left installed.
    """
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    installed: list[Any] = []
    if task is not None:
        for name in _RELEASING_SIGNALS:
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                loop.add_signal_handler(sig, task.cancel)
            except (NotImplementedError, RuntimeError, ValueError):
                continue
            installed.append(sig)
    try:
        yield
    finally:
        for sig in installed:
            with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
                loop.remove_signal_handler(sig)


#: What the operator attested during the dwell.
ATTESTATION_MATCHED = "matched"
ATTESTATION_MISMATCHED = "mismatched"
ATTESTATION_TIMEOUT = "timeout"
#: The circuit was where the command asserts, but it was already there: no
#: transition was observed, so nothing was demonstrated. Distinct from
#: `mismatched`, which is a contradicted polarity -- a dead relay, an
#: unconnected pin and an inverted `active_high` all produce this one.
ATTESTATION_INCONCLUSIVE = "inconclusive"


class ProofRefusedError(Exception):
    """A refusal that names its reason, so an operator is told which bound held."""

    def __init__(self, reason: str, detail: str) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}")


class CoilDriver(Protocol):
    async def connect(
        self,
        gpio_pin: int,
        active_high: bool = True,
        *,
        tolerate_missing_backend: bool = False,
        initial_coil_state: str = "de_energised",
    ) -> None:
        """Take the line as an output, at the given coil state."""
        raise NotImplementedError

    async def disconnect(self) -> None:
        """Release the line to an undriven input."""
        raise NotImplementedError

    async def trigger(self, duration_seconds: float | None = None) -> bool:
        """Energise the coil; True when the driver did."""
        raise NotImplementedError

    async def release(self) -> bool:
        """De-energise the coil; True when the driver did."""
        raise NotImplementedError

    @property
    def is_simulated(self) -> bool:
        """True when no hardware line was taken, so nothing was commanded."""
        raise NotImplementedError

    @property
    def is_active(self) -> bool:
        """True when the driver reports the coil energised."""
        raise NotImplementedError


class ProofStore(Protocol):
    """The audit surface, declared in full so it is checked rather than assumed."""

    async def record_commissioning_proof_observation(
        self,
        *,
        binding_hash: str,
        zone_id: str,
        gpio_pin: int,
        active_high: bool,
        outcome: str,
        coil_state_commanded: str,
        level_driven: str,
        consent_nonce: str,
        consented_at_ms: int,
        commanded_at_ms: int,
        command_issued: bool,
        held_ms: int,
        observation_json: str | None,
        outcome_note: str | None,
    ) -> int:
        """Open the audit row at consent, returning its id."""
        raise NotImplementedError

    async def complete_commissioning_proof_observation(
        self,
        *,
        row_id: int,
        commanded_at_ms: int,
        command_issued: bool,
        operator_attestation: str | None,
        release_requested: bool,
        held_ms: int,
        observation_json: str | None,
        outcome_note: str | None,
    ) -> None:
        """Close the row once the command has been issued."""
        raise NotImplementedError

    async def commissioning_proof_observations(self, binding_hash: str) -> list[dict]:
        """Every recorded command for one binding, oldest first."""
        raise NotImplementedError


@dataclass(frozen=True)
class Observation:
    """One contract-shaped observation of a commanded outcome.

    `commanded`, `coil_state` and `gpio_level` are the runtime's: it issued
    them. The rest is the operator's, taken on the terminal. Sensor readings
    and the instrument are absent unless someone supplied them, because an
    unmeasured value is not zero.
    """

    commanded: str
    coil_state: str
    gpio_level: str
    load_present_before: bool
    load_present_after: bool
    terminal_state_observed: str
    sensor_before: float | None = None
    sensor_after: float | None = None
    instrument: str | None = None

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "commanded": self.commanded,
            "coil_state": self.coil_state,
            "gpio_level": self.gpio_level,
            "load_present_before": self.load_present_before,
            "load_present_after": self.load_present_after,
            "terminal_state_observed": self.terminal_state_observed,
        }
        for name in ("sensor_before", "sensor_after", "instrument"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        return out


def expected_circuit(outcome: str) -> str:
    """The terminal state the outcome asserts."""
    return "open" if outcome == "open_protected_circuit" else "closed"


def attestation_for(observation: Observation) -> str:
    """Derive the verdict from the observed facts, never from a separate answer.

    A conclusion the operator gives alongside the facts can contradict them,
    and then the record carries both. Only the facts are collected; this is the
    reading of them.
    """
    opening = observation.commanded == "open_protected_circuit"
    if observation.terminal_state_observed != expected_circuit(observation.commanded):
        return ATTESTATION_MISMATCHED
    # The same pair the verifier requires of a proof observation
    # (`binding.py`, proof_consistency). A command whose load never changed
    # state demonstrates nothing about the control path, and deriving
    # `matched` from it certifies a proof this runtime's own verifier refuses.
    expected_pair = (True, False) if opening else (False, True)
    if (observation.load_present_before, observation.load_present_after) != (
        expected_pair
    ):
        return ATTESTATION_INCONCLUSIVE
    return ATTESTATION_MATCHED


class Terminal(Protocol):
    """The controlling terminal, opened and owned by this module."""

    def write(self, text: str) -> None:
        """Put text on the terminal."""
        raise NotImplementedError

    def poll_line(self) -> str | None:
        """One complete line if one has arrived, else None. Never blocks."""
        raise NotImplementedError

    def at_eof(self) -> bool:
        """The terminal has gone away; no further line can arrive."""
        raise NotImplementedError

    def flush_input(self) -> None:
        """Discard anything typed before now."""
        raise NotImplementedError

    def close(self) -> None:
        """Release both handles."""
        raise NotImplementedError


class ControllingTerminal:
    """`/dev/tty`, opened here rather than received from a caller.

    Consent that arrives as a value has already left the operator: it can be
    piped, replayed, or supplied by whatever invoked the tool. Opening the
    terminal directly is what makes this an attestation rather than a
    credential, and it is why no argument to this class carries an answer.

    The read side is a raw descriptor polled without blocking. A buffered
    `readline()` blocks until a newline however the caller bounded the wait,
    so on a terminal left in non-canonical mode -- a raw-mode TUI, a crashed
    editor -- a single keystroke would satisfy `select` and then hold the read
    open indefinitely, with the coil energised and the deadline powerless.
    """

    def __init__(self) -> None:
        self._read_fd: int | None = None
        self._out: TextIO | None = None
        self._buffer = ""
        self._eof = False
        try:
            self._read_fd = os.open(TTY_PATH, os.O_RDONLY | os.O_NONBLOCK)
            self._out = open(TTY_PATH, "w", buffering=1, encoding="utf-8")
        except OSError as exc:
            self.close()
            raise ProofRefusedError(
                "no_controlling_terminal",
                f"{TTY_PATH} could not be opened: {exc}. Consent is an operator "
                "attestation and cannot be given by a pipe, a flag, or a "
                "non-interactive session.",
            ) from exc
        if not (os.isatty(self._read_fd) and os.isatty(self._out.fileno())):
            self.close()
            raise ProofRefusedError(
                "no_controlling_terminal",
                f"{TTY_PATH} is not an interactive terminal.",
            )

    def write(self, text: str) -> None:
        assert self._out is not None
        self._out.write(text)
        self._out.flush()

    def poll_line(self) -> str | None:
        """One complete line if one has arrived, else None. Never blocks."""
        if self._read_fd is None:
            return None
        try:
            ready, _, _ = select.select([self._read_fd], [], [], 0)
            if ready:
                data = os.read(self._read_fd, 4096)
                if data:
                    self._buffer += data.decode("utf-8", "replace")
                else:
                    self._eof = True
        except (BlockingIOError, InterruptedError):
            return None
        except (OSError, ValueError):
            return None
        if "\n" not in self._buffer:
            return None
        line, _, self._buffer = self._buffer.partition("\n")
        return line

    def at_eof(self) -> bool:
        """The terminal has gone away; no further line can arrive."""
        return self._eof or self._read_fd is None

    def flush_input(self) -> None:
        """Discard anything typed before now.

        An answer already in the buffer when the coil moves describes an effect
        that had not happened yet -- the same defect the removed CLI flags
        carried, arriving on the terminal instead. Type-ahead, a paste, or a
        held Enter key all produce it.
        """
        self._buffer = ""
        if self._read_fd is None:
            return
        with contextlib.suppress(OSError, ValueError):
            termios.tcflush(self._read_fd, termios.TCIFLUSH)

    def close(self) -> None:
        if self._read_fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._read_fd)
            self._read_fd = None
        if self._out is not None:
            with contextlib.suppress(OSError):
                self._out.close()
            self._out = None


#: How the operation obtains its terminal. Module-private and read at call
#: time, so no caller can supply one: a tool that hands over a terminal has
#: made consent transferable, which is the property the contract forbids.
#: Tests substitute it here; nothing else may.
_TERMINAL_FACTORY: Any = ControllingTerminal


def _zone_for(binding: AcceptedBinding, zone_id: str | None) -> AcceptedZone:
    zones = [z for z in binding.zones if z.kind == "local_gpio"]
    if not zones:
        raise ProofRefusedError(
            "no_local_gpio_zone",
            "the provisional binding declares no local_gpio zone. A firmware "
            "channel's control leg has no design yet and cannot be proven here.",
        )
    if zone_id is None:
        if len(zones) > 1:
            raise ProofRefusedError(
                "zone_required",
                "the provisional binding declares more than one local_gpio zone; "
                "name the one to prove.",
            )
        return zones[0]
    for zone in zones:
        if zone.zone_id == zone_id:
            return zone
    raise ProofRefusedError(
        "unknown_zone", f"no local_gpio zone {zone_id!r} in the provisional binding"
    )


class ProofOperation:
    """One consented command against one provisional zone, and nothing else."""

    def __init__(
        self,
        *,
        store: ProofStore,
        driver: CoilDriver,
        provisional: AcceptedBinding | None,
        in_force: AcceptedBinding | None,
        hardened: bool,
        gpio_backend_available: bool,
    ) -> None:
        self._store = store
        self._driver = driver
        self._provisional = provisional
        self._in_force = in_force
        self._hardened = hardened
        self._gpio_available = gpio_backend_available

    # ── the refusal wall ──────────────────────────────────────────────────

    def _admissible(self, zone_id: str | None, outcome: str) -> AcceptedZone:
        """Every bound that can be decided before a terminal is opened."""
        if self._hardened:
            raise ProofRefusedError(
                "hardened_posture",
                "commissioning precedes hardening. A hardened runtime refuses "
                "declared hardware with no binding in force, and a provisional "
                "binding is not in force, so this proof runs during "
                "installation in development posture.",
            )
        if self._provisional is None:
            raise ProofRefusedError(
                "no_provisional_binding",
                "there is no provisional binding to prove. Deliver one first.",
            )
        if outcome not in OUTCOMES:
            raise ProofRefusedError(
                "unknown_outcome",
                f"{outcome!r} is not a protected-circuit outcome.",
            )
        zone = _zone_for(self._provisional, zone_id)
        if self._in_force is not None and any(
            z.identity_key == zone.identity_key for z in self._in_force.zones
        ):
            raise ProofRefusedError(
                "already_in_force",
                f"zone {zone.zone_id!r} is bound by the binding in force; the "
                "proof operation is unavailable once a zone is proven.",
            )
        if not self._gpio_available:
            raise ProofRefusedError(
                "no_gpio_backend",
                "no GPIO backend is available. A simulated command proves "
                "nothing, and this operation has no degraded path: it either "
                "drives the declared pin or it refuses.",
            )
        return zone

    # ── consent ───────────────────────────────────────────────────────────

    async def _consent(
        self, terminal: Terminal, zone: AcceptedZone, outcome: str
    ) -> str:
        """One nonce, typed back on the terminal, for exactly one command."""
        assert self._provisional is not None
        coil_state = zone.mapping[outcome]
        energised = coil_state == "energised"
        active_high = bool(zone.identity["active_high"])
        level = "high" if energised == active_high else "low"
        nonce = secrets.token_hex(3).upper()

        terminal.write(
            "\n"
            "  COMMISSIONING PROOF — one physical command\n"
            f"    binding        {self._provisional.canonical_hash}\n"
            f"    zone           {zone.zone_id}\n"
            f"    pin            GPIO {zone.identity['gpio_pin']} "
            f"(asserted active_high={active_high})\n"
            f"    outcome        {outcome}\n"
            f"    coil expected  {coil_state}  (driving the pin {level})\n"
            f"    held for       as long as you need to answer, up to "
            f"{PROOF_OBSERVATION_CAP_SECONDS:.0f}s, then released to an "
            f"undriven input\n"
            f"    taking the pin drives it straight to the coil state above; "
            f"that acquisition is the whole physical act, and nothing else "
            f"follows it\n"
            f"    on controller loss this zone's circuit goes "
            f"{zone.mapping['de_energised_terminal_state']}\n"
            "\n"
            "  The polarity above is asserted by the binding and is what this\n"
            "  command exists to test. If it is wrong, the coil does the\n"
            "  opposite of what this says.\n"
            "\n"
            f"  Type {nonce} to authorise this single command, anything else to "
            "refuse: "
        )
        answer = await self._read_line(terminal, None)
        if answer is None or answer.strip() != nonce:
            raise ProofRefusedError(
                "consent_refused",
                "the authorisation was not given; no command was issued.",
            )
        return nonce

    # ── the bounded command ───────────────────────────────────────────────

    async def command(
        self,
        *,
        outcome: str,
        zone_id: str | None = None,
    ) -> dict[str, Any]:
        """One consent, one physical command, and a contract-shaped observation.

        The pin is taken *at* the commanded coil state rather than taken at
        de-energised and then commanded, so one authorisation produces one
        physical act. `load_present_before` is asked before consent, because it
        is a fact about the world before the command; the rest is asked while
        the commanded level is still held.
        """
        with _cancel_on_signal():
            return await self._command(outcome=outcome, zone_id=zone_id)

    async def _command(
        self,
        *,
        outcome: str,
        zone_id: str | None,
    ) -> dict[str, Any]:
        zone = self._admissible(zone_id, outcome)
        assert self._provisional is not None
        terminal = _TERMINAL_FACTORY()
        row_id: int | None = None
        attempted_connect = False
        released = False
        command_issued = False
        commanded_at = 0
        held_ms = 0
        collected: Observation | None = None
        try:
            load_before = await self._ask_load(
                terminal,
                "Before anything is commanded: is the load present at the "
                "protected circuit now? [y/n]: ",
                deadline=None,
            )
            if load_before is None:
                raise ProofRefusedError(
                    "observation_timeout",
                    "the state of the load before the command was not given, "
                    "and it cannot be inferred; no command was issued.",
                )

            nonce = await self._consent(terminal, zone, outcome)
            consented_at = now_ms()

            coil_state = zone.mapping[outcome]
            energised = coil_state == "energised"
            active_high = bool(zone.identity["active_high"])
            level = "high" if energised == active_high else "low"

            row_id = await self._store.record_commissioning_proof_observation(
                binding_hash=self._provisional.canonical_hash,
                zone_id=zone.zone_id,
                gpio_pin=int(zone.identity["gpio_pin"]),
                active_high=active_high,
                outcome=outcome,
                coil_state_commanded=coil_state,
                level_driven=level,
                consent_nonce=nonce,
                consented_at_ms=consented_at,
                commanded_at_ms=0,
                command_issued=False,
                held_ms=0,
                observation_json=None,
                outcome_note="consented; the line had not been taken",
            )

            actuator = CommissionedActuator(
                driver=self._driver,
                zone=zone,
                binding_seq=self._provisional.binding_seq,
            )
            try:
                # Taking the line *is* the command. Nothing follows it: a
                # `command()` here would be the second physical act of one
                # authorisation.
                attempted_connect = True
                command_issued = await actuator.acquire_commanding(outcome)
                commanded_at = now_ms()
                last = actuator.last
                assert last is not None
                if not command_issued:
                    # Nothing to observe: dwelling here would ask an operator
                    # to attest to the effect of a command the driver says it
                    # did not issue.
                    raise ProofRefusedError(
                        "command_failed",
                        "the driver took no hardware line, so nothing was "
                        "commanded, there is nothing to observe, and no proof "
                        "follows; the pin is released.",
                    )
                # Nothing typed before the coil moved is an observation of it.
                terminal.flush_input()
                started = time.monotonic()
                deadline = started + PROOF_OBSERVATION_CAP_SECONDS
                observed = await self._observe(
                    terminal, outcome, coil_state, level, load_before, deadline
                )
                collected = observed
                # The floor, not the cap: releasing when the answer arrives
                # makes the hold as short as the typing, but holding to the cap
                # once the operator has answered energises a coil on an
                # unproven polarity for no further observation.
                await self._hold_until(started + PROOF_HOLD_FLOOR_SECONDS)
            finally:
                if attempted_connect:
                    held_ms = max(now_ms() - commanded_at, 0) if commanded_at else 0
                    await self._driver.disconnect()
                    released = True

            attestation = (
                ATTESTATION_TIMEOUT if observed is None else attestation_for(observed)
            )
            note = {
                ATTESTATION_MATCHED: None,
                ATTESTATION_MISMATCHED: (
                    "the circuit the operator observed is not what this command "
                    "asserts; the asserted polarity is contradicted"
                ),
                ATTESTATION_INCONCLUSIVE: (
                    "the circuit was already where this command would put it, so "
                    "no transition was observed and nothing is demonstrated; the "
                    "verifier refuses a proof observation with this load pair"
                ),
                ATTESTATION_TIMEOUT: (
                    "observation_timeout: the observation was not completed "
                    "within the dwell"
                ),
            }[attestation]
            await self._complete(
                row_id,
                commanded_at=commanded_at,
                command_issued=command_issued,
                attestation=attestation,
                held_ms=held_ms,
                observation=observed,
                note=note,
            )
            terminal.write(
                f"\n  commanded {outcome}: coil {last.coil_state}, pin taken "
                f"{last.level}\n"
                f"  held {held_ms / 1000:.1f}s, operator attestation: "
                f"{attestation}\n"
                "  the runtime did not verify the coil; only the observation "
                "above speaks to what happened\n"
                "  the pin is released to an undriven input\n\n"
            )
            return {
                "zone_id": zone.zone_id,
                "outcome": outcome,
                "coil_state_commanded": last.coil_state,
                "level_driven": last.level,
                "observation_window_seconds": PROOF_OBSERVATION_CAP_SECONDS,
                "hold_floor_seconds": PROOF_HOLD_FLOOR_SECONDS,
                "held_ms": held_ms,
                "command_issued": command_issued,
                "effect_verified": False,
                "operator_attestation": attestation,
                "observation": observed.as_dict() if observed else None,
                "release_requested": True,
                "binding_hash": self._provisional.canonical_hash,
            }
        except BaseException as exc:
            # An observation already collected is recorded as collected: a
            # failure after it must not report `timeout` and discard the
            # operator's answers, which would mean repeating a live actuation.
            failed = (
                isinstance(exc, ProofRefusedError) and exc.reason == "command_failed"
            )
            if row_id is not None:
                with contextlib.suppress(Exception):
                    await self._complete(
                        row_id,
                        commanded_at=commanded_at,
                        command_issued=command_issued,
                        attestation=(
                            attestation_for(collected)
                            if collected is not None
                            else ATTESTATION_TIMEOUT
                        ),
                        held_ms=held_ms,
                        observation=collected,
                        note=(
                            "command_failed: the driver reported the line was "
                            "not taken; nothing was observed"
                            if failed
                            else (
                                "the operation ended before it returned, but "
                                "the observation was complete"
                                if collected is not None
                                else "observation_timeout: the operation ended "
                                "without a completed observation"
                            )
                            + (
                                "; the line was taken, so whether the coil "
                                "moved is indeterminate"
                                if attempted_connect and not command_issued
                                else ""
                            )
                        ),
                    )
            raise
        finally:
            if not released:
                await self._driver.disconnect()
            terminal.close()

    async def _observe(
        self,
        terminal: Terminal,
        outcome: str,
        coil_state: str,
        level: str,
        load_before: bool,
        deadline: float,
    ) -> Observation | None:
        """Collect the operator's half of the contract's observation."""
        terminal.write(
            f"\n  The coil is commanded {coil_state} NOW and is held while you\n"
            f"  answer, for up to {PROOF_OBSERVATION_CAP_SECONDS:.0f} seconds. "
            "Take the time to look at the\n"
            "  protected circuit itself; the answers are what the proof rests\n"
            "  on, and there are two of them.\n"
        )
        state = await self._ask_choice(
            terminal,
            "  Is the protected circuit open or closed? [open/closed]: ",
            ("open", "closed"),
            deadline,
        )
        if state is None:
            return None
        load_after = await self._ask_load(
            terminal, "  Is the load present now? [y/n]: ", deadline=deadline
        )
        if load_after is None:
            return None
        return Observation(
            commanded=outcome,
            coil_state=coil_state,
            gpio_level=level,
            load_present_before=load_before,
            load_present_after=load_after,
            terminal_state_observed=state,
        )

    async def _ask_load(
        self, terminal: Terminal, prompt: str, *, deadline: float | None
    ) -> bool | None:
        answer = await self._ask_choice(
            terminal, prompt, ("y", "yes", "n", "no"), deadline
        )
        return None if answer is None else answer in ("y", "yes")

    async def _ask_choice(
        self,
        terminal: Terminal,
        prompt: str,
        allowed: tuple[str, ...],
        deadline: float | None,
    ) -> str | None:
        """One answer from the allowed set, or None. An unrecognised reply is
        re-prompted rather than read as any of them."""
        terminal.write(prompt)
        while deadline is None or time.monotonic() < deadline:
            line = await self._read_line(terminal, deadline)
            if line is None:
                return None
            reply = str(line).strip().lower()
            if reply in allowed:
                return reply
            terminal.write(f"    not one of {'/'.join(allowed)}. {prompt}")
        return None

    @staticmethod
    async def _read_line(terminal: Terminal, deadline: float | None) -> str | None:
        """Poll the terminal from the coroutine, so nothing blocks or detaches.

        A worker thread blocked on a terminal cannot be cancelled and is joined
        at interpreter exit, which turned an unanswered prompt into a process
        that ignored SIGINT and SIGTERM with the coil still energised.
        """
        while deadline is None or time.monotonic() < deadline:
            line = terminal.poll_line()
            if line is not None:
                return line
            if terminal.at_eof():
                # A prompt taken before consent has no deadline, because nothing
                # is energised while it waits. A terminal that has gone away
                # must still end the wait rather than spin on it.
                return None
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        return None

    @staticmethod
    async def _hold_until(deadline: float) -> None:
        """Keep the commanded level until the dwell's deadline."""
        remaining = deadline - time.monotonic()
        if remaining > 0:
            await asyncio.sleep(remaining)

    async def _complete(
        self,
        row_id: int,
        *,
        commanded_at: int,
        command_issued: bool,
        attestation: str,
        held_ms: int,
        observation: Observation | None,
        note: str | None,
    ) -> None:
        """Close the audit row. `effect_verified` is never asserted here."""
        await self._store.complete_commissioning_proof_observation(
            row_id=row_id,
            commanded_at_ms=commanded_at,
            command_issued=command_issued,
            operator_attestation=attestation,
            release_requested=True,
            held_ms=held_ms,
            observation_json=(
                json.dumps(observation.as_dict(), sort_keys=True)
                if observation is not None
                else None
            ),
            outcome_note=note,
        )


async def export_observations(
    *, store: ProofStore, provisional: AcceptedBinding | None
) -> dict[str, Any]:
    """Everything recorded against the provisional binding, and nothing more.

    Read-only by construction: it takes no observation, no consent, no pin and
    no claimed outcome from its caller. A producer assembles the new document
    from what the runtime recorded, not from what a tool asserts.
    """
    if provisional is None:
        raise ProofRefusedError(
            "no_provisional_binding",
            "there is no provisional binding whose proof could be exported.",
        )
    rows = await store.commissioning_proof_observations(provisional.canonical_hash)
    return {
        "binding_hash": provisional.canonical_hash,
        "binding_seq": provisional.binding_seq,
        "observations": [
            {
                "zone_id": r["zone_id"],
                "outcome": r["outcome"],
                "coil_state_commanded": r["coil_state_commanded"],
                "level_driven": r["level_driven"],
                "gpio_pin": r["gpio_pin"],
                "active_high": bool(r["active_high"]),
                "commanded_at_ms": r["commanded_at_ms"],
                "held_ms": r["held_ms"],
                "command_issued": bool(r["command_issued"]),
                "effect_verified": bool(r["effect_verified"]),
                "operator_attestation": r["operator_attestation"],
                "release_requested": bool(r["release_requested"]),
                "observed": json.loads(r["observation_json"])
                if r["observation_json"]
                else None,
                "note": r["outcome_note"],
            }
            for r in rows
        ],
    }
