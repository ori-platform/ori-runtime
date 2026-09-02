# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The release-owned safety registry: activation, evaluation, actuation.

Assembled once at startup from the release-shipped profile set and the
accepted binding's zones — skills, configuration and policy are structurally
not inputs — and consulted synchronously for every reading before anything
else sees it. A matched profile's outcome executes through a registry-owned
seam holding an unforgeable authority token; no dispatcher, skill context,
or remote path participates.

The trip sequence is the contract's: a bounded intent append that never
delays the command, the machine's pending posture, one driver attempt under
the in-flight lease, the durable record, then the resolution mark. Retries
for unresolved commands and unpersisted records are reading-independent
obligations with bounded backoff and no terminal limit.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol
from uuid import uuid4

from ori.safety.activation import (
    ActivationResult,
    ZoneFacts,
    activate,
)
from ori.safety.evaluation import evaluate_reading
from ori.safety.trip_state import (
    OPEN_PROTECTED_CIRCUIT,
    DeferredStartupGate,
    ZoneTripState,
)
from ori.security.commissioning.profiles import ProfileSet
from ori.state.store import TripJournal
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

# The intent-append deadline: a reviewed, release-owned constant, at the
# contract's 250 ms ceiling. No configuration, policy, or remote input
# selects it — whoever chooses this number controls Tier D response latency.
TRIP_INTENT_APPEND_DEADLINE_MS = 250

# Safety notices repeat no faster than this per pair and kind: the contract
# requires bounded suppression so a persistent fault is not a message flood.
SAFETY_ALERT_SUPPRESSION_S = 300.0

# Measurement loss is declared after this many missed poll intervals with
# no credible reading, and never sooner than the floor: fast pollers get
# the floor's tolerance, and a sensor with no declared interval gets
# exactly the floor. Both are release-owned and documented, not
# configurable.
MEASUREMENT_LOSS_INTERVALS = 5
MEASUREMENT_LOSS_FLOOR_MS = 60_000

RETRY_BACKOFF_BASE_S = 1.0
RETRY_BACKOFF_CAP_S = 60.0

# How long the record write waits behind its own intent before deferring to
# recovery. Release-owned like the deadline; injectable only for tests.
RECORD_ORDER_GRACE_S = 5.0


class SafetyAlertSink(Protocol):
    """Where mandatory Tier A safety notices go. The runtime's sink calls
    its delivery-or-durable-queue path directly — never the dispatcher and
    never anything DevicePolicy can gate — so a safety-path notice cannot
    disappear behind entitlement."""

    async def send(
        self, *, kind: str, zone_id: str, profile_id: str, message: str
    ) -> bool:
        """Deliver or durably queue one notice; True when it is accounted for."""
        raise NotImplementedError


class OutcomeCommander(Protocol):
    """The commissioned actuation seam the registry commands through."""

    async def command_outcome(self, zone_id: str, outcome: str) -> bool:
        """Command a protected-circuit outcome; True when the driver accepts."""
        raise NotImplementedError

    async def command_startup_de_energised(self, zone_id: str) -> bool:
        """The startup coil command, through the zone's commissioned mapping."""
        raise NotImplementedError


class _RegistryAuthority:
    """The unforgeable Tier D authority token. Instantiated only by the
    registry that owns it; the executor compares identity, not shape."""

    __slots__ = ()


@dataclass(frozen=True)
class ActivePair:
    zone_id: str
    profile_id: str
    sensor_id: str
    trip_point: float
    outcome: str
    unit: str
    range_min: float
    range_max: float
    terminal_state: str
    binding_seq: int
    actuator_identity: tuple[str, str]


class SafetyOutcomeExecutor:
    """Executes a profile outcome, and only for the registry that made it."""

    def __init__(
        self,
        commander: OutcomeCommander,
        authority: _RegistryAuthority,
        active: Mapping[tuple[str, str], ActivePair],
    ) -> None:
        self._commander = commander
        self._authority = authority
        self._active = active

    async def execute(
        self,
        authority: _RegistryAuthority,
        pair: tuple[str, str],
        outcome: str,
        *,
        binding_seq: int,
        actuator_identity: tuple[str, str],
    ) -> bool:
        """The final independent check before a Tier D outcome executes."""
        if authority is not self._authority:
            raise PermissionError(
                "Tier D outcome refused: not the registry's authority"
            )
        entry = self._active.get(pair)
        if entry is None:
            raise PermissionError(f"Tier D outcome refused: pair {pair} is not active")
        if (
            entry.binding_seq != binding_seq
            or entry.actuator_identity != actuator_identity
        ):
            raise PermissionError(
                "Tier D outcome refused: binding or actuator identity no longer matches"
            )
        if outcome != entry.outcome:
            # A profile authorises its own outcome and nothing else: v1
            # profiles only open, and a close through this seam would be a
            # second path to reconnecting a load that only arm and reset own.
            raise PermissionError(
                f"Tier D outcome refused: {outcome!r} is not the profile's "
                f"outcome {entry.outcome!r}"
            )
        return await self._commander.command_outcome(entry.zone_id, outcome)


@dataclass(frozen=True)
class ReadingDecision:
    """What the registry decided about one reading, for the caller's log."""

    pair: tuple[str, str]
    verdict: str
    reason: str | None = None
    tripped: bool = False
    driver_accepted: bool | None = None


class SafetyRegistry:
    """Owns activation, the per-pair machines, and the actuation seam."""

    def __init__(
        self,
        profile_set: ProfileSet,
        zones: Iterable[Any],
        journal: TripJournal,
        commander: OutcomeCommander,
        *,
        binding_seq: int,
        record_order_grace_s: float = RECORD_ORDER_GRACE_S,
        alert_sink: SafetyAlertSink | None = None,
        poll_intervals_ms: Mapping[str, int] | None = None,
        clock: Any = now_ms,
    ) -> None:
        self._journal = journal
        self._commander = commander
        self._binding_seq = binding_seq
        self._record_order_grace_s = record_order_grace_s
        self._unsettled_intents: dict[tuple[str, str], asyncio.Future[None]] = {}
        self._alert_sink = alert_sink
        self._poll_intervals_ms = dict(poll_intervals_ms or {})
        self._clock = clock
        self._started_ms = int(clock())
        self._last_credible_ms: dict[tuple[str, str], int] = {}
        self._measurement_degraded: set[tuple[str, str]] = set()
        self._rejected_active: set[tuple[str, str]] = set()
        self._last_alert_ms: dict[tuple[tuple[str, str], str], int] = {}
        self._suppressed_alerts = 0
        self._zones = {z.zone_id: z for z in zones}
        facts = [ZoneFacts.from_accepted_zone(z) for z in self._zones.values()]
        self._terminal_states = {
            z.zone_id: z.mapping.get("de_energised_terminal_state", "open")
            for z in self._zones.values()
        }
        self.activation: ActivationResult = activate(profile_set, facts)
        self._authority = _RegistryAuthority()
        self._active: dict[tuple[str, str], ActivePair] = {}
        for entry in self.activation.activated:
            zone = self._zones[entry.zone_id]
            facts_for = next(f for f in facts if f.zone_id == entry.zone_id)
            self._active[(entry.zone_id, entry.profile_id)] = ActivePair(
                zone_id=entry.zone_id,
                profile_id=entry.profile_id,
                sensor_id=entry.sensor_id,
                trip_point=entry.trip_point,
                outcome=entry.outcome,
                unit=facts_for.unit,
                range_min=facts_for.range_min,
                range_max=facts_for.range_max,
                terminal_state=self._terminal_states[entry.zone_id],
                binding_seq=binding_seq,
                actuator_identity=zone.identity_key,
            )
        self._executor = SafetyOutcomeExecutor(commander, self._authority, self._active)
        self._machines: dict[tuple[str, str], ZoneTripState] = {}
        self._gates: dict[str, DeferredStartupGate] = {}
        self._by_sensor: dict[str, list[tuple[str, str]]] = {}
        for pair, active in self._active.items():
            self._by_sensor.setdefault(active.sensor_id, []).append(pair)

    def startup_verdict(self, *, hardened: bool) -> str:
        return self.activation.startup_verdict(hardened=hardened)

    @property
    def zones_with_active_pairs(self) -> frozenset[str]:
        """Zones whose startup coil command this registry owns: the
        terminal-state conditioning and the latch check only exist where a
        profile is active, and every other zone keeps the plain startup
        de_energised command it has today."""
        return frozenset(entry.zone_id for entry in self._active.values())

    async def start(self) -> None:
        """Load durable state for every pair — active and orphaned alike —
        and issue the terminal-state-conditioned startup commands. Must run
        after activation was judged startable and before any reading."""
        journal_pairs = set(await self._journal.pairs())
        for pair in journal_pairs | set(self._active):
            entry = self._active.get(pair)
            terminal = (
                entry.terminal_state
                if entry is not None
                else self._terminal_states.get(pair[0], "open")
            )
            machine = ZoneTripState(pair[0], pair[1], terminal_state=terminal)
            durable_state, journal = await self._journal.load(*pair)
            transition = machine.startup(
                durable_state, journal, binding_seq_in_force=self._binding_seq
            )
            if entry is None:
                machine.binding_removed()
            self._machines[pair] = machine
            if transition.startup_command == "deferred":
                self._gates.setdefault(pair[0], DeferredStartupGate(deferred=True))
        for zone_id in {p.zone_id for p in self._active.values()}:
            pairs = [m for k, m in self._machines.items() if k[0] == zone_id]
            if any(m.state == "tripped" for m in pairs):
                self._gates.get(
                    zone_id, DeferredStartupGate(deferred=False)
                ).note_trip()
                continue
            if self._terminal_states[zone_id] == "open":
                accepted = await self._commander.command_startup_de_energised(zone_id)
                if not accepted:
                    logger.error(
                        "[safety] startup de_energised command refused zone=%s", zone_id
                    )

    async def observe_reading(
        self, sensor_id: str, value: Any, unit: Any, quality: Any
    ) -> list[ReadingDecision]:
        """The synchronous consumption of one reading, before deduplication,
        history, the EventBus, or any skill sees it."""
        decisions: list[ReadingDecision] = []
        tripped_now = False
        for pair in self._by_sensor.get(sensor_id, ()):
            entry = self._active[pair]
            machine = self._machines[pair]
            verdict = evaluate_reading(
                value,
                unit,
                quality,
                expected_unit=entry.unit,
                trip_point=entry.trip_point,
                range_min=entry.range_min,
                range_max=entry.range_max,
            )
            transition = machine.observe(verdict)
            if verdict.verdict == "rejected_input":
                # A rejected reading never trips and never silently vanishes:
                # an immediate Tier A notice under bounded suppression, and a
                # health flag until a credible reading clears it.
                self._rejected_active.add(pair)
                await self._safety_alert(
                    pair,
                    "rejected_input",
                    f"reading rejected ({verdict.reason}) on zone {pair[0]} "
                    f"profile {pair[1]}; the profile cannot evaluate it",
                )
            else:
                self._last_credible_ms[pair] = int(self._clock())
                self._rejected_active.discard(pair)
                if pair in self._measurement_degraded:
                    self._measurement_degraded.discard(pair)
                    logger.info(
                        "[safety] measurement recovered zone=%s profile=%s",
                        pair[0],
                        pair[1],
                    )
            if transition.outcome == OPEN_PROTECTED_CIRCUIT:
                tripped_now = True
                accepted = await self._attempt_command(pair, entry, machine)
                decisions.append(
                    ReadingDecision(
                        pair, verdict.verdict, tripped=True, driver_accepted=accepted
                    )
                )
            else:
                decisions.append(
                    ReadingDecision(pair, verdict.verdict, reason=verdict.reason)
                )
        if decisions:
            await self._settle_deferred_gate(sensor_id, decisions, tripped_now)
        return decisions

    async def _settle_deferred_gate(
        self, sensor_id: str, decisions: list[ReadingDecision], tripped_now: bool
    ) -> None:
        del tripped_now
        zone_ids = {pair[0] for pair in self._by_sensor.get(sensor_id, ())}
        for zone_id in zone_ids:
            gate = self._gates.get(zone_id)
            if gate is None or not gate.pending:
                continue
            zone_decisions = [d for d in decisions if d.pair[0] == zone_id]
            zone_tripped_now = any(d.tripped for d in zone_decisions)
            if zone_tripped_now or any(
                d.verdict == "rejected_input" for d in zone_decisions
            ):
                if zone_tripped_now:
                    gate.note_trip()
                continue
            any_tripped = any(
                m.state == "tripped"
                for k, m in self._machines.items()
                if k[0] == zone_id
            )
            command = gate.note_credible_reading(any_pair_tripped=any_tripped)
            if command == "de_energised":
                accepted = await self._commander.command_startup_de_energised(zone_id)
                if not accepted:
                    logger.error(
                        "[safety] deferred de_energised command refused zone=%s",
                        zone_id,
                    )

    async def _attempt_command(
        self,
        pair: tuple[str, str],
        entry: ActivePair,
        machine: ZoneTripState,
    ) -> bool | None:
        """One physical attempt under the contract's sequence — bounded
        intent, one leased command, durable record, resolution mark — used
        by the first trip and by every retry alike, because a retry is a new
        physical attempt and carries its own intent evidence."""
        attempt_id = str(uuid4())
        accepted: bool | None
        # The append is never cancelled: a cancelled coroutine's SQLite work
        # keeps running in its thread and could commit after the record,
        # which a restart would read as a newer unresolved intent. The task
        # runs to completion on its own, the command proceeds at the
        # deadline regardless, and the record write later queues behind it
        # on the store's write lock so the journal order cannot invert.
        intent_task = asyncio.ensure_future(
            self._journal.append_intent(
                *pair,
                attempt_id=attempt_id,
                binding_seq=entry.binding_seq,
                outcome=entry.outcome,
                created_at_ms=now_ms(),
            )
        )
        self._unsettled_intents[pair] = intent_task
        done, _ = await asyncio.wait(
            {intent_task}, timeout=TRIP_INTENT_APPEND_DEADLINE_MS / 1000
        )
        if intent_task in done and intent_task.exception() is not None:
            logger.error(
                "[safety] trip intent append failed zone=%s: %s",
                pair[0],
                intent_task.exception(),
            )
        elif intent_task not in done:
            logger.error(
                "[safety] trip intent append missed the deadline zone=%s", pair[0]
            )
            intent_task.add_done_callback(lambda t: t.exception())
        machine.begin_driver_attempt()
        try:
            accepted = await self._executor.execute(
                self._authority,
                pair,
                entry.outcome,
                binding_seq=entry.binding_seq,
                actuator_identity=entry.actuator_identity,
            )
        except Exception:
            logger.exception("[safety] trip command raised zone=%s", pair[0])
            machine.release_driver_attempt()
            accepted = None
        else:
            machine.record_driver_result(accepted=accepted)
        await self._persist_record(pair, machine, after=intent_task)
        return accepted

    async def _persist_record(
        self,
        pair: tuple[str, str],
        machine: ZoneTripState,
        *,
        after: "asyncio.Future[None] | None" = None,
    ) -> None:
        if after is not None and not after.done():
            # The intent write is still running; the record must not race
            # it. Wait a bounded grace, then leave the record to recovery —
            # which is itself gated on this pair's unsettled intent, so the
            # ordering dependency survives the grace expiring.
            done, _ = await asyncio.wait({after}, timeout=self._record_order_grace_s)
            if after not in done:
                logger.error(
                    "[safety] record deferred behind a slow intent zone=%s", pair[0]
                )
                machine.record_write_failed()
                return
        self._unsettled_intents.pop(pair, None)
        try:
            await self._journal.append_record(
                *pair, command_status=machine.command_status, created_at_ms=now_ms()
            )
            await self._journal.mark_resolved(*pair)
        except Exception:
            logger.exception("[safety] trip record write failed zone=%s", pair[0])
            machine.record_write_failed()

    async def retry_pending_once(self) -> int:
        """One pass of the reading-independent retry obligation. Returns how
        many commands were attempted; the loop wrapper owns the backoff."""
        attempted = 0
        for pair, machine in self._machines.items():
            if not self._intent_settled(pair):
                continue
            if machine.outcome_retry().retry != "attempted":
                continue
            entry = self._active.get(pair)
            if entry is None:
                continue
            await self._attempt_command(pair, entry, machine)
            attempted += 1
        return attempted

    def _intent_settled(self, pair: tuple[str, str]) -> bool:
        """No durable write for this pair may cross an unsettled intent."""
        task = self._unsettled_intents.get(pair)
        if task is None:
            return True
        if not task.done():
            return False
        self._unsettled_intents.pop(pair, None)
        return True

    async def retry_records_once(self) -> int:
        """One pass of the persistence-recovery obligation, independent of
        the command retries and never re-issuing an accepted command."""
        recovered = 0
        for pair, machine in self._machines.items():
            if machine.record_state != "pending":
                continue
            if not self._intent_settled(pair):
                continue
            try:
                await self._journal.append_record(
                    *pair,
                    command_status=machine.command_status,
                    created_at_ms=now_ms(),
                )
                await self._journal.mark_resolved(*pair)
            except Exception:
                logger.exception("[safety] record recovery failed zone=%s", pair[0])
                continue
            machine.record_retry(committed=True)
            recovered += 1
        return recovered

    async def _safety_alert(
        self, pair: tuple[str, str], kind: str, message: str
    ) -> None:
        key = (pair, kind)
        now = int(self._clock())
        last = self._last_alert_ms.get(key)
        if last is not None and now - last < SAFETY_ALERT_SUPPRESSION_S * 1000:
            self._suppressed_alerts += 1
            return
        self._last_alert_ms[key] = now
        if self._alert_sink is None:
            logger.error("[safety] %s (no alert sink wired): %s", kind, message)
            return
        delivered = await self._alert_sink.send(
            kind=kind, zone_id=pair[0], profile_id=pair[1], message=message
        )
        if not delivered:
            logger.error(
                "[safety] %s notice not delivered or queued: %s", kind, message
            )

    async def watch_measurement_loss(self) -> None:
        """The per-pair loss watch: no credible reading for longer than the
        documented bound — five intervals, never sooner than the floor —
        degrades the pair, alerts under suppression, and holds the trip
        state, because v1 never opens a circuit on loss. It runs from
        configured intervals, so a sensor whose adapter never connected is
        watched from the start rather than absent. Degradation is recorded
        synchronously; the notice is awaited, not fired and forgotten."""
        now = int(self._clock())
        newly_lost: list[tuple[tuple[str, str], int, int]] = []
        for pair, entry in self._active.items():
            interval = self._poll_intervals_ms.get(entry.sensor_id, 0)
            bound = max(
                interval * MEASUREMENT_LOSS_INTERVALS, MEASUREMENT_LOSS_FLOOR_MS
            )
            last = self._last_credible_ms.get(pair, self._started_ms)
            if now - last <= bound or pair in self._measurement_degraded:
                continue
            self._measurement_degraded.add(pair)
            newly_lost.append((pair, now - last, bound))
        for pair, elapsed, bound in newly_lost:
            await self._safety_alert(
                pair,
                "measurement_loss",
                f"no credible reading for zone {pair[0]} profile {pair[1]} "
                f"in {elapsed} ms (bound {bound} ms); trip state held",
            )

    async def run_retry_loop(self, shutdown: asyncio.Event) -> None:
        """Bounded backoff, no terminal limit, stops only on shutdown; each
        pass also runs the measurement-loss watch, so its cadence is bounded
        by the backoff cap."""
        delay = RETRY_BACKOFF_BASE_S
        while not shutdown.is_set():
            await self.watch_measurement_loss()
            attempted = await self.retry_pending_once()
            attempted += await self.retry_records_once()
            delay = (
                RETRY_BACKOFF_BASE_S
                if attempted
                else min(delay * 2, RETRY_BACKOFF_CAP_S)
            )
            try:
                await asyncio.wait_for(shutdown.wait(), timeout=delay)
            except asyncio.TimeoutError:
                continue

    def health_snapshot(self) -> dict[str, Any]:
        return {
            "active": sorted(self._active),
            "pending_ratification": sorted(
                (p.zone_id, p.profile_id) for p in self.activation.pending
            ),
            "refused": sorted(
                (r.zone_id, r.profile_id, r.reason) for r in self.activation.refused
            ),
            "uncovered_zones": sorted(self.activation.uncovered_zones),
            "pairs": {
                f"{zone_id}/{profile_id}": {
                    "state": m.state,
                    "command_status": m.command_status,
                    "record": m.record_state,
                    "effect": m.effect,
                    "orphaned": m.orphaned,
                    "measurement_degraded": (zone_id, profile_id)
                    in self._measurement_degraded,
                    "rejected_input_active": (zone_id, profile_id)
                    in self._rejected_active,
                    "last_credible_at_ms": self._last_credible_ms.get(
                        (zone_id, profile_id)
                    ),
                }
                for (zone_id, profile_id), m in sorted(self._machines.items())
            },
            "suppressed_alerts": self._suppressed_alerts,
        }
