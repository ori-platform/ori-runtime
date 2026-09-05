# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Waveform tests for the AC measurement window.

Synthetic samples throughout: the arithmetic is separated from the ADC so that
the decision to accept or refuse a window can be driven exactly.
"""

from __future__ import annotations

import asyncio
import contextlib
import math
import sys
from typing import Any, cast

import pytest

from ori.actions.alert_failover import AlertFailoverSender
from ori.hal.ac_measurement import WindowRefusedError, WindowSpec, summarise_window


@contextlib.contextmanager
def _frozen_at(elapsed_ms: int):
    """Hold `ori.runtime.now_ms` at one instant.

    The schedule is a function of elapsed time, so every escalation test has
    to say what time it is. The module is resolved through `sys.modules`
    rather than imported a second time under an alias, since this file
    already imports from it.
    """
    # `sys.modules` is typed as a plain module, so the attribute this needs to
    # swap is invisible to the checker; resolved through it rather than
    # imported a second time under an alias.
    module = cast(Any, sys.modules["ori.runtime"])
    original = module.now_ms
    module.now_ms = lambda: int(elapsed_ms)
    try:
        yield
    finally:
        module.now_ms = original


SPEC = WindowSpec(
    mains_frequency_hz=50.0,
    window_cycles=2,
    min_samples=32,
    full_scale_volts=3.3,
    clip_margin_volts=0.05,
    overrun_tolerance=1.5,
)


def _sine(
    *,
    amplitude: float,
    bias: float = 1.65,
    phase: float = 0.0,
    count: int = 64,
    cycles: int = 2,
) -> list[float]:
    """A whole number of cycles, evenly spaced, as the hardware is asked for."""
    return [
        bias + amplitude * math.sin(2 * math.pi * cycles * i / count + phase)
        for i in range(count)
    ]


def test_a_steady_sine_reports_its_rms_amplitude() -> None:
    """The definition the whole path rests on: RMS is amplitude over root two."""
    amplitude = 1.0
    result = summarise_window(_sine(amplitude=amplitude), SPEC.nominal_seconds, SPEC)
    assert result.rms_volts == pytest.approx(amplitude / math.sqrt(2), rel=1e-3)


def test_no_signal_reports_no_current() -> None:
    """A flat line at the bias is zero amplitude, not zero volts."""
    result = summarise_window([1.65] * 64, SPEC.nominal_seconds, SPEC)
    assert result.rms_volts == pytest.approx(0.0, abs=1e-9)
    assert result.bias_volts == pytest.approx(1.65)


@pytest.mark.parametrize("bias", [1.20, 1.65, 2.10])
def test_the_bias_is_measured_rather_than_assumed(bias: float) -> None:
    """A divider drifts with supply and temperature.

    A configured constant would become an offset added to every reading, so the
    same waveform must measure the same regardless of where it sits.
    """
    result = summarise_window(
        _sine(amplitude=0.8, bias=bias), SPEC.nominal_seconds, SPEC
    )
    assert result.rms_volts == pytest.approx(0.8 / math.sqrt(2), rel=1e-3)
    assert result.bias_volts == pytest.approx(bias, rel=1e-6)


@pytest.mark.parametrize("phase", [0.0, math.pi / 4, math.pi / 2, math.pi])
def test_the_result_does_not_depend_on_where_sampling_began(phase: float) -> None:
    """The defect this replaces: one sample at an arbitrary phase.

    A steady load read instantaneously scatters between zero and peak depending
    on when the poll landed. Over whole cycles the starting phase cannot matter.
    """
    result = summarise_window(
        _sine(amplitude=1.0, phase=phase), SPEC.nominal_seconds, SPEC
    )
    assert result.rms_volts == pytest.approx(1.0 / math.sqrt(2), rel=1e-3)


def test_a_clipped_waveform_is_refused_rather_than_under_reported() -> None:
    """Clipping removes the peaks, so RMS reads low — an under-report.

    Under-reporting is the dangerous direction: the current is higher than the
    number says, which is exactly when a cutoff must not be talked out of firing.
    """
    samples = [min(s, 3.28) for s in _sine(amplitude=2.0)]
    with pytest.raises(WindowRefusedError, match="clipped"):
        summarise_window(samples, SPEC.nominal_seconds, SPEC)


def test_a_waveform_touching_the_lower_rail_is_refused_too() -> None:
    """Clipping is symmetric; only checking the ceiling would miss half of it.

    The bias sits low here on purpose. A waveform large enough to hit the floor
    while also exceeding the ceiling is caught by the ceiling, so it says
    nothing about whether the floor is checked at all.
    """
    samples = [max(sample, 0.02) for sample in _sine(amplitude=0.6, bias=0.5)]
    assert max(samples) < SPEC.full_scale_volts - SPEC.clip_margin_volts, (
        "this waveform must not reach the ceiling, or it tests the wrong branch"
    )
    with pytest.raises(WindowRefusedError, match="clipped"):
        summarise_window(samples, SPEC.nominal_seconds, SPEC)


def test_too_few_samples_are_refused() -> None:
    """Below the sample floor the waveform is not resolved, only guessed at."""
    with pytest.raises(WindowRefusedError, match="fewer than"):
        summarise_window(_sine(amplitude=1.0, count=16), SPEC.nominal_seconds, SPEC)


def test_a_window_that_overran_is_refused_however_many_samples_it_holds() -> None:
    """Sample count alone is not evidence the window spanned whole cycles.

    Samples spread over the wrong interval do not cover an integer number of
    cycles, so their mean is not the bias and their RMS is not the amplitude.
    """
    with pytest.raises(WindowRefusedError, match="against a nominal"):
        summarise_window(
            _sine(amplitude=1.0, count=256),
            SPEC.nominal_seconds * 2.0,
            SPEC,
        )


def test_a_window_with_no_elapsed_time_is_refused() -> None:
    """A clock that did not advance cannot have timed anything."""
    with pytest.raises(WindowRefusedError, match="no elapsed time"):
        summarise_window(_sine(amplitude=1.0), 0.0, SPEC)


def test_refusal_is_checked_before_the_arithmetic_runs() -> None:
    """Ordering matters: a bad window must not be reduced to a number first.

    Timing is judged before clipping and before the mean, so a caller cannot
    receive a plausible figure derived from samples that were never valid.
    """
    clipped_and_overrun = [3.29] * 256
    with pytest.raises(WindowRefusedError) as raised:
        summarise_window(clipped_and_overrun, SPEC.nominal_seconds * 5, SPEC)
    assert "against a nominal" in str(raised.value)


# ── refusal handling in the runtime ───────────────────────────────────────────


class _Runtime:
    """The refusal bookkeeping, lifted off OriRuntime so it can be driven directly."""

    def __init__(self) -> None:
        from ori.runtime import OriRuntime

        self.runtime = OriRuntime.__new__(OriRuntime)
        self.runtime._measurement_refusals = {}
        self.runtime._measurement_valid_streak = {}
        self.runtime._measurement_degraded = set()
        self.runtime._measurement_unnotified = set()
        self.runtime._measurement_notify_attempts = {}
        self.runtime._measurement_degraded_since = {}
        self.runtime._measurement_notice_stage = {}
        self.runtime._secondary_contact = ""
        self.runtime._alert_sender = None
        self.runtime._state_store = None
        self.runtime._operator_contact = "+2340000000000"
        self.runtime._primary_alert_channel = "sms"
        self.alerts: list[str] = []

        async def _capture(**kwargs: object) -> bool:
            self.alerts.append(str(kwargs.get("sensor_id")))
            # Delivered or durably queued; the runtime records it as reported
            # only on a True answer.
            return True

        self.runtime._emit_measurement_degraded_warning = _capture  # type: ignore[method-assign]

    async def refuse(self, times: int, sensor_id: str = "load-current") -> None:
        for _ in range(times):
            await self.runtime._note_measurement_refusal(
                sensor_id=sensor_id, detail="clipped"
            )

    async def accept(self, times: int, sensor_id: str = "load-current") -> None:
        for _ in range(times):
            await self.runtime._note_measurement_accepted(sensor_id)

    @property
    def degraded(self) -> set:
        return self.runtime._measurement_degraded


async def test_a_single_refusal_does_not_degrade_a_sensor() -> None:
    """One refused window is a transient the next poll retries."""
    harness = _Runtime()
    await harness.refuse(1)
    assert harness.degraded == set()
    assert harness.alerts == []


async def test_a_run_of_refusals_degrades_and_alerts_once() -> None:
    """Silence is the failure mode: a sensor that stopped measuring reads as absent.

    The alert fires on the transition rather than per window, so a persistent
    fault does not become a message flood.
    """
    from ori.runtime import MEASUREMENT_REFUSALS_BEFORE_DEGRADED

    harness = _Runtime()
    await harness.refuse(MEASUREMENT_REFUSALS_BEFORE_DEGRADED)
    assert harness.degraded == {"load-current"}
    assert harness.alerts == ["load-current"]

    await harness.refuse(20)
    assert harness.alerts == ["load-current"], "the alert repeated per window"


async def test_recovery_needs_a_run_of_valid_windows() -> None:
    """Recovery is slower than failure on purpose.

    A path that alternates is not coming back, and flapping would produce an
    alert stream operators learn to ignore.
    """
    from ori.runtime import (
        MEASUREMENT_REFUSALS_BEFORE_DEGRADED,
        MEASUREMENT_WINDOWS_TO_RECOVER,
    )

    harness = _Runtime()
    await harness.refuse(MEASUREMENT_REFUSALS_BEFORE_DEGRADED)
    await harness.accept(MEASUREMENT_WINDOWS_TO_RECOVER - 1)
    assert harness.degraded == {"load-current"}, "recovered before the run completed"

    await harness.accept(1)
    assert harness.degraded == set()


async def test_one_refusal_restarts_the_recovery_run() -> None:
    """Alternating windows must not accumulate toward recovery."""
    from ori.runtime import (
        MEASUREMENT_REFUSALS_BEFORE_DEGRADED,
        MEASUREMENT_WINDOWS_TO_RECOVER,
    )

    harness = _Runtime()
    await harness.refuse(MEASUREMENT_REFUSALS_BEFORE_DEGRADED)
    for _ in range(4):
        await harness.accept(MEASUREMENT_WINDOWS_TO_RECOVER - 1)
        await harness.refuse(1)
    assert harness.degraded == {"load-current"}


# ── durable measurement state ─────────────────────────────────────────────────


async def _store(tmp_path, name: str = "state.db"):
    from ori.state.store import StateStore

    store = StateStore(str(tmp_path / name))
    await store.open()
    return store


async def test_a_fresh_database_knows_of_no_degraded_sensors(tmp_path) -> None:
    store = await _store(tmp_path)
    assert await store.get_measurement_degradation() == {}
    await store.close()


async def test_degradation_and_its_notified_flag_survive_a_reopen(tmp_path) -> None:
    """The whole point of persisting it: a restart must not lose either fact."""
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=False)
    await store.set_measurement_degraded("grid-voltage", notified=True)
    assert await store.get_measurement_degradation() == {
        "load-current": False,
        "grid-voltage": True,
    }
    await store.close()

    reopened = await _store(tmp_path)
    assert await reopened.get_measurement_degradation() == {
        "load-current": False,
        "grid-voltage": True,
    }
    await reopened.close()


async def test_a_pending_notification_becomes_notified_and_stays_that_way(
    tmp_path,
) -> None:
    """Once reported, stays reported.

    A later write that has not itself notified must not reopen the alert, or a
    persistent fault would re-warn on every refusal that follows.
    """
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=False)
    assert await store.get_measurement_degradation() == {"load-current": False}

    await store.set_measurement_degraded("load-current", notified=True)
    assert await store.get_measurement_degradation() == {"load-current": True}

    await store.set_measurement_degraded("load-current", notified=False)
    assert await store.get_measurement_degradation() == {"load-current": True}
    await store.close()


async def test_recovery_survives_a_reopen(tmp_path) -> None:
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=True)
    await store.clear_measurement_degraded("load-current")
    assert await store.get_measurement_degradation() == {}
    await store.close()

    reopened = await _store(tmp_path)
    assert await reopened.get_measurement_degradation() == {}
    await reopened.close()


async def test_recovery_clears_the_notified_flag_so_a_later_fault_warns_again(
    tmp_path,
) -> None:
    """A sensor that recovered and failed again is a new fault, not the old one."""
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=True)
    await store.clear_measurement_degraded("load-current")
    await store.set_measurement_degraded("load-current", notified=False)
    assert await store.get_measurement_degradation() == {"load-current": False}
    await store.close()


async def test_repeated_writes_are_idempotent(tmp_path) -> None:
    store = await _store(tmp_path)
    for _ in range(5):
        await store.set_measurement_degraded("load-current", notified=True)
    assert await store.get_measurement_degradation() == {"load-current": True}
    for _ in range(5):
        await store.clear_measurement_degraded("load-current")
    assert await store.get_measurement_degradation() == {}
    await store.close()


# ─── Persistent measurement loss escalates (ori-platform/ori-runtime#510) ──────


class _EscalationHarness:
    """The escalation schedule, driven directly off `OriRuntime`.

    A device that could not establish a trustworthy measurement said so once
    and then waited indefinitely for a person. These drive what keeps saying
    it, and to whom.
    """

    def __init__(self, *, secondary: str = "+2349999999999") -> None:
        from ori.runtime import OriRuntime

        self.runtime = OriRuntime.__new__(OriRuntime)
        self.runtime._measurement_degraded = {"load-current"}
        self.runtime._measurement_unnotified = set()
        self.runtime._measurement_degraded_since = {"load-current": 0}
        self.runtime._measurement_notice_stage = {"load-current": 0}
        self.runtime._measurement_notify_attempts = {}
        self.runtime._state_store = None
        self.runtime._alert_sender = cast(AlertFailoverSender, object())
        self.runtime._operator_contact = "+2340000000000"
        self.runtime._secondary_contact = secondary
        self.runtime._primary_alert_channel = "sms"
        self.sent: list[tuple[str, str]] = []
        self.deliverable = True

        async def _send(**kwargs: object) -> bool:
            if not self.deliverable:
                return False
            self.sent.append((str(kwargs["recipient"]), str(kwargs["message"])))
            return True

        # The structural, policy-exempt route. An entitlement cap must not be
        # able to silence a notice that a channel is not being measured.
        self.runtime._send_or_queue_safety_alert = _send  # type: ignore[method-assign]

        async def _policy_gated(**kwargs: object) -> bool:
            raise AssertionError(
                "measurement escalation must not use the policy-gated path"
            )

        self.runtime._send_or_queue_alert = _policy_gated  # type: ignore[method-assign]

    async def tick(self, at_hours: float) -> None:
        with _frozen_at(int(at_hours * 60 * 60 * 1000)):
            await self.runtime._escalate_persistent_measurement_loss()


def test_the_schedule_is_a_function_of_elapsed_time_alone():
    """Stage 0 immediate, 1 at six hours, 2 at twelve, then daily."""
    from ori.runtime import measurement_notice_stage_due as due

    hour = 60 * 60 * 1000
    assert due(0) == 0
    assert due(5 * hour) == 0
    assert due(6 * hour) == 1
    assert due(11 * hour) == 1
    assert due(12 * hour) == 2
    assert due(35 * hour) == 2
    assert due(36 * hour) == 3
    assert due(60 * hour) == 4
    # No terminal stage: a still-unprotected channel never becomes silent.
    assert due(365 * 24 * hour) > 300


async def test_a_reminder_goes_to_the_primary_contact_at_six_hours():
    harness = _EscalationHarness()

    await harness.tick(1)
    assert harness.sent == []

    await harness.tick(6)
    assert [recipient for recipient, _ in harness.sent] == ["+2340000000000"]


async def test_the_escalation_goes_to_the_secondary_contact_at_twelve_hours():
    harness = _EscalationHarness()
    await harness.tick(6)
    harness.sent.clear()

    await harness.tick(12)

    assert [recipient for recipient, _ in harness.sent] == ["+2349999999999"]


async def test_the_escalation_repeats_daily_to_the_secondary_contact():
    harness = _EscalationHarness()
    await harness.tick(12)
    harness.sent.clear()

    await harness.tick(35)
    assert harness.sent == []

    await harness.tick(36)
    await harness.tick(60)

    assert [recipient for recipient, _ in harness.sent] == [
        "+2349999999999",
        "+2349999999999",
    ]


async def test_a_device_with_no_secondary_contact_still_escalates():
    """One contact is not a reason to go silent about an unprotected channel."""
    harness = _EscalationHarness(secondary="")

    await harness.tick(12)

    assert [recipient for recipient, _ in harness.sent] == ["+2340000000000"]


async def test_a_stage_is_resent_until_it_gets_out():
    harness = _EscalationHarness()
    harness.deliverable = False

    await harness.tick(6)
    assert harness.sent == []
    assert harness.runtime._measurement_notice_stage["load-current"] == 0

    harness.deliverable = True
    await harness.tick(7)

    assert len(harness.sent) == 1


async def test_an_undelivered_reminder_does_not_cancel_the_next_escalation():
    """The schedule advances on time, not on delivery.

    Otherwise a device whose six-hour reminder could not be sent would never
    reach the twelve-hour escalation, and the one operator who was already
    unreachable would be the only one ever told.
    """
    harness = _EscalationHarness()
    harness.deliverable = False
    await harness.tick(6)
    assert harness.sent == []

    harness.deliverable = True
    await harness.tick(12)

    assert [recipient for recipient, _ in harness.sent] == ["+2349999999999"]


async def test_the_escalation_runs_even_when_the_first_notice_never_got_out():
    """The case where the operator knows least must not be the silent one.

    The notice on the transition has bounded retries, so blocking the
    schedule until it succeeds makes the block permanent once they are spent:
    a device whose primary contact is unreachable would never reach the
    secondary at all.
    """
    harness = _EscalationHarness()
    harness.runtime._measurement_unnotified = {"load-current"}

    await harness.tick(12)

    assert [recipient for recipient, _ in harness.sent] == ["+2349999999999"]


async def test_a_stage_states_the_fault_when_the_first_notice_was_not_delivered():
    """It cannot recall a notice nobody received."""
    harness = _EscalationHarness()
    harness.runtime._measurement_unnotified = {"load-current"}

    await harness.tick(12)

    message = harness.sent[0][1]
    assert "could not be delivered" in message
    assert "still not produced" not in message


async def test_a_degradation_with_no_recorded_start_is_anchored_not_flooded():
    harness = _EscalationHarness()
    harness.runtime._measurement_degraded_since = {}

    await harness.tick(48)

    assert harness.sent == []
    assert harness.runtime._measurement_degraded_since["load-current"] == 48 * 3600000


async def test_the_reminder_never_claims_anything_was_restored():
    harness = _EscalationHarness()

    await harness.tick(12)

    message = harness.sent[0][1]
    assert "Nothing has been restored" in message
    assert "not running" in message
    for word in ("restored protection", "resolved", "recovered", "fixed"):
        assert word not in message.lower().replace("nothing has been restored", "")


async def test_the_staleness_loop_drives_the_escalation():
    """The join, not the mechanism.

    Every other escalation test reaches
    `_escalate_persistent_measurement_loss` directly, so none of them
    observes that anything calls it. Without this one, deleting its call site
    would leave a persistent measurement loss reported once and then
    forgotten while the rest of the suite stayed green.
    """
    harness = _EscalationHarness()
    runtime = harness.runtime
    runtime._sensor_poll_interval_ms = {}
    runtime._sensor_last_seen_ms = {}
    runtime._stale_sensor_active = set()
    runtime._shutdown_event = asyncio.Event()

    with _frozen_at(12 * 60 * 60 * 1000):
        task = asyncio.create_task(
            runtime._sensor_staleness_loop(
                alert_sender=cast(AlertFailoverSender, object()),
                check_interval_s=3600.0,
            )
        )
        for _ in range(20):
            await asyncio.sleep(0)
            if harness.sent:
                break
        runtime._shutdown_event.set()
        await asyncio.wait_for(task, 5)

    assert [recipient for recipient, _ in harness.sent] == ["+2349999999999"]


async def test_the_notice_schedule_survives_a_reopen(tmp_path) -> None:
    """A restart must not restart the escalation clock.

    Without persistence a crash-looping device postpones every escalation
    forever: each start re-anchors the degradation to now, and the six-hour
    reminder is never due.
    """
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=True)
    await store.set_measurement_notice_stage("load-current", 2)
    schedule = await store.get_measurement_notice_schedule()
    began, stage = schedule["load-current"]
    await store.close()

    reopened = await _store(tmp_path)
    try:
        assert await reopened.get_measurement_notice_schedule() == {
            "load-current": (began, 2)
        }
    finally:
        await reopened.close()
    assert stage == 2


async def test_a_second_degradation_write_does_not_move_the_start(tmp_path) -> None:
    """The schedule is measured from when measurement was lost."""
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=False)
    began = (await store.get_measurement_notice_schedule())["load-current"][0]

    await store.set_measurement_degraded("load-current", notified=True)

    assert (await store.get_measurement_notice_schedule())["load-current"][0] == began
    await store.close()


async def test_recovery_clears_the_schedule(tmp_path) -> None:
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=True)
    await store.set_measurement_notice_stage("load-current", 3)

    await store.clear_measurement_degraded("load-current")

    assert await store.get_measurement_notice_schedule() == {}
    await store.close()


async def test_a_row_written_before_the_schedule_columns_dates_from_its_last_write(
    tmp_path,
) -> None:
    """An upgrade must not restart the schedule for an already-degraded sensor.

    A row from before these columns existed carries no start, so it is dated
    to its last write rather than to now. Dating it to now would postpone
    every escalation by the age of the degradation, on exactly the devices
    that have been unprotected longest.
    """
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=True)
    legacy_updated_at = 1_700_000_000_000
    store._conn.execute(  # type: ignore[union-attr]
        "UPDATE sensor_measurement_state SET degraded_since = NULL, "
        "notice_stage = 0, updated_at = ? WHERE sensor_id = ?",
        (legacy_updated_at, "load-current"),
    )
    store._conn.commit()  # type: ignore[union-attr]

    assert await store.get_measurement_notice_schedule() == {
        "load-current": (legacy_updated_at, 0)
    }
    await store.close()


async def test_the_runtime_restores_the_schedule_and_sends_the_stage_that_is_due(
    tmp_path,
) -> None:
    """Store write, reopen, restoration through the startup seam, next stage.

    Driven through `_restore_measurement_state`, the same call startup makes,
    rather than by reassigning the fields it sets. Rebuilding them by hand
    would let the durable join drift from what a restart actually does and
    the test would not notice.
    """
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=True)
    began = (await store.get_measurement_notice_schedule())["load-current"][0]
    await store.set_measurement_notice_stage("load-current", 1)
    await store.close()

    reopened = await _store(tmp_path)
    harness = _EscalationHarness()
    runtime = harness.runtime
    runtime._state_store = reopened
    await runtime._restore_measurement_state()

    assert runtime._measurement_degraded == {"load-current"}
    assert runtime._measurement_notice_stage == {"load-current": 1}
    assert runtime._measurement_unnotified == set()

    with _frozen_at(began + 12 * 60 * 60 * 1000):
        await runtime._escalate_persistent_measurement_loss()

    # Stage 1 was sent before the restart and is not repeated; stage 2 is due
    # and goes to the secondary contact.
    assert [recipient for recipient, _ in harness.sent] == ["+2349999999999"]
    assert (await reopened.get_measurement_notice_schedule())["load-current"][1] == 2
    await reopened.close()


async def test_a_delivered_escalation_stops_the_initial_notice_being_retried(
    tmp_path,
) -> None:
    """Failed initial, delivered secondary, restart, further refusal.

    The initial notice to the primary contact never got out, so the
    degradation is recorded un-notified. The twelve-hour escalation reaches
    the secondary contact. If only the stage were recorded, a restart would
    find the degradation still marked un-notified and send the initial
    warning again — to the primary, about a fault the secondary already has,
    at the cost of another message.
    """
    store = await _store(tmp_path)
    # The transition: degraded, and the notice did not get out.
    await store.set_measurement_degraded("load-current", notified=False)
    began = (await store.get_measurement_notice_schedule())["load-current"][0]

    harness = _EscalationHarness()
    runtime = harness.runtime
    runtime._state_store = store
    await runtime._restore_measurement_state()
    assert runtime._measurement_unnotified == {"load-current"}

    with _frozen_at(began + 12 * 60 * 60 * 1000):
        await runtime._escalate_persistent_measurement_loss()

    assert [recipient for recipient, _ in harness.sent] == ["+2349999999999"]
    assert runtime._measurement_unnotified == set()
    await store.close()

    # Restart, and a further refused window.
    reopened = await _store(tmp_path)
    restarted = _EscalationHarness()
    restarted.runtime._state_store = reopened
    await restarted.runtime._restore_measurement_state()

    assert restarted.runtime._measurement_unnotified == set()

    initial_notices: list[str] = []

    async def _initial(**kwargs: object) -> bool:
        initial_notices.append(str(kwargs.get("sensor_id")))
        return True

    restarted.runtime._emit_measurement_degraded_warning = _initial  # type: ignore[method-assign]
    restarted.runtime._measurement_refusals = {"load-current": 9}
    restarted.runtime._measurement_valid_streak = {}
    await restarted.runtime._note_measurement_refusal(
        sensor_id="load-current", detail="still refused"
    )

    assert initial_notices == []


async def test_the_notice_on_the_transition_is_policy_exempt() -> None:
    """An entitlement cap must not silence it.

    `DevicePolicy` can suppress an ordinary Tier A alert at a monthly cap.
    Suppressing this one leaves an operator believing a measurement is being
    taken that is not, which is the fact the notice exists to carry, so it
    takes the structural route that consults no policy and moves no
    policy-counted counter.
    """
    from ori.runtime import OriRuntime

    runtime = OriRuntime.__new__(OriRuntime)
    runtime._alert_sender = cast(AlertFailoverSender, object())
    runtime._operator_contact = "+2340000000000"
    runtime._primary_alert_channel = "sms"
    structural: list[str] = []

    async def _structural(**kwargs: object) -> bool:
        structural.append(str(kwargs["trigger_name"]))
        return True

    async def _policy_gated(**kwargs: object) -> bool:
        raise AssertionError(
            "the measurement degradation notice must not consult DevicePolicy"
        )

    runtime._send_or_queue_safety_alert = _structural  # type: ignore[method-assign]
    runtime._send_or_queue_alert = _policy_gated  # type: ignore[method-assign]

    sent = await runtime._emit_measurement_degraded_warning(
        sensor_id="load-current", refusals=3
    )

    assert sent is True
    assert structural == ["measurement_degraded:load-current"]


async def test_the_stage_and_the_notified_mark_are_written_together(tmp_path) -> None:
    """One transaction, so a crash cannot land half of it.

    Written as two statements, an interruption between them leaves the disk
    saying a later stage was sent while still saying nobody was notified, and
    the next start sends the notice for the transition again.
    """
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=False)
    began = (await store.get_measurement_notice_schedule())["load-current"][0]
    assert await store.get_measurement_degradation() == {"load-current": False}

    await store.record_measurement_notice_delivered(
        "load-current", 2, degraded_since=began
    )

    await store.close()
    reopened = await _store(tmp_path)
    try:
        assert await reopened.get_measurement_degradation() == {"load-current": True}
        assert (await reopened.get_measurement_notice_schedule())["load-current"][
            1
        ] == 2
    finally:
        await reopened.close()


async def test_a_failed_record_leaves_the_operator_still_owed_the_notice(
    tmp_path,
) -> None:
    """The split failure, forced: the write does not land at all.

    Neither disk fact moves, and the in-memory set still says the operator is
    owed the notice on the transition, so the initial retry keeps owning this
    sensor rather than the runtime believing a message got out that did not.
    """
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=False)
    began = (await store.get_measurement_notice_schedule())["load-current"][0]

    harness = _EscalationHarness()
    runtime = harness.runtime
    runtime._state_store = store
    await runtime._restore_measurement_state()

    async def _fails(sensor_id: str, stage: int, *, degraded_since: int) -> None:
        raise RuntimeError("disk gone")

    store.record_measurement_notice_delivered = _fails  # type: ignore[method-assign]

    with _frozen_at(began + 12 * 60 * 60 * 1000):
        await runtime._escalate_persistent_measurement_loss()

    assert len(harness.sent) == 1
    assert runtime._measurement_unnotified == {"load-current"}
    assert await store.get_measurement_degradation() == {"load-current": False}
    assert (await store.get_measurement_notice_schedule())["load-current"][1] == 0
    await store.close()


async def test_a_failing_store_does_not_turn_every_pass_into_another_message(
    tmp_path,
) -> None:
    """The stage advances in memory even when the write fails.

    Otherwise a store that is failing makes the loop resend the same stage on
    every pass, which is a message flood rather than a bounded repeat.
    """
    store = await _store(tmp_path)
    await store.set_measurement_degraded("load-current", notified=True)
    began = (await store.get_measurement_notice_schedule())["load-current"][0]

    harness = _EscalationHarness()
    runtime = harness.runtime
    runtime._state_store = store
    await runtime._restore_measurement_state()

    async def _fails(sensor_id: str, stage: int, *, degraded_since: int) -> None:
        raise RuntimeError("disk gone")

    store.record_measurement_notice_delivered = _fails  # type: ignore[method-assign]

    with _frozen_at(began + 12 * 60 * 60 * 1000):
        await runtime._escalate_persistent_measurement_loss()
        await runtime._escalate_persistent_measurement_loss()
        await runtime._escalate_persistent_measurement_loss()

    assert len(harness.sent) == 1
    await store.close()


async def test_an_escalation_reconstructs_a_row_the_first_write_never_created(
    tmp_path,
) -> None:
    """Transient store failure, recovery, delivered escalation, restart.

    The write that records the degradation is allowed to fail — a store
    failure is logged and must not stop polling — so the disk can hold no row
    at all while the runtime knows perfectly well that the sensor is
    degraded. If a later escalation writes with an `UPDATE`, it matches
    nothing, raises nothing, and the runtime marks the operator as told about
    a degradation the disk has never heard of; the next start finds no
    degraded sensor and forgets the measurement loss entirely.
    """
    store = await _store(tmp_path)
    harness = _EscalationHarness()
    runtime = harness.runtime
    runtime._state_store = store

    # The transition happened, and the store was unavailable for it.
    began = 1_700_000_000_000
    runtime._measurement_degraded = {"load-current"}
    runtime._measurement_degraded_since = {"load-current": began}
    runtime._measurement_notice_stage = {"load-current": 0}
    runtime._measurement_unnotified = {"load-current"}
    assert await store.get_measurement_degradation() == {}

    # The store recovers, and the twelve-hour escalation is delivered.
    with _frozen_at(began + 12 * 60 * 60 * 1000):
        await runtime._escalate_persistent_measurement_loss()

    assert [recipient for recipient, _ in harness.sent] == ["+2349999999999"]
    await store.close()

    reopened = await _store(tmp_path)
    try:
        restarted = _EscalationHarness()
        restarted.runtime._state_store = reopened
        await restarted.runtime._restore_measurement_state()

        # The loss is still known, dated to when it happened rather than to
        # when the disk caught up, and the operator is not owed the notice
        # for the transition a second time.
        assert restarted.runtime._measurement_degraded == {"load-current"}
        assert restarted.runtime._measurement_degraded_since == {"load-current": began}
        assert restarted.runtime._measurement_notice_stage == {"load-current": 2}
        assert restarted.runtime._measurement_unnotified == set()
    finally:
        await reopened.close()


async def test_a_write_for_an_absent_row_creates_it(tmp_path) -> None:
    """The upsert never lands on nothing.

    A plain `UPDATE` here matches no row, raises nothing, and reports success
    for a write that changed nothing. The row is created instead, so the
    degradation the caller is recording a notice about exists on disk
    afterwards whether or not it did before.
    """
    store = await _store(tmp_path)
    try:
        await store.record_measurement_notice_delivered(
            "never-degraded", 2, degraded_since=1_700_000_000_000
        )
        assert await store.get_measurement_degradation() == {"never-degraded": True}
    finally:
        await store.close()
