# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Waveform tests for the AC measurement window.

Synthetic samples throughout: the arithmetic is separated from the ADC so that
the decision to accept or refuse a window can be driven exactly.
"""

from __future__ import annotations

import math

import pytest

from ori.hal.ac_measurement import WindowRefusedError, WindowSpec, summarise_window

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
