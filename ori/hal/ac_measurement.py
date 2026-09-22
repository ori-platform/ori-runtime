# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Turn a burst of ADC samples into an AC RMS measurement, or refuse it.

Kept apart from the adapter so the arithmetic can be driven by synthetic
waveforms. The hardware supplies samples and a monotonic elapsed time; every
decision about whether those samples constitute a measurement is made here.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Sequence


class WindowRefusedError(Exception):
    """The samples do not constitute a measurement.

    Raised rather than returning a sentinel: a refused window must not be able
    to reach a caller that treats it as a number.
    """


@dataclass(frozen=True)
class WindowSpec:
    """What a window must satisfy to be a measurement.

    A window is a fixed span of time, not a whole number of cycles. The loop
    paces at the conversion interval and stops on a deadline, and 860 samples
    a second does not divide a 50 Hz period, so the window runs a little past
    two cycles however correctly everything is configured. The mean is then
    not quite the bias and the root mean square not quite the amplitude.

    At the geometry the bench measured — 36 samples over 41.09 ms against a
    40.00 ms nominal — that floor is about 2%, and it is under every reading
    this path produces. `test_ac_measurement.py` holds it, along with the two
    facts that make it easy to reason about wrongly:

    - **A supply drifting inside its band does not add to it.** Where the
      window stops relative to a cycle is what decides the error, so 47 Hz can
      land closer to whole cycles than 50 Hz does and read better. Across
      45–53 Hz the error stays under 5% and moves in both directions.
    - **Declaring the wrong band does dominate it.** ``mains_frequency_hz`` is
      a declared fact that nothing here can check, and it sets the window
      length: two cycles at 60 Hz is 33 ms, which spans 1.67 cycles of a 50 Hz
      supply. That reaches about 7%, several times the geometry's own floor,
      and it is the only frequency error worth an operator's attention.

    **Every one of these is worse downward than upward.** The worst case is an
    under-report, which is a Tier D threshold reached later than it should be
    or not at all, so these bounds are not symmetric and must not be quoted as
    though they were.

    Deriving the frequency from the samples would close the wrong-band case,
    and is not done here yet. A matched filter over the two candidate bands
    would classify reliably at the amplitudes involved; what is undecided is
    what to do with a disagreement. Refusing the window removes protection to
    correct a few percent, which is the wrong trade — accumulating disagreement
    into the existing degraded-health and bounded-notice path removes none, and
    is the option to weigh once a clamp on a live load has shown what the noise
    actually looks like. Until then the declaration is a commissioning
    obligation and this is what getting it wrong costs.
    """

    mains_frequency_hz: float
    window_cycles: int
    min_samples: int
    full_scale_volts: float
    clip_margin_volts: float
    overrun_tolerance: float
    # Where the bias network should hold the input, and how far its components
    # and supply may move it. A window whose mean sits beyond that is not the
    # clamp's signal on the bias; see `summarise_window`.
    expected_bias_volts: float
    bias_tolerance_volts: float

    @property
    def nominal_seconds(self) -> float:
        return self.window_cycles / self.mains_frequency_hz


@dataclass(frozen=True)
class WindowResult:
    rms_volts: float
    bias_volts: float
    sample_count: int
    elapsed_s: float


def summarise_window(
    samples: Sequence[float], elapsed_s: float, spec: WindowSpec
) -> WindowResult:
    """Reduce one sampling window to an RMS voltage, or refuse it.

    Refusals are the point of this function. An AC clamp read at one arbitrary
    phase produces a plausible number that is not a measurement, and a threshold
    over such numbers is decided by sampling phase.
    """
    if len(samples) < spec.min_samples:
        raise WindowRefusedError(
            f"window held {len(samples)} samples, fewer than the {spec.min_samples} "
            "needed to resolve the waveform"
        )

    # Timing is checked before the arithmetic: samples spread over the wrong
    # interval do not span whole cycles, so their mean is not the bias and their
    # RMS is not the amplitude, however many of them there are.
    if elapsed_s <= 0:
        raise WindowRefusedError("window reported no elapsed time")
    if elapsed_s > spec.nominal_seconds * spec.overrun_tolerance:
        raise WindowRefusedError(
            f"window took {elapsed_s * 1000:.1f} ms against a nominal "
            f"{spec.nominal_seconds * 1000:.1f} ms"
        )

    ceiling = spec.full_scale_volts - spec.clip_margin_volts
    floor = spec.clip_margin_volts
    if any(sample >= ceiling or sample <= floor for sample in samples):
        raise WindowRefusedError(
            "a sample reached the usable limit of the input range; the signal "
            "is clipped and its amplitude is unknown"
        )

    # The bias is measured rather than assumed. A divider drifts with supply
    # and temperature, and a configured constant would silently become an
    # offset added to every reading.
    bias = math.fsum(samples) / len(samples)

    # But it must still be the bias. A disconnected input floats near 0.6 V and
    # picks up hum, which reduces to a small, steady, plausible current. The
    # allowance adds what the signal itself can move the mean: over a window
    # spanning at least one true cycle, a load without DC has a mean within a
    # quarter of its peak-to-peak of the bias, wherever the window starts. Two
    # declared cycles span one and a half at 45 Hz under a 60 Hz declaration,
    # so a mis-declared, sagging supply stays inside it. The bound is on the
    # waveform; the samples carry it only where they catch its peaks, so a pulse
    # narrower than the sample interval can still be refused.
    signal_allowance = (max(samples) - min(samples)) / 4
    allowed = spec.bias_tolerance_volts + signal_allowance
    offset = bias - spec.expected_bias_volts
    if abs(offset) > allowed:
        raise WindowRefusedError(
            f"window mean {bias:.3f} V is {offset:+.3f} V from the bias midpoint "
            f"{spec.expected_bias_volts:.3f} V, beyond the {allowed:.3f} V the bias "
            "network and the signal allow, so the window cannot be certified as the "
            "clamp's signal on its bias: the input may be disconnected, its bias "
            "network may have failed, or the samples did not resolve the waveform"
        )

    mean_square = math.fsum((sample - bias) ** 2 for sample in samples) / len(samples)
    return WindowResult(
        rms_volts=math.sqrt(mean_square),
        bias_volts=bias,
        sample_count=len(samples),
        elapsed_s=elapsed_s,
    )
