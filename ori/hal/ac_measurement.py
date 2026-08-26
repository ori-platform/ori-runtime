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
    """What a window must satisfy to be a measurement."""

    mains_frequency_hz: float
    window_cycles: int
    min_samples: int
    full_scale_volts: float
    clip_margin_volts: float
    overrun_tolerance: float

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
    mean_square = math.fsum((sample - bias) ** 2 for sample in samples) / len(samples)
    return WindowResult(
        rms_volts=math.sqrt(mean_square),
        bias_volts=bias,
        sample_count=len(samples),
        elapsed_s=elapsed_s,
    )
