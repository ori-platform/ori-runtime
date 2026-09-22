# The calibrated current path, measured on the bench Pi against a filament lamp

**Result: the release's `ads1115_current` path reads a real mains current on
the target, is linear to within 2% from 0.5 A to 2.4 A once the supply's own
drift is removed, and refuses a window that reaches the input rail. Its
absolute calibration is the clamp's label, and the reading is consistent with
that label within what a residential supply allows. A disconnected input was
also read as a full-quality current, which is recorded here and tracked
separately.**

Run on the bench Raspberry Pi 4 Model B, Raspberry Pi OS Trixie, runtime
v2.5.0rc8 as installed by the release installer, on 2026-09-22. The runtime
service was active and produced every figure below through its own adapter;
raw captures used the same driver and chip with the service stopped, and are
labelled as such.

## The setup

- ADS1115 at `0x48`, gain 1, `data_rate: 860`, A0 single-ended.
- Bias network: 10 kΩ from the Pi's 3.3 V to a midpoint row, 10 kΩ from that
  row to a Pi ground pin, 10 µF from the row to ground. The Pi's rails are used
  directly; no breadboard rail carries anything.
- Clamp: SCT-013-030, voltage output, 30 A : 1 V, plug cut off. One core to
  the midpoint row, the other to A0. `sensitivity_v_per_amp: 0.0333`,
  `mains_frequency_hz: 50`.
- Load: a 100 W incandescent lamp, marked 220–240 V, on a fused plug, with the
  outer sheath of its flex removed over 40 cm so the live conductor alone
  passes through the clamp. The neutral stays outside the jaws.
- Supply for the linearity series: the house mains, voltage not measured. An
  earlier part of the session ran on a generator whose panel read 200–220 V
  at 52 Hz; no figure from that supply is used below.

## The chain, before any load

| Reading | Value |
| --- | --- |
| A0 with the clamp on nothing, raw | 1.635 V, spread 0.6 mV over 20 reads |
| Runtime `bias_volts` | 1.638 V |
| Runtime no-load current | 0.016 to 0.037 A |
| Samples per 40 ms window | 35, `quality` 1.0 |

The midpoint row read on A1 as a control gives the same 1.638 V, so the
clamp's own resistance drops nothing measurable. With the clamp on five passes
of the lamp's live conductor, a raw capture at the chip and the runtime's
window gave the same 12.7 mV RMS, and the raw waveform was a clean sine at the
generator's 52 Hz. The runtime's reduction of a window to an RMS current is
therefore the chip's own figure, on the target.

## Linearity by turns

The reference is the clamp's turns ratio. The same conductor passes through
the window one to five times, so the clamp sees the lamp's current
multiplied by the count while the current itself does not change. Five passes
of this flex fill the window and need care to close with the faces meeting.
Forty windows per point, on mains, in this order:

| Turns | Mean | Spread | Per turn |
| --- | --- | --- | --- |
| 1 | 0.502 A | 0.479 to 0.519 | 0.502 A |
| 2 | 0.987 A | 0.944 to 1.010 | 0.494 A |
| 4 | 1.895 A | 1.805 to 1.984 | 0.474 A |
| 3 | 1.425 A | 1.402 to 1.456 | 0.475 A |
| 1, repeated | 0.480 A | 0.470 to 0.494 | 0.480 A |
| 5 | 2.406 A | 2.360 to 2.502 | 0.481 A |

The single-turn figure fell 4.5% between the first and last points with
nothing on the bench changed, so the lamp's current itself drifted, which on a
filament is the supply voltage moving. Against the later single-turn figure,
three, four and five turns are within 1.5% of linear, and five is within
0.3%; against the earlier one, within 6%. The path is linear to the precision
this bench can hold, and its remaining scatter is the supply, not the sensor.

## What that settles, and what it does not

**Settled.** The bias network, the window, the RMS reduction and the quality
gate all work on the supported hardware with a real mains current. The
sensitivity constant, the sample floor and the window geometry produce a
figure that scales with the current the way a current transformer must. A
100 W filament reads about 0.48 to 0.50 A per turn on this supply.

**Absolute calibration.** The calibration constant is the clamp's label,
30 A : 1 V. A 100 W filament at a nominal 230 V draws 0.43 A; the reading
is 10 to 15% above that, and it moved 4.5% during the series with nothing
on the bench changed. A residential supply is not held to its nominal
voltage, so a comparison against a computed nominal current is bounded by
the supply's excursion, not by the sensor, and the readings sit inside that
bound. No reference instrument was on the bench. A simultaneous reference on
the same conductor, which sees the same instant and so removes the supply
from the comparison, would tighten this to the instrument's own tolerance;
that comparison is not part of this record.

**Clipping.** Five turns of a 100 W lamp reach 2.4 A, and the input clips
near 35 A of clamp current, so no load on this bench reaches the top of the
range through the clamp. The refusal itself was exercised at the bottom rail:
with A0 taken to ground, every window was refused as clipped with its
amplitude declared unknown, the sensor was marked degraded, and the adapter's
breaker opened after five refusals. Recovery needed a service restart; the
adapter does not reconnect on its own.

**Population.** One clamp, one ADS1115, one lamp. Nothing here is a statement
about the supported set.

## Two things the bench taught, recorded so they are not relearned

**A conductor in the jaw's parting slit is not in the window.** Closed on a
wire lying across the gap where the moving jaw meets the body, the core does
not shut, the coil catches leakage only, and the reading is an unrepeatable
fraction of the truth: single-turn readings of 0.072, 0.040, 0.020 and 0.000 A
in successive closures, and no change when the jaws were opened. The wire must
pass into the square window on one face and out on the other. The open jaw is
the only view that shows the difference, and a closed-jaw photograph does not.

**A disconnected input reads as a current.** With the A0 lead removed and the
lamp lit on the bench beside the wiring, the runtime reported 0.041 to 0.070 A
at `quality` 1.0 from an input floating at 0.598 V, and logged the sensor as
recovered. With the clamp not coupled to the conductor, as above, it read the
noise floor at the correct bias. Both are a sensor that has stopped observing
the circuit while the runtime publishes a plausible number. The first is
decidable from `bias_volts`; the second is not decidable from the signal.
That is tracked as its own defect.
