# A disconnected clamp input, refused on the bench Pi

**Result: with the midpoint check, the `ads1115_current` path refused every
window observed from a floating A0 input, which it previously published as a
full-quality current, and accepted every window observed from a connected,
idle clamp on the same bias network. This was measured on the target chip,
through the adapter's own read path. It covers those captures: 5 floating, 10
connected and 5 restored windows, with no conductor in the clamp.**

Run on the bench Raspberry Pi 4 Model B, Raspberry Pi OS Trixie, 2026-09-22,
with the house supply off and the Pi alone on its own supply. The installed
runtime was v2.5.0rc8, which does not carry the check. The adapter under test
was the working tree's `ori/` package, copied to its own directory on the Pi
and imported by the bench virtual environment, so the installed release was not
modified. The `ori-runtime` service was stopped for the captures and restarted
afterwards, and it came back with binding 2 in force and the coil commanded
`de_energised`.

## The setup

The wiring was the one recorded in `2026-09-22-pi4-sct013-linearity.md`:
ADS1115 at `0x48`, A0 single-ended, and a bias network of 10 kΩ, 10 kΩ and
10 µF on the Pi's 3.3 V rail. The SCT-013-030 was across the midpoint row and
A0, with no conductor in its window and no load anywhere. Calibration was
`sensitivity_v_per_amp: 0.0333` and `mains_frequency_hz: 50`.

The probe connected an `I2CAdapter` for `ads1115_current` and called `read()`
once every 0.5 s, recording either the reading or the refusal.

## Results

| Leg | Windows | Outcome | Window mean | Reported |
| --- | --- | --- | --- | --- |
| Clamp connected | 10 | 10 accepted | 1.661 V (1.6609 to 1.6620) | 0.019 to 0.038 A, 35 samples, `quality` 1.0 |
| A0 lead removed, input floating | 5 | 5 refused | 0.601 to 0.603 V | no reading |
| Lead restored | 5 | 5 accepted | 1.658 V (1.6573 to 1.6579) | 0.015 to 0.028 A, 35 samples, `quality` 1.0 |

Every refusal named the offset, for example `window mean 0.602 V is -1.048 V
from the bias midpoint 1.650 V, beyond the 0.171 V the bias network and the
signal allow`. The floating level matches the 0.598 V that the linearity
session recorded when the same fault was published as 0.041 to 0.070 A.

The healthy midpoint was 1.661 V on this supply, against 1.638 V in the
linearity session. Both are inside the derived band of 1.481 to 1.819 V.

## What this does not establish

- **A loaded clamp was not observed.** Acceptance was shown only for an idle,
  connected clamp. That a large current is not refused rests on the host tests
  across load shapes, not on this bench run.

- **Only the floating leg is covered.** A clamp that is closed on the conductor
  instead of around it holds the midpoint, and this check cannot see it. That
  case remains undetected, and commissioning catches it only if the circuit leg
  records the bound sensor's readings.
- **The runtime's degradation path was not exercised on the Pi.** The probe
  drove the adapter directly. The transitions to degraded after three refusals
  and back after five good windows, and the health reason, are host-tested.
- **The adapter's circuit breaker opened after the fifth refusal.** It counts
  every exception from a read, a refused window included, as clipped windows
  already do. Readings then stay withheld until its 300 s recovery timeout,
  after the fault has cleared. That fails closed, and it is not changed here.
- **The rail tolerance is an allowance, not a measured bound.** The two healthy
  midpoints differ by 23 mV across two supplies, so this bench exercises little
  of the band.
