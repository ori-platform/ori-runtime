# the ADS1115 measurement path, characterised on the bench Pi

**Result: the release's driver path sustains the advertised 860 SPS with
10 µs jitter; three of the four provisional measurement constants are now
measured and left as they were; the fourth waits on the clamp. Two defects
were found on the way, and the second is the kind no clip check questions.**

Run on the bench Raspberry Pi 4 Model B, Raspberry Pi OS Trixie, stock Python
3.13.5, on 2026-09-03, with the runtime service active throughout. The driver
path is the release's own: adafruit-blinka over `/dev/i2c-1`, the platform
library staged from apt `python3-rpi-lgpio`, `adafruit-circuitpython-ads1x15`
3.0.5. The ADS1115 is at `0x48`; A0 is tied to a header ground pin.

## Rate and jitter

Unpaced, the path reads the conversion register **3000 times a second**
against an 860 SPS conversion rate — roughly 3.5 reads per conversion. An
unpaced loop therefore meets any sample floor with the same value repeated,
which is why `_read_ads1115_current` paces at the conversion interval.

Paced as the adapter paces, over a 2-cycle 50 Hz window (40 ms), three trials
at each rate:

```text
rate=860  samples=36  gap_mean=1.164ms  max=1.219..1.222ms  sd=0.009..0.010ms
rate=475  samples=20  gap_mean=2.108ms  max=2.163..2.184ms  sd=0.014..0.018ms
rate=250  samples=11  gap_mean=4.006ms  max=4.058..4.059ms  sd=0.017..0.018ms
```

The target interval at 860 SPS is 1.163 ms. The worst single gap ran 5% over
it; the jitter is an order of magnitude under the interval.

These are host read cadences. The driver's first continuous read sleeps for two
conversion intervals inside the window it opens, and the pacing loop then
catches up with back-to-back reads, so the first window after a connect carries
a few duplicated conversions where later windows carry one. A worst gap of
1.222 ms cannot contain that 2.3 ms sleep, so the windows recorded here were not
the first after their connect.

## What that settles, and what it does not

| Constant | Was | Now |
| --- | --- | --- |
| `data_rate: 860` | datasheet figure, unmeasured | **measured on the host side**: the reads sustain 860 a second, evenly spaced, and the config word carries the 860 SPS rate bits. A0 was grounded throughout, so a duplicate read of one conversion cannot be told from a fresh one; that the chip converts at 860 is the datasheet's claim and the configuration's, not this bench's |
| `_MIN_SAMPLE_FRACTION = 2/3` | derived from the above, so equally unmeasured | **measured safe**: nominal 34.4 samples gives a floor of 22; the window delivers 36, ~60% headroom. Left at two thirds — the margin is for a loaded Pi, and the load here was one running runtime |
| `overrun_tolerance: 1.5` | a guess at scheduling slop | **measured safe**: it bounds the whole window's elapsed time against nominal, and five windows ran 41.09 ms against 40.00 ms — ratio 1.027, recorded below. 1.5x is far more slack than needed |
| `clip_margin_volts: 0.05` | assumes saturation reads near a rail | **low rail only**: a grounded input reads between -0.0006 and +0.0000 V single-shot (recorded below), inside the margin, and the window is refused as clipped. The high rail needs a saturated clamp on the bench and stays provisional |

None of the three measured constants changes value: each was already safe, and
the record is what changes — from "provisional, unmeasured" to "measured, and
why the margin is kept".

Recorded verbatim, so the two figures above are measurements and not quotes:

```text
single-shot A0, five reads:  -0.0006  -0.0001  -0.0004  -0.0001  +0.0000  V

whole-window elapsed, paced as the adapter paces, 2 cycles at 50 Hz:
  trial 0: samples=36 elapsed=41.090 ms nominal=40.000 ms ratio=1.0273
  trial 1: samples=36 elapsed=41.090 ms nominal=40.000 ms ratio=1.0272
  trial 2: samples=36 elapsed=41.089 ms nominal=40.000 ms ratio=1.0272
  trial 3: samples=36 elapsed=41.092 ms nominal=40.000 ms ratio=1.0273
  trial 4: samples=36 elapsed=41.089 ms nominal=40.000 ms ratio=1.0272
```

## Defect 1: the configured channel was never selected

The pinned driver, the latest published, never selects a channel in continuous
mode: `_write_config` re-reads the chip's current mux and discards the
requested pin unless the mode is `SINGLE`. The adapter built the ADS1115 in
continuous mode, so both `ads1115_current` and `ads1115_voltage` read whatever
mux the chip already held. Proven at the register — chip forced to its
power-on default, then a fresh continuous object asked for channel 0:

```text
chip mux after construction:  A0-A1 diff
ch0 read: -0.0001 V   mux now: A0-A1 diff   <- asked A0 single, got A0-A1 diff
asked for channel 1:          chip mux now: A0 single  <- pin ignored
```

On a fresh chip that is the A0-A1 differential: a clamp on A0 measured against
a floating pin. A floating input on this part drifts between roughly 0 and
+0.6 V, so the value reported depended on an unconnected pin. This is
ori-runtime#500. The fix selects the channel with one single-shot read, which
is the one path in this driver that honours the pin, before switching to
continuous mode, and reads the mux back.

## Defect 2: after the fix, every sample was the config register

The first version of that fix read back a constant **+2.1404 V, raw 17123**
on the grounded input, unchanged by any settle time. 17123 is 0x42E3 — the
config word for mux 4, gain 1, continuous, 860 SPS. Every config write leaves
the chip's register pointer on CONFIG, and the driver's continuous-mode read is
a fast read that does not move the pointer, so it returned the configuration as
if it were a conversion.

```text
config register: 17123   fast read now: 17123
after one pointered read -> 65534   fast read now: 65534   (= -2 counts, ~0 V)
```

A plausible mid-range voltage that is not a measurement is exactly what a clip
check cannot catch. The connect now ends with a pointered read after the mux
readback, and the read path never touches the pointer again.

## Defect 3: two adapters on one chip steal each other's channel

The shipped `ori.yaml.example` puts `load-current` on A0 and `grid-voltage` on
A1 of the same ADS1115 at `0x48`. The runtime builds one adapter — and one
driver object — per sensor. The chip has one mux, and once a driver object has
read its pin its later reads take a fast path that trusts the mux to be where
it left it. So the second adapter's connect moves the mux, and the first
adapter's reads follow it, both connects having verified their own channel.
Reproduced on the bench with the real adapter, A0 grounded and A1 floating:

```text
load-current (ch0) after its connect:  -0.0003 V   <- A0 grounded
grid-voltage (ch1) after its connect:  +0.5823 V   <- A1 floating
load-current read again:               +0.5745 V   <- A1's value, under A0's label
```

A current channel would then report the voltage channel's waveform as
amperes. Two things close it. One ADS1115 now serves one adapter per runtime:
a second connect to a claimed chip is refused, and the shipped example is
corrected to put its second sensor on a second chip. And the configuration is
read back before every measurement, not only at connect, with a pointered
conversion read after it.

The whole config word is compared, not the mux field, because the two changes
that corrupt a reading most quietly move no mux. A second process that sets its
own gain rescales every sample: at gain 2/3 against the gain 1 this adapter
set, a 20.8 A load reads 13.9 A. One that sets single-shot mode leaves the chip
powered down after one conversion, so the window that follows is a held value
and a 21.7 A load reads 0.0 A. Both under-report, which is the direction that
matters for a current a trip threshold is defined over. Both were measured by
driving the real 3.0.5 driver over a register-level model of the part.

The check certified the chip at the start of each window and not through it,
which left two ways in. A configuration write landing mid-window was not caught
until the next window, and a foreign pointered read mid-window sent the
remaining fast reads back to the config word: measured in that model at 10.9 A
against 20.9 A. The pointer half is closed outright, on a
measurement rather than on inspection. The configuration half is narrowed
rather than closed, and the residue is stated below rather than left implied.

## Defect 4: a chip at 0x48 that is not an ADS1115 hung the connect

The driver's single-shot read spins on the conversion-complete bit with no
bound. A TMP102 and an LM75 both default to `0x48`, ACK, and answer with that
bit clear for any temperature below mid-scale. Reproduced against a simulated
chip on the host, not on the bench, which has a real ADS1115. The connect now
writes the mux itself and waits a bounded few conversion intervals for the bit,
refusing with the address if it never sets.

The bound is not an identity check, and nothing here is. A device whose word
happens to carry that bit passes the wait, and what refuses it is the
configuration readback: a foreign word has to match the exact 16 bits this
adapter wrote to get through. That is a probability, not a proof of part.

## Defect 5: a chip taken by another writer was retried rather than refused

Recorded 2026-09-04, on the same bench and the same part.

A reading refused because the chip is running a configuration this process did
not set is evidence that something else is writing it. Re-selecting the
configuration would be a contest with that writer, and losing it intermittently
produces a plausible number rather than a refusal — the failure would present
as an occasional wrong value, which is worse than an outage because nothing
about it looks wrong.

So the chip is quarantined for the life of the process, keyed by bus and
address rather than by the adapter object: `close()` releases the chip claim,
so an adapter-scoped latch would let a second object connect, rewrite the chip
and resume reading inside the same process, and the operator message promising
a restart would not be true.

Driven against the bench part with a second driver instance as the competing
writer, which writes single-shot mode and leaves the mux alone:

```text
before            : -0.0001 V
after the writer  : refused
chip put back     : 0x42E3
same adapter      : still refused
new adapter       : refused at connect
```

The third line matters: the chip was returned to exactly the word the adapter
had set, `0x42E3`, and the refusal held anyway. No reading can establish that
the competing writer is gone, so no reading clears the refusal. Recovery is a
restart, after an operator has removed whatever was writing the chip.

A readback that cannot be performed at all does not quarantine. A dropped
transaction is not evidence that anything took the chip, and treating it as
such would turn one bad transfer into an outage lasting until restart.

## What a quarantine does not establish

A quarantine is a refusal to measure, not a protection. A device holding one is
not protecting that channel, and nothing here restores it: the runtime does not
restart itself, and it does not withhold a watchdog feed to force a reset. What
a reset would do to a commissioned coil is measured in
`2026-09-01-pi4-gpio-controller-loss.md`, which also records that a genuine
watchdog reset was not among the conditions tested. The consequence of a
withheld measurement having no effect beyond one notice is tracked separately.

## Defect 6: the window was certified only at its start

Recorded 2026-09-04, same bench and part.

A pointered conversion read per sample was the obvious way to close the pointer
class outright — no sample can then return anything but the conversion register
— and the objection to it was cost: it writes one extra byte per sample, and
nothing had established that this fits inside the 1.163 ms conversion interval
at 860 SPS. So it was measured before it was adopted, paced exactly as the
adapter paces, over a 2-cycle 50 Hz window:

```text
fast read (today)        samples 36  elapsed 41.09 ms (ratio 1.0272)
                         gap mean 1.164 ms  max 1.223  sd 0.010
pointered every sample   samples 35  elapsed 40.15 ms (ratio 1.0038)
                         gap mean 1.164 ms  max 1.222  sd 0.011
floor at 2/3 of nominal 34.4 samples = 22
```

One sample in thirty-six, an unchanged mean gap, and a whole-window elapsed
ratio that is nearer nominal rather than further from it. The floor is 22, so
the cost is well inside it. Adopted.

Confirmed afterwards through the adapter's own sampler rather than a standalone
loop:

```text
trial 0: samples=35 elapsed=40.16 ms ratio=1.0039 gap mean=1.164 max=1.829
trial 1: samples=35 elapsed=40.16 ms ratio=1.0039 gap mean=1.164 max=1.221
trial 2: samples=35 elapsed=40.16 ms ratio=1.0039 gap mean=1.164 max=1.221
```

The 1.829 ms outlier in the first trial is one gap of thirty-four on a loaded
Pi; the window still filled to 35 against a floor of 22.

The scaling moved with it. A pointered read returns the register unsigned,
because the driver signs it a layer up in the reader this replaces, so the
adapter now does the two's complement and multiplies by the datasheet's
full-scale range over 2^15 — not 32767, which is what the driver's own
arithmetic uses. Checked against that arithmetic on the bench for every gain
and for the edge values 0x0000, 0x0001, 0x7FFF, 0x8000, 0xFFFF, 0xFFFE, 0x42E3
and 0x4000: identical to the last place.

The configuration half is narrowed, not closed. A pointered read says nothing
about a gain or a mode changed part-way through, so the configuration is read
back again at the end of every window and a window whose chip is **still** on
someone else's configuration at that point is refused rather than summarised.
That is what an interfering process which keeps its own settings leaves behind,
and it was the case measured at 13.9 A against 20.8 A.

What it does not catch is a writer that changes the configuration, lets some
samples be taken under it, and restores this adapter's configuration before the
window closes. Both checks then pass and those samples are summarised.

The residue is not a harmless transient, and it does not only under-report.
The chip converts against whatever range it is on while the adapter scales back
with the range its own driver object still believes, since nothing told that
object anything changed. Two effects then pull in opposite directions: the
affected samples have their amplitude scaled by the ratio of the ranges, and
the bias shifts with them, which puts a step in the middle of the window that
adds to the RMS about its mean. Modelled at code level for a foreign gain of
2/3 over a 15 A signal in a 35-sample window:

```text
samples under the foreign gain ->  emitted current  (true 15.00 A)
   4/35                              15.48 A   ( +3.2%)
  12/35                              15.75 A   ( +5.0%)
  20/35                              15.10 A   ( +0.7%)
  28/35                              13.40 A   (-10.6%)
  34/35                              11.17 A   (-25.6%)
```

So a brief interference over-reports by a few per cent and a sustained one
under-reports by a quarter, and neither is refused. A window affected for its
whole length is the case the end-of-window check does catch.

No amount of additional polling closes this: proving a configuration held for
the whole of a 40 ms window requires exclusive ownership of the bus, which
cannot be established from the same bus. It is a wiring and platform property.

## The adapter as fixed

Chip forced to its power-on default, then the real `I2CAdapter` connected on
channel 0, 1, 0 in turn. For each: the first fast read the read path would
take, three reads through the adapter, then the config register read back
pointered, last, so it cannot disturb what came before:

```text
channel=0: fast read after connect = 65535 counts (a sample, not 0x42E3)
           reads [-0.0001, 0.0001, -0.0006]     mux read back: A0 single
channel=1: fast read after connect =  4671 counts (a sample, not 0x42E3)
           reads [0.5839, 0.5784, 0.5784]       mux read back: A1 single
channel=0: fast read after connect = 65534 counts (a sample, not 0x42E3)
           reads [-0.0003, -0.0009, -0.0009]    mux read back: A0 single
```

A0 is grounded; A1 floats. 65535 and 65534 are -1 and -2 counts, two's
complement.

`tests/test_i2c_adapter.py::TestPiIntegration` on the bench: the DC read on
grounded A0 and the rail-pinned refusal pass; the RMS current test skips,
naming the bias network it needs; the BME280 test skips, naming the part.

## What this does not establish

The high-rail half of `clip_margin_volts`, and the RMS measurement itself over
a real clamp signal: both need the SCT-013-030 on its mid-rail bias network,
which is not yet on the bench. Nothing here is a protection claim; the
measurement path can now be characterised, which is what ori-runtime#398 asked
for, and its remaining item is the clamp.
