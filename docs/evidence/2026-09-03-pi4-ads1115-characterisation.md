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

The check certifies the chip at the start of each window, not through it. A
write that lands mid-window is not caught until the next one, and a foreign
pointered read mid-window sends the remaining fast reads back to the config
word: measured in that model at 10.9 A against 20.9 A. Closing that costs
either a second readback after the window or a pointered read per sample, and
the per-sample cost at 1.163 ms has not been measured on the bench. Tracked in
ori-runtime#503 rather than guessed at here.

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
