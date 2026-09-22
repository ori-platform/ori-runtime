# the circuit leg proven on the bench Pi, and a zone brought into force

**Result: the bench zone's circuit leg is proven by the declared current
sensor watching a filament lamp switched by the relay contacts, absent before
and present after the closing command, present before and absent after the
opening one. A binding carrying both legs was signed, delivered and accepted,
the zone is in force, and the commissioned seam connected the relay and
commanded the coil de-energised at the next start.**

Run on the bench Raspberry Pi 4 Model B, Raspberry Pi OS Trixie, runtime
v2.5.0rc8 as installed by the release installer, on 2026-09-22, with the
runtime service active throughout. The declared sensor is `load-current`, an
ADS1115 at `0x48` reading an SCT-013-030 clamp, calibrated and measured for
linearity earlier the same day in the companion record.

## The setup

- Relay channel 1 of the SRD-05VDC board in the live conductor of a 100 W
  incandescent lamp: the plug side into COM, the lamp side into NO, the
  neutral uncut alongside. The relay at rest holds the lamp off.
- The clamp closed on the lamp side of that conductor, one pass through the
  window, so it observes only current that the contacts admit.
- Coil side unchanged from the control-leg proof: DC+ on Pi pin 2, DC− on the
  shared ground, IN1 on GPIO 26, trigger selector on Com-High.
- The relay board was not enclosed during the proof. The board's mains
  terminals were exposed on the bench, which the procedure does not permit and
  the operator chose to accept for this run; the record notes it rather than
  omitting it.

## The two commands

The zone was provisional under binding 1, whose control leg was proven on
2026-09-07 and whose circuit leg was `undemonstrated`. `commissioning
prove-command` was run twice from the operator's own terminal on the device,
consent typed each time.

| Command | Consent lead | Held | Attestation | Lamp |
| --- | --- | --- | --- | --- |
| close, from rest | 10 ms | 53.6 s | matched | off, lit, off at release |
| open, from lit | 8 ms | 17.6 s | matched | lit, off, stayed off |

For the opening command the lamp was lit beforehand with nothing holding the
pin: a holder took the coil energised through the seam and was killed
outright, leaving the pad driving high, which is the controller-loss retention
measured on 2026-09-01. The proof command then took the line low and the lamp
went out.

## What the sensor saw

Means of the runtime's own `load-current` readings from the state store, at
the runtime's normal cadence, over the 28 s before each command and the hold
after it:

| Command | Before | After | Delta |
| --- | --- | --- | --- |
| close | 0.026 A | 0.508 A | +0.482 A |
| open | 0.516 A | 0.025 A | −0.491 A |

The zone's noise floor is 0.05 A. Both deltas clear it by an order of
magnitude and carry the sign the transition requires, which is the verifier's
load-transition rule applied to a measurement rather than to an assertion.

## The binding

Binding 2 was assembled from the two exported observations and the readings
above, with `proof.method: actuate_and_observe` carrying `sensor_before`,
`sensor_after` and the instrument, and `proof.control_path` carrying the same
two commands as `commanded_and_observed`. Its `calibration_ref` names the
companion linearity record. It was signed with the bench-only commissioning
key whose public half is the device's configured anchor, verified on the
workstation with the runtime's own checker, then delivered:

```text
accepted, binding_seq 2, state in_force, unproven_zones []
```

On the next start the runtime logged binding 2 in force with actuation
licensed, connected the relay on GPIO 26 at `active_high: true` with the coil
taken de-energised, and reported the zone `in_force` and `available` with the
actuator's last command `startup: de_energised, pin low`. The lamp was
unplugged for that start; the relay's own indicator stayed off.

## What that settles, and what it does not

**Settled.** Both proof legs on a real relay, a real load and the declared
sensor, and the full path from a hand-assembled document through delivery,
verification, retention and the seam's startup command on the supported
hardware. The commissioned seam is no longer host-tested only.

**Not settled.** Controller-loss behaviour is unchanged from the 2026-09-01
record: loss of coil power and process loss remain as measured there, and the
in-force zone inherits them. The document was assembled and signed with the
test tooling because the ceremony tool's capture step does not yet exist, so
this is bench evidence and not a pilot commissioning record. One relay, one
lamp, one bench.
