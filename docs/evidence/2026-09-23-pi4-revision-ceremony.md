# the commissioning ceremony through the CLI on the bench Pi

**Result: on the published `v2.5.0-rc.11`, the operator CLI revised the binding
in force end to end. It exported the binding from the device, captured a
revision that carries its proof, signed it and delivered it without `--force`,
and the runtime brought it into force as binding 3. The same CLI refused a
change that needs fresh proof on a line the binding in force drives, and the
device refused a revision that carried a stale proof. The first-commissioning
path (capture, prove, export, sign, deliver) ran end to end in a throwaway
data root, and reached a provisional binding carrying a proven control leg.
Its circuit leg was recorded undemonstrated, with no meter at the bench.**

Run on the bench Raspberry Pi 4 Model B, Raspberry Pi OS Trixie,
`python3.13`, on 2026-09-23. The bench wiring is that of the 2026-09-22 circuit
leg record: relay channel 1 in the live conductor of a 100 W filament lamp,
GPIO 26, the declared sensor `load-current` (an ADS1115 at `0x48` reading an
SCT-013-030 clamp). The operator CLI was built from the repository's `main`
for `linux/arm64` and run as the service account against the installed
runtime's bridge.

## The upgrade to the candidate

The device ran `2.5.0-rc.8` with binding 2 in force. The first run of the
release installer for `2.5.0-rc.11` was refused before anything changed:

```text
unsafe_install_root: special files are forbidden in the install root: named
pipe '/opt/ori/data/.lgd-nfy0'. Stop the service, remove that file, and run
this again: a running runtime recreates the ones it made.
```

The active release, the configuration and the release directories were
byte-for-byte as before. The pipe was the GPIO library's notify pipe. It was
dated when a bridge command had been run from the data directory, not when the
service started: loading a configuration that declares the ADS1115 imported
the GPIO library, which creates that pipe in its caller's working directory.
Following the refusal's own instruction (stop the service, remove the file,
run again) the upgrade completed healthy, with the device's identity kept.

Two further observations from the upgrade:

- **The new unit runs in its own runtime directory.** It runs with
  `WorkingDirectory=/run/ori` and `RuntimeDirectory=ori`. With the relay in
  use, the runtime's pipe was created in `/run/ori`, and none appeared in the
  data directory.
- **The upgrade replaced the hand-edited configuration.** The bench `ori.yaml`
  (789 bytes, carrying the sensor block and the relay pin) was replaced by the
  installer's generated 568-byte document, which has no sensor and no pin,
  while the installer reported the device healthy. The bench file was
  restored by hand before any commissioning step.

The library behaviour behind the refusal is fixed after this candidate. Every
Ori process now points the library at a directory it owns, and loading a
configuration no longer imports it. That fix was verified on this device with
the change staged over the installed interpreter, not with a published
release.

## Revising the binding in force

| Step | Command | Outcome |
| --- | --- | --- |
| Export | `commissioning binding-export` | binding 2, `sha256:718c079f…`, matching the hash the inventory reports |
| Capture | `binding capture --zone bench` | rated capacity 10 A (nameplate) changed to 5 A (installer measured); actuator, sensor, polarity, mapping and inventory generation carried; both proof legs carried |
| Sign | `binding sign` on the workstation, bench-only commissioning key | binding 3, `sha256:937ef3f1…` |
| Deliver | `binding deliver`, no `--force` | accepted, `state: in_force`, installed over the staged binding 2 |
| Start | service restart | binding 3 in force, relay connected on GPIO 26, coil commanded de-energised at startup |

Capture read the prior document from the device, showed each fact as recorded,
and asked only whether it changed. The prior capacity went into the recorded
reason. The staged file after delivery was the envelope byte for byte. Health
reported the zone in force and available, with the protection claim
`unprotected`: no safety profile is active.

## Two refusals

- **At capture, on the driven line.** A recalibration of the sensor was
  declared. The CLI refused as soon as it was declared, with exit status 2,
  and wrote no draft: the change needs fresh proof legs, and the only line the
  zone could be proven on is the one binding 3 drives.
- **At the device.** A revision changing the sensor's noise floor from 0.05 to
  0.07, while carrying binding 3's proof, was signed by hand and delivered. It
  was refused `stale_proof` at `proof_consistency`, with exit status 2. The
  staged file and the binding in force were unchanged.

## A first commissioning, in a throwaway root

A device with a binding in force cannot show a first commissioning, and taking
a zone out of operation to prove it again is not yet specified. So the service
was stopped, and a second runtime of the same release was run as a transient
unit. It used a fresh data directory with its own device identity
(`ori-bench-cli-proof`), its own state store and no binding. The configuration
was a copy of the bench's, so the same sensor and GPIO 26 were declared.

| Step | Outcome |
| --- | --- |
| `binding capture` | circuit leg recorded `undemonstrated`: no meter at the bench to establish the circuit at the terminals before energisation |
| `binding sign`, `binding deliver` | binding 1, `sha256:4554edf9…`, `provisional`; the runtime recorded it and left the pin undriven |
| `binding prove`, close, from rest | operator consent on the device's own terminal, held 18.4 s, attestation `matched` |
| `binding prove`, open, from lit | held 15.5 s, attestation `matched` |
| `binding export --zone bench` | control leg `commanded_and_observed`: close with coil energised and pin high, open with coil de-energised and pin low |
| `binding sign --control-path` | the captured draft with the exported leg attached, no hand edits, `sha256:28d5f623…` |
| `binding deliver` | refused `binding_already_staged` without `--force`; accepted with it, `provisional` |

After a restart, health reported the zone `provisional` and `unavailable`,
with the control leg `commanded_and_observed` and the circuit leg
`undemonstrated`. For the opening command the lamp was lit first by a holder
killed outright, leaving the pin driving high, as in the 2026-09-22 record.
The throwaway runtime was then stopped and its directory removed. The service
came back with binding 3 in force.

Completing a provisional binding needed `--force`, because the document it
replaces is a staged provisional and not the binding in force.

## What that settles, and what it does not

**Settled.**
- The revision half of the ceremony on the supported hardware, through the
  operator CLI and the published candidate: export, capture, sign, delivery
  without `--force`, and the in-force transition.
- The two refusals that keep a revision from carrying a proof onto hardware
  nobody proved.
- The first-commissioning path through the CLI, as far as a provisional
  binding with a proven control leg: capture, runtime-owned proof commands,
  export of what the runtime recorded, attachment, and delivery.

**Not settled.**
- **A circuit leg captured through the CLI.** It was recorded
  `undemonstrated`, so no binding authored end to end by the CLI reached in
  force on this bench.
- **The installer replacing the configuration.** An upgrade replaces a
  hand-edited `ori.yaml` with the generated default, and it is not fixed in
  this candidate.
- **Protection.** No safety profile is active, so nothing here is autonomous
  protection. The binding in force licenses actuation through the seam, and
  nothing yet trips it from a reading.
- **Scope.** One relay, one lamp, one bench.

## Archive

On the bench Pi under `~/ori-evidence-rc11/`: the installer's refused and
successful outputs, the configuration the upgrade generated, the exported
binding, the capture transcripts, the envelopes, the delivery results, health
and the journal. The throwaway root's state store, proof export, control leg
and envelopes are under `cli-proof/`.
