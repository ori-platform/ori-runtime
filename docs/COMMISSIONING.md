# Commissioned safety binding

The runtime actuates a physical circuit only through a **commissioned safety
binding**: a signed record, per `commissioned-safety-binding/v1` in
`ori-specs`, of which sensor observes which circuit, which actuator controls
it, what its coil states do to the load, and what the load is rated for —
established at installation by whoever certified the electrical work, and
proven by measurement rather than asserted.

Nothing about a relay's polarity or its coil mapping comes from `ori.yaml`.
`actions.relay.active_high` is refused at startup; `actions.relay.gpio_pin`
declares only that the pin exists.

## What the installation carries

| Item | Where | Who writes it |
| --- | --- | --- |
| Current commissioning anchor | `ORI_COMMISSIONING_ANCHOR_PUBLIC_KEY_B64` in the service environment (`/etc/ori/runtime.env` or `~/.config/ori/runtime.env`) | The installer, out of band |
| Previous commissioning anchor (verify-only, optional) | `ORI_COMMISSIONING_ANCHOR_PREVIOUS_PUBLIC_KEY_B64`, same file | The installer, on rotation |
| The binding | `commissioning/binding.json` beside `ori.yaml` — the envelope form, `{"binding": …, "signature": "ed25519:…"}` | The commissioning producer (`ori-cli`) |
| Retained state | The state store, table `commissioned_binding` (in force) or `commissioned_binding_provisional` | The runtime |

Both anchors are the canonical base64 of a raw 32-byte Ed25519 public key.
No configuration document names or overrides them. If either commissioning
anchor is the provisioning anchor's key material, the runtime refuses to
start in every posture (`anchor_collision`).

## What the runtime does with it

At startup, after the actuator backend has been proven available:

1. The binding in force is reloaded from the state store.
2. If `commissioning/binding.json` is present and is not the document already
   in force, it is verified through the contract's twelve stages — `parses`,
   `device_id`, `key_selection`, `signature`, `authority`, `freshness`,
   `mapping_self_consistency`, `proof_consistency`, `bounds`,
   `disambiguation`, `inventory`, `activation_posture` — against the anchors,
   the accepted binding, the inventory `ori.yaml` declares, the deployment
   posture, and the release-shipped safety profile set (for the trip-point
   bound). A document that passes is retained and supersedes the one in
   force; one that fails leaves the binding in force unchanged, whatever
   stage it failed at.
3. Declared actuating hardware with no binding **in force** refuses a
   hardened start (staging, production, or
   `security.enforce_production_posture`) and starts a development runtime
   **degraded**, with no protection claimed and no actuation licensed through
   the commissioned seam.

The verdict and what the device holds are reported in health under
`commissioning`: `binding_seq` and `binding_hash` of the binding in force,
`anchors_configured`, the retained `zones` — provisional or in force — each
with its actuator identity, commissioned mapping, `circuit_proof`,
`control_path_proof`, `state` and `availability`, the `last_verdict`
(`stage`, `reason`, the presented `binding_seq`), and `actuation_licensed`.

## Verification is not authority

A document that passes all twelve stages has been shown to be authentic,
self-consistent and about this device. It has not been shown that the pin this
binding names is what moves that coil, which is a separate measurement.

The proof therefore has two legs. `proof` is the **circuit** leg: the protected
circuit, its terminal states, and that this sensor observes that circuit.
`proof.control_path` is the **control** leg: that the control input the binding
names, at its declared `active_high`, is what moves that coil. The control leg
is optional in the grammar and **absent means unproven** — a document written
before the leg existed makes no claim about it.

| State | Reached by | The runtime |
| --- | --- | --- |
| refused | failing any stage | leaves the binding in force unchanged |
| **provisional** | passing every stage with any zone missing either leg | retains it apart, reports it, connects nothing, commands nothing |
| **in force** | passing every stage with both legs proven for every zone | connects and commands the declared actuator |

A zone is in force only when its circuit proof is not `undemonstrated` **and**
its control proof is `commanded_and_observed` on a `local_gpio` actuator. One
zone short of that leaves the whole document provisional. A `firmware_channel`
zone is always provisional: proving a control leg through the authenticated
command path has no design yet.

`active_high` is an assertion until the control leg proves it, and getting it
wrong inverts every later command — an instruction to release the coil
energises it. So the startup coil command is not exempt: a provisional binding
leaves the output untouched.

**An untouched output is not a safe circuit.** It preserves whatever
controller-loss state the site commissioned, which may be `closed`. Health
reports such a zone `unavailable`, never protected.

**A revision invalidates the proof leg by leg.** A revision changing any
actuator identity field, any mapping field, or `calibration_ref` carries a
circuit leg performed after the retained circuit proof and, where it claims one,
a control leg performed after the retained control proof. A changed `gpio_pin`
or `active_high` does not inherit the control proof taken against the old one:
that measurement recorded which level drove which coil state on the wiring this
revision replaces. The retained record therefore keeps both timestamps, and a
retained document that carried no control leg has none, so a revision's control
leg is fresh by construction.

A retained binding whose legs are not both proven is migrated into the
provisional record and the in-force row is retired, so the device keeps a
per-zone unavailable report and the document the proof operation will act on.
The provisional slot holds one record: where one is already held it is kept,
because it was verified under the current rules with both legs assessed, and the
retired in-force row remains available for audit either way. Held means any
readable record, including one for another device — that record is reported and
never adopted, but it is not destroyed at the moment its provenance is in
question.

A provisional binding is retained in its own table and never enters the
freshness chain: `binding_seq` and `supersedes` describe the succession of
documents that were in force. Proving the leg produces a **new signed
document**, and that document, not the provisional record, is what comes into
force.

Commissioning therefore precedes hardening. A hardened start refuses declared
hardware with no binding in force, and a provisional binding is not in force,
so the proof runs during installation in development posture and the
deployment is promoted afterwards.

## Actuation through the binding

A local GPIO relay is connected only under a zone **in force** that names its
pin, with that zone's `active_high`. At startup the coil is commanded
`de_energised` through that polarity — commanded, not assumed, so the level on
the wire is the one the commissioning observed for a released coil. The
runtime's relay actions resolve through the zone's mapping at the moment of
actuation: `trip_relay` and `close_gas_valve` command `open_protected_circuit`,
`release_relay` commands `close_protected_circuit`, and the mapping decides
whether that energises or releases the coil. A declared pin with no zone in force is
never driven and its relay actions are not registered. Every logged
physical action records the `binding_seq` in force (`action_log.binding_seq`),
and health reports the actuator's coil state and last command under
`commissioning.actuator`.

## What this release does and does not do

- Verifies, retains and reports the binding; refuses `active_high` from the
  provisioning document; drives the relay only through the binding.
- Does **not** yet arm a zone, activate a safety profile, latch a trip, or
  migrate the packaged Tier D triggers to profile outcomes. Those land with
  the safety registry. What the coil does when the controller is lost is a
  property of the wiring the commissioning observed, not of this software.
- Does **not** offer the commissioning proof operation that closes the control
  leg. Until it exists, a control leg is proven only by a producer that
  performed the operation itself, so a runtime commissioned by the bench
  tooling holds a provisional binding and drives nothing.

## Producing a binding

`ori-cli` will capture, prove and sign bindings. Until it does, a binding for
a bench can be signed with the test tooling in `tests/commissioning/signing.py`
under a bench-only key whose public half is the configured anchor — never a
provisioning key, and never a key that signs anything else.
