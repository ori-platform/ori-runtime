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
| Retained state | The state store, table `commissioned_binding` | The runtime |

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
3. Declared actuating hardware with no accepted binding **refuses a hardened
   start** (staging, production, or `security.enforce_production_posture`)
   and starts a development runtime **degraded**, with no protection claimed
   and no actuation licensed through the commissioned seam.

The verdict and the binding in force are reported in health under
`commissioning`: `binding_seq`, `binding_hash`, `anchors_configured`, the
accepted `zones` with their actuator identity, commissioned mapping and proof
method, the `last_verdict` (`stage`, `reason`, the presented `binding_seq`),
and `actuation_licensed`.

## What this release does and does not do

- Verifies, retains and reports the binding; refuses `active_high` from the
  provisioning document.
- Does **not** yet resolve an outcome through the mapping at actuation, arm a
  zone, or activate a safety profile. The relay executor still drives the pin
  under gpiozero's default polarity, as documented in `docs/RASPBERRY_PI_SUPPORT.md`.
  The commissioned actuation seam is the next change; profile activation and
  trip state land with the safety registry.

## Producing a binding

`ori-cli` will capture, prove and sign bindings. Until it does, a binding for
a bench can be signed with the test tooling in `tests/commissioning/signing.py`
under a bench-only key whose public half is the configured anchor — never a
provisioning key, and never a key that signs anything else.
