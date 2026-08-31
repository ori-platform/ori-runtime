# Ori Runtime — Unreleased

Changes merged to `main` after `v2.5.0-rc.7` are collected here until the next
candidate or release is cut.

## Added

- The runtime verifies, retains and reports a commissioned safety binding
  (`ori-specs/commissioned-safety-binding/v1`). The binding envelope at
  `commissioning/binding.json` beside `ori.yaml` is verified through the
  contract's twelve ordered stages against commissioning anchors the
  installer delivers in the service environment, retained whole in the state
  store, and reported in health under `commissioning` with the verdict by
  stage and reason. Declared actuating hardware with no accepted binding
  refuses a hardened start and degrades a development one. The safety profile
  set ships with the release and is loaded under its closed grammar.
  `actions.relay.active_high` is refused from `ori.yaml`: polarity is a
  commissioned fact.
- A commissioned mapping is proven in two legs, and verification no longer
  grants authority. `proof` establishes the circuit; the optional
  `proof.control_path` establishes that the pin the binding names, at its
  declared `active_high`, is what moves that coil. Absence of the control leg
  denies rather than grants. A document passing every stage with either leg
  unproven on any zone is **provisional**: retained apart from the binding in
  force, reported in health as `unavailable`, kept out of the freshness chain,
  and never connected or commanded — the startup coil command included,
  because that command is derived from the polarity the leg exists to prove.
  `actuation_licensed` now requires both legs on every zone.
  `commissioning deliver` names which state a staged document reaches. A
  revision invalidates the proof leg by leg: a changed pin or polarity does not
  inherit the control proof taken against the old wiring, so the retained
  record keeps both timestamps and a revision reusing its predecessor's control
  proof is refused as `stale_proof`. A retained binding whose legs are not both
  proven is migrated into the provisional record rather than only retired, and
  an existing provisional record is never overwritten by that migration.
- The relay is driven only through the commissioned binding. It is connected
  under the zone's polarity, startup commands the coil `de_energised` through
  it, and `trip_relay`, `close_gas_valve` and `release_relay` resolve to
  `open_protected_circuit` / `close_protected_circuit` through the zone's
  mapping at the moment of actuation. A declared pin with no accepted zone is
  not driven and registers no relay action. Every logged physical action
  records the `binding_seq` in force, and health reports the actuator's coil
  state and last command.

