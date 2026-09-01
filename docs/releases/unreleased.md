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
- The commissioning proof operation closes the control leg. `commissioning
  prove-command` issues exactly one coil command against one provisional zone,
  taking consent interactively from `/dev/tty` which it opens itself, stating
  the binding, zone, pin, polarity, outcome, expected coil state and
  controller-loss condition before each command. One authorisation permits one
  command and cannot arrive as a bridge argument, a flag, or piped stdin. What
  that establishes is that a process holding the controlling terminal answered:
  the nonce is printed to the same terminal it is read from, so a parent that
  allocates a pty can supply it, and no POSIX check separates that from a
  person. A terminal is not proof of physical presence and is not reported as
  one; presence stays a commissioning procedure requirement. Taking a GPIO line as an output drives it -- gpiozero
  has no high-impedance output -- so the pin is taken at the **requested** coil
  state, which makes the acquisition the one physical act. Taking it at
  de-energised and then commanding the outcome would issue two acts for one
  authorisation, and on a closing outcome would momentarily open the circuit.
  Nothing follows the acquisition, and the consent prompt says so. The commanded
  level is **held while the operator answers** -- at least a release-owned one
  second however fast they are, and at most sixty. The hold and the answer
  window are one interval, because the facts being attested are only true while
  the command is in force. The operator supplies the contract's own observation
  fields on the same terminal: `load_present_before`
  before consent, then `terminal_state_observed` and `load_present_after` during
  the dwell. The verdict is derived from those facts rather than taken as a
  separate answer that could contradict them, and it applies the same
  load-transition rule the verifier does, so a command whose load never changed
  state is `inconclusive` rather than a proof. Anything typed before the coil
  moved is flushed: a buffered answer reports an effect that has not happened
  yet, which is why it cannot be supplied as a flag either. Silence,
  cancellation or an error records `observation_timeout` and produces no proof,
  and a terminating signal is turned into a cancellation so the release runs. The runtime never
  observes the coil, so `effect_verified` is always false and the response
  separates `command_issued` from `operator_attestation`. The pin is released to
  an undriven input on every exit, never parked in a chosen state, because
  choosing one would derive it from the polarity under test; releasing it is not
  by itself the zone's controller-loss condition, which has to be observed at
  the panel for process death and loss of power separately. Consent and
  actuation are one audit row. `commissioning proof-export` returns what was
  recorded and accepts nothing. The operation is runtime-owned: the bridge
  invokes it and performs none of it.
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

