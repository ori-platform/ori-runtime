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
  authorisation, briefly commanding the zone's de-energised terminal state --
  whatever commissioning recorded that to be -- rather than the outcome the
  operator authorised.
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
  an undriven input on every exit where the operation's own code runs, never parked in a chosen state, because
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

- The release-owned safety registry is wired and reports per-pair protection
  posture on the health surface. Release-shipped profiles activate from
  commissioned zones, and each conjunct of a protection claim is checked where
  the claim is made rather than inferred from an earlier check. Every shipped
  profile remains a candidate, so no zone is bound to an active runtime-owned
  pair on any real device yet.
- A measurement loss that does not resolve escalates rather than being reported
  once. The transition notice is followed by a reminder to the primary contact
  at six hours and the secondary at twelve, then daily, on the existing audited
  outbox. It is Tier A throughout, carries no physical authority, and has no
  give-up condition: a still-unprotected channel must not become permanently
  silent. Escalation tells a person a channel is unprotected; it never restores
  protection, and no message says otherwise.
- An alert a customer has switched off is withheld, and the suppression is
  recorded in `action_log` as `suppressed` so it is distinguishable from a
  delivery that failed.

## Changed

- `SIGTERM` and `SIGINT` are ordered against startup rather than racing it, so a
  stop signal arriving mid-start is honoured at a checkpoint instead of leaving
  a half-initialised runtime.
- A signed configuration binds what it means and bounds how it is read: a
  hostile document is refused rather than raising out of the loader, a repeated
  key is refused, and a document nested past the recursion limit cannot stop the
  runtime.
- A relative `database.path` resolves against the directory holding the
  configuration that declared it, rather than against the working directory of
  whatever process loaded it. Every generated configuration declares
  `ori_state.db` relative, so the runtime, the commissioning bridge and the
  production encrypted-storage check previously each answered according to
  where they were started: a ceremony command run from outside the data
  directory reported that the device held no state store while the store and
  its binding sat intact beside the configuration, and the requirement that
  `database.path` live under `state.encryption.encrypted_path_prefixes` could
  be satisfied or defeated by standing in the right directory. An installed
  deployment is unaffected, because its unit sets `WorkingDirectory` to the
  data directory that holds its configuration. A deployment that relied on the
  working directory to select its store, or to satisfy that posture check, now
  resolves and is judged against the configuration instead. Where a store
  exists only where the working directory would have found one, config load
  reports both paths, since opening the resolved store creates it and the
  device would otherwise come up on an empty one while its commissioned
  binding sits in the other. That is reported and not refused: a file of that
  name in the working directory is a coincidence as often as it is the
  device's store. An absolute `database.path` is taken exactly as declared,
  and `:memory:` names no file so it is not resolved.
- `state action-log` and `state history` take `--path` and read the store the
  named installation declares. They previously opened `ori_state.db` beside the
  caller and read no configuration at all, so they could not reach a deployment
  that declared any other `database.path`, and a read in a directory with no
  store created an empty one and reported an empty action log — a device that
  appeared to have taken no actions rather than a lookup that went elsewhere.
  An absent store is now refused and named, and a refusal distinguishes a store
  that is missing from a path that is not a file.
- `SECURITY.md` names Raspberry Pi OS Trixie as the production-supported Pi
  platform and Bookworm as a published bundle that is not a certified target,
  which is what `docs/linux-install.md` and the capability matrix already said.
  The installer now recognises Trixie, so `detect_platform` no longer returns
  nothing on the platform the matrix certifies.

## Fixed

- Telemetry stops exporting to an endpoint that has refused this device. A
  terminal refusal is classified narrowly — status, media type, absent
  authentication challenge and an exact detail — so a captive portal or proxy
  cannot suspend a device permanently, and the condition is observable through
  its own counter without touching the health verdict.
- The ADS1115 path measures what it claims: the channel is selected and verified
  before every measurement, the window is certified at both ends, every sample
  is pointered, a chip whose configuration changed under the runtime is
  quarantined, and the adapter survives a driver reporting an unusable platform
  instead of crashing on an import that raises something other than ImportError.
- The adapter lifecycle is serialised so a close cannot straddle a connect, and
  the contract sits on `BaseAdapter` rather than being restated per adapter.
- The installer stages the Blinka platform library beside the pin factory, so a
  Pi resolves its GPIO factory from inside the release tree.
- The bootstrap keeps stdout for the installer's document, so `--json` is a
  single JSON document rather than prose interleaved with it.
- `ori doctor` no longer reports USB readiness for a deployment that declares no
  USB.

## Security

- A trust anchor whose private key this repository publishes is refused, at
  every deployment profile. This repository commits Ed25519 seeds as test
  material, and three verification paths across two trust boundaries accepted a
  public key derived from one: the commissioning anchor, loaded independently
  at runtime startup and by `commissioning deliver`, and the
  configuration-signature trust anchor. A device configured with such a key
  accepted documents signed by anyone holding a clone — a commissioned binding
  claiming both proof legs, which licenses actuation through the commissioned
  seam, or a signed configuration carrying `device.rated_capacity_amps`, the
  input that scales the Tier D trip point. The refusal covers the verify-only
  previous commissioning slot, and `provisioning_anchor` reads such a key as
  absent. A device carrying one now refuses to start rather than starting on a
  forgeable authority, which is upgrade-breaking and costs detection as well as
  actuation; rotate to a key that has never left the producer. No installer,
  document or example ever configured one. Coordinated as
  `GHSA-rv38-92xc-7xq8`.

- The same refusal covers every other boundary that treats a key as authority.
  `verify_signed_payload` is the shared verifier for community skills, offline
  Tier C approval tokens and device policy, so one check covers all three and a
  later caller inherits it. The skill loader refuses the same material again at
  admission, where it can name whether the anchor came from the constructor or
  the environment.
- A firmware signing seed this repository publishes is refused where one is
  read: the environment loader every runtime consumer uses, and `read_seed` in
  the provisioning CLI, which signs approvals without going through that loader.
  Those boundaries receive the private half, so the public key is derived and
  checked against the same list rather than a second one being kept in step. A
  seed whose key cannot be derived is refused rather than trusted.
