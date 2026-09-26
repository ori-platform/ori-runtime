# Ori Runtime — Unreleased

Changes merged to `main` after `v2.5.0-rc.7` are collected here until the next
candidate or release is cut.

## Added

- The runtime verifies, retains and reports a commissioned safety binding
  (`ori-specs/commissioned-safety-binding/v2`). The binding envelope at
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
- A revision changing any field of a zone's sensor, its actuator identity or
  its mapping needs every claimed proof leg fresh: every sensor field now
  counts, not only `calibration_ref`, so the retained record keeps the whole
  sensor. A revised zone is held to every retained zone it shares a name, an
  actuator or a sensor with, so renaming a zone
  no longer lets an inverted polarity or a rebound clamp keep the old proof.
  `commissioning binding-export` returns the signed envelope in force, read
  only, for a revision to start from, and never a provisional one. The
  vendored corpus and its misreading table follow ori-specs
  `commissioned-safety-binding/v2` at `06ba18e`.
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

- A tagged release publishes the Android runtime payload. Each of the three
  ABIs is built by the release workflow from the tagged commit with a pinned
  Rust toolchain, `cargo-ndk` and NDK, in a job that holds no signing
  credential, and published as a separate asset with a detached signature
  envelope and a checksum under `runtime-mobile/v2`. Signing is a protocol of
  its own — its own schema, domain separator, target grammar and key registry —
  so a payload signature cannot verify as a release-bundle signature, and the
  registry refuses any key whose private seed this repository or the
  conformance corpus publishes. `stripped` and the API level are measured from
  each artifact's ELF image rather than taken from build configuration, and a
  payload whose recorded API level is not its target's is not signed. Every
  target is signed and verified before the draft release exists and verified
  again from the public origin afterwards, so a partial or unverifiable set is
  never published. `scripts/verify_published_release.py --android-target`
  fetches a payload by tag and runs the nine consumer checks on it;
  `scripts/verify-android-runtime-payload.py` does the same for a file already
  on disk. Digests reproduce on the runner image that published them — every
  release rebuilds each payload and fails if one does not — and differ between
  host operating systems, which `docs/android-runtime-mobile.md` states along
  with the measurement and the reason.
- The Android payload reports what it observes of its meter. It posts a signed
  `runtime.sensor_status.v1` snapshot of every declared sensor to the telemetry
  endpoint's `/sensor-status` route: whether the last read succeeded, why not
  when it did not, when one last did, and how many have failed since. A silent
  meter previously looked exactly like a quiet one. Each snapshot also carries
  the payload's export state — readings delivered, duplicated, declined,
  abandoned, dropped and refused since start, and the counts queued and
  retained now — so a phone dropping readings or sitting on a backlog is
  visible to whoever receives the reports rather than only in its own logs.
- The runtime produces, delivers and confirms its own evidence anchor
  registration (`ori-specs/evidence-exchange/v2`). `evidence commission`
  records the commissioning reference at the device against the epoch the
  running runtime reports on its health socket, once that epoch is shown to be
  the one the configured evidence store holds, refusing a malformed reference
  before touching anything, a missing epoch, a store the runtime does not hold
  open, and a different reference for the same epoch without `--force`. The
  command implements the mechanism that predates the operator socket: the
  bridge reads the configuration document and the health socket and records
  the reference in the state store itself, with its own refusal codes. The
  socket-served command `operator-socket/v1` specifies, whose bridge opens no
  store, is the open gap the contract repository records against the runtime
  and lands with the operator socket. The
  runtime seals a registration under the recorded reference and keeps a
  durable confirmation obligation holding its exact bytes: a courier `queued`
  retires only the handoff copy, and the obligation re-offers the identical
  bytes under the release-owned schedule, across restarts, until a verified
  epoch confirmation for that epoch completes it: the first re-offer 60
  seconds after the first attempted offer, each later delay doubling to a
  3,600-second ceiling, measured from the previous attempted offer of those
  bytes and never from sealing, with the time of each attempt persisted so a
  restart measures from it. Each epoch's
  obligation is independent: one left open when the epoch changes keeps being
  re-offered until it resolves. The effect of an evidence disposition is
  implemented behind a verification seam, and no disposition is applied on
  this release: the release ships no disposition key registry, the installed
  verifier verifies nothing, and no inbound route carries one. Behind that
  seam a disposition binds to any artifact this device sealed for delivery,
  under the epoch that artifact names, and has the effect the value gives it:
  `retained_pending` suspends a registration's re-offers, `artifact_terminal`
  closes a registration attempt for operator repair or is only recorded
  against any other artifact, and `epoch_reprovisioning_required` or
  `identity_replacement_required` stops every new handoff within that epoch or
  the whole identity -- registrations, checkpoints and delivery envelopes,
  including copies already waiting for the courier -- while Tier C/D evidence
  is still signed and sealed locally. What is stopped stays sealed and durable
  on the device, is neither discarded nor rewritten, and is never re-signed
  under another identity; an artifact the courier already acknowledged
  `queued` stays the courier's. An artifact-scoped disposition stops nothing
  further. A stop is permanent: nothing deletes, clears or weakens one, not a
  restart, a new commissioning reference, a later disposition, a new epoch or
  an identity replacement, and `superseded` means only that a disposition has
  no new effect. The stop record is itself the move into stopped local
  custody: a stopped artifact leaves active ordering and the pending counts
  only because the record exists, and is counted in health as
  `stopped_local_artifact_count`, `stopped_local_bytes` and
  `oldest_stopped_local_since_ms` (`null` when none is stopped), across
  current and earlier epochs, matched by the same condition the courier
  route excludes it by. `pending_export_count` keeps its `runtime-health/v3`
  meaning, every sealed envelope no courier has acknowledged holding, stopped
  or not. Bytes the courier held before the stop are the
  courier's and are not counted. Checkpoints are handed off in the order they
  were produced: a later checkpoint waits while an earlier one is still its
  predecessor, whatever its own retry schedule. A checkpoint stops being a
  predecessor only once the runtime durably records a verified `queued`
  acknowledgement, a covering stop, or a verified terminal refusal
  (`malformed` or `binding_mismatch`), which keeps its exact bytes retired as
  `refused`; `queue_full`, an acknowledgement that fails authentication and no
  acknowledgement at all leave it a predecessor. This order is a behaviour
  of the release and not a declared carriage capability: the capability
  profile carries no `carriage_capabilities` member, because declaring
  `checkpoint_fifo_handoff_v1` is an evidence-epoch migration that the
  evidence authority must be upgraded for first, taken together with the
  disposition purpose when the disposition verifier ships; until then a
  checkpoint rollback under this epoch is refused artifact-scoped, never
  identity-scoped. The acknowledgement router retires a checkpoint on a
  courier's verified `malformed` from any gateway, while the contract counts
  `malformed` as terminal only from a gateway claiming the evidence carriage
  contract; this runtime carries under `gateway-api/v1`, and the distinction
  is unobservable while the capability is undeclared. Before the courier
  acknowledges `queued`, the handoff copy is retried on the outbox schedule,
  separate from the obligation's re-offers. The
  profile grammar accepts the member, so a registration declaring one is
  derived as `runtime-evidence-anchor/v2` specifies, and an empty, unsorted,
  repeated or unknown entry is refused before derivation. The earliest checkpoint is
  selected on its own, so any number of checkpoints waiting behind it cannot
  crowd a registration or an envelope out of a drain, and registrations and
  re-offers that are not yet due cannot hide one that is. The stop is read
  again immediately before each handoff, so one applied during a drain holds
  what that drain has not yet carried. An acknowledgement for a copy never
  handed off is refused rather than retiring it. Every retained copy is
  checked before it is carried: one whose bytes are not UTF-8 text, or no
  longer hash to the digest recorded with them, is kept where it is, taken out
  of the route and the checkpoint order, and recorded once as a local fault
  in the evidence store; such a row can no longer fail the query the route
  runs, which previously took the route down on every reconnect. Health
  reports no count of such faults, since `runtime-health/v3` defines none. A
  disposition is
  bound only to an artifact sealed under this device identity, so evidence
  files carried over from another identity cannot stop this one, and copies
  another identity sealed are never carried; health counts them as
  `foreign_identity_pending_count`. A copy counts as another identity's only
  when it is a JSON object naming a text `device_id` other than this one;
  bytes that are not JSON, a non-object, and a missing or non-text
  `device_id` are carried so the courier can refuse and retire them, and bytes
  that are not JSON are never read as JSON, so no row can take the courier
  route down. A disposition for a registration already confirmed or closed,
  or a stop already in force, is refused `superseded`. `evidence commission`
  reports the status the runtime will actually hold after the reference is
  recorded: `confirmed`, the current status under a stop, and otherwise
  `pending_confirmation`; a snapshot naming no recognised status refuses the
  command rather than guessing. Health reports, per `runtime-health/v3`,
  `anchor_epoch_id`, `registration_status` (`disabled`,
  `pending_authorisation`, `pending_confirmation` or `confirmed`; an attempt a
  terminal disposition closed stays `pending_confirmation`, keeps its pending
  time and overdue diagnostic, and is reported as `registration_offer:
  closed`, since the reference is still held and no confirmation arrived),
  `registration_pending_since_ms`, `registration_confirmation_overdue`,
  `registration_offer`, `last_disposition`, `foreign_identity_pending_count`,
  the three stopped-local diagnostics and
  `delivery_stop_status` (`not_stopped`, `epoch_stopped` or
  `identity_stopped`); none of them gates, delays or suppresses an
  approved Tier C action or any Tier D execution. The authorisation-based
  registrar, which could never produce anything because the device never
  holds an authorisation, is removed. An epoch confirmation applies only to a
  registration this device sealed for that epoch and key, and a late one for
  an earlier epoch no longer moves the active epoch back.
- Evidence waiting for the courier is republished at once after the clock is
  stepped back past its last attempt, for delivery envelopes and checkpoints
  as well as registrations; previously an envelope or checkpoint waited for
  the clock to catch up. Backoff for every evidence artifact stops doubling at
  its ceiling, so an attempt count, which is unbounded, can no longer
  overflow the delay and take the courier route down.
- Known limits of the anchor registration. `registration_pending_since_ms` is
  the wall-clock time the registration was sealed, and
  `registration_confirmation_overdue` compares it with the wall clock, true
  once 7,200 seconds have elapsed: a
  clock stepped forward reports overdue early, one stepped back reports it
  late, and one set before the sealing time reports it overdue at once,
  because the time spent pending cannot then be measured and reporting
  `false` would hide a stall for as long as the step was large. It stays on the
  wall clock because the contract defines the field as that observed time and
  a monotonic clock restarts at every boot, so it cannot carry a pending
  duration across a restart; the flag is a diagnostic and gates nothing. A
  `--force` replacement withdraws the superseded registration's courier copy,
  but rolling back to the previous release puts that copy back in circulation,
  because the previous release does not read the withdrawal; and `--force`
  cannot recall a copy the gateway has already queued, which reaches the
  evidence authority as a pending-registration conflict cleared by
  cancellation there. A store in which an earlier release applied an epoch
  confirmation without a sealed registration reports `pending_authorisation`
  here, while the firmware confirmation coordinator still reads that epoch as
  active from the table the earlier release wrote. `evidence commission`
  records the reference in a short `BEGIN IMMEDIATE` transaction on the live
  state store, bounded by a 3-second lock wait; while it holds the lock, and
  for as long as a stalled command held it, the runtime's own state-store
  writes wait up to the store's busy timeout. Action executors do not wait on
  it; the writes that do are records, such as the action log and the
  offline-token audit. Opening a store written by the previous release is
  tested for the evidence ledger against the schema v2.5.0-rc.11 shipped,
  vendored as a fixture; the state-store half of that test simulates the
  older store by dropping the new reference table rather than vendoring the
  previous state-store schema.

## Changed

- The vendored ori-specs corpora are selected by the contract version each
  set claims, now that a vector directory can hold more than one version: a
  `<stem>-v<N>.json` belongs to version N, an untokened file to the original
  version and to each later one that has not replaced it, and
  `scripts/refresh-evidence-vectors.sh` vendors, per stem, the newest file at
  or below the claimed version and nothing from a later one. Each manifest
  records the version as `contract_version`. The runtime claims
  `evidence-exchange/v2` (with its receiver-state corpus), `evidence/v3`
  (its chain-row corpus is `chain-row-v3.json`, vendored under
  `tests/vectors/evidence`), `runtime-evidence-anchor/v2` and
  `commissioned-safety-binding/v2`, each pinned at ori-specs `06ba18e`; the
  gateway-api, safety-profile and sensor-configuration sets are unchanged and
  keep their pins. The disposition corpus is held to for its re-offer
  schedule, its overdue bound and its canonical bytes; the courier's routing
  projection is vendored for the drift check and owned by the gateway.

- Three action-registry entries that governed physical actions with no executor
  behind them — `emergency_cutoff`, `open_safety_circuit` and
  `switch_power_source` — are retired rather than bound. A physical capability
  is an outcome on a commissioned zone, never an action name, and a source check
  now fails if a physical entry is ever governed that the runtime never
  registers. **A skill that declares one of the retired names above Tier A is
  now refused at load** with the capability named, where it previously loaded
  and produced a no-executor result at dispatch; no skill that ships with the
  runtime names any of them. `close_gas_valve` is unchanged and retires with its
  safety profile. Rows in the action log and the evidence chain that carry a
  retired name decode as before — nothing reads an action name against the
  registry. - `SIGTERM` and `SIGINT` are ordered against startup rather than
  racing it, so a stop signal arriving mid-start is honoured at a checkpoint
  instead of leaving a half-initialised runtime. - A signed configuration binds
  what it means and bounds how it is read: a hostile document is refused rather
  than raising out of the loader, a repeated key is refused, and a document
  nested past the recursion limit cannot stop the runtime. - A relative
  `database.path` resolves against the directory holding the configuration that
  declared it, rather than against the working directory of whatever process
  loaded it. Every generated configuration declares `ori_state.db` relative, so
  the runtime, the commissioning bridge and the production encrypted-storage
  check previously each answered according to where they were started: a
  ceremony command run from outside the data directory reported that the device
  held no state store while the store and its binding sat intact beside the
  configuration, and the requirement that `database.path` live under
  `state.encryption.encrypted_path_prefixes` could be satisfied or defeated by
  standing in the right directory. An installed deployment is unaffected,
  because its unit sets `WorkingDirectory` to the data directory that holds its
  configuration. A deployment that relied on the working directory to select its
  store, or to satisfy that posture check, now resolves and is judged against
  the configuration instead. Where a store exists only where the working
  directory would have found one, config load reports both paths, since opening
  the resolved store creates it and the device would otherwise come up on an
  empty one while its commissioned binding sits in the other. That is reported
  and not refused: a file of that name in the working directory is a coincidence
  as often as it is the device's store. An absolute `database.path` is taken
  exactly as declared, and `:memory:` names no file so it is not resolved. -
  `state action-log` and `state history` take `--path` and read the store the
  named installation declares. They previously opened `ori_state.db` beside the
  caller and read no configuration at all, so they could not reach a deployment
  that declared any other `database.path`, and a read in a directory with no
  store created an empty one and reported an empty action log — a device that
  appeared to have taken no actions rather than a lookup that went elsewhere. An
  absent store is now refused and named, and a refusal distinguishes a store
  that is missing from a path that is not a file. - Installer and doctor output
  no longer prints a filesystem name raw. A refusal is produced when something
  about a path is already wrong, which is when an operator reads most carefully
  and distrusts least, and the name in it is not always one they chose: a walk
  over a path's parents reports whichever component failed, and a directory
  listing reports whatever it found. An escape sequence that erases the line it
  is printed on, a newline that forges a second diagnostic, a carriage return
  that overwrites the first and a bidi mark that reverses the rest all now
  arrive escaped. - An error `detail` stays one message rather than becoming
  two. It is prose for an operator, not a machine-readable path field, so the
  path in it is escaped in the JSON form too; a consumer recovering a path by
  parsing that sentence was never reliable, which is the mistake
  `offending_path` made. - A remedy is quoted for a shell rather than escaped
  for a terminal, because it is a command an operator copies and runs. A path
  containing a newline would otherwise have ended that command and run what
  followed as the next one. The path stays a single argument. - A configuration
  error names its path escaped as well. The loader wrote `'{path}'`, which looks
  quoted and is not escaped, and `ori config validate` appends that message to a
  line of its own, so escaping only the outer line left the name it reports
  untouched. The same treatment reaches the config installer, the firmware
  provisioner, the inverter profile doctor and the phone doctor's report header.
  - `ori doctor` reports the offending release path whole. The machine-readable
  `offending_path` was recovered by splitting the human sentence on its first
  space, so any release path containing one was reported truncated. - The
  service works in a runtime directory of its own rather than in the directory
  it keeps state in. A GPIO library creates its notification pipe in the working
  directory and never removes it, and the install root admits regular files
  only, so a device that had driven GPIO refused its own reinstall with `special
  files are forbidden` and no indication of what had been found or where.
  systemd creates the runtime directory and removes it when the service stops,
  so an artefact any library leaves there is gone by the time an installer
  looks, whichever library and whichever platform. A refusal now names the
  offending path and its file type, so a device carrying one from an earlier
  release says which file to remove rather than sending an operator looking.
  That refusal is also what keeps a pipe from stalling an install indefinitely:
  the permission walk opens each file it plans to change, and opening a pipe
  waits for a writer that never comes, so it opens non-blocking and checks what
  it opened. Both halves are needed. An inode number is reused immediately after
  `unlink` on the filesystems these installs run on, so a regular file the walk
  validated and a pipe that replaced it carry the same number, and only the file
  type says anything changed. - A device endpoint must name an absolute path, or
  a URL where its transport can open one. `sensors[*].port` on `protocol:
  serial` and `actions.sms.gsm.port` are opened with `Serial()`, which takes a
  port name, so neither accepts a URL; `sensors[*].device_path` on `protocol:
  usb_serial` is handed to `serial_for_url` and still accepts `socket://` and
  the other forms that reaches. `sensors[*].device` on `protocol: smart` reaches
  `smartctl` as an argument, so it must be absolute too, which also keeps a
  value beginning with `-` from arriving there as an option. A device path is
  not anchored to the configuration the way a data file is, because it names a
  node the host owns rather than a file beside the document; left relative it
  would follow the working directory, which is now a runtime directory systemd
  empties on every stop. This is a deliberate compatibility change, not the
  tightening of something that could never have worked: a relative name does
  reach a device through a symlink in the working directory, and a deployment
  doing that must now name the device absolutely. The refusal happens at config
  load and names the field, rather than surfacing as a failed read later. -
  `ORI_AUTOLOAD_DOTENV` is refused under staging or production posture, and
  under a development deployment that has opted into hardened posture. A
  configuration signature covers the document before `${VAR}` fields are
  expanded, so a `.env` in the data directory the service can write would decide
  what a signed field holds while the signature still verified. A hardened
  deployment's environment belongs in the unit's `EnvironmentFile`, which the
  service cannot write. The posture is read from the document directly, since
  the decision has to be made before the configuration that would answer it is
  loaded, and a document that cannot be read is treated as hardened. A posture
  field that is itself expanded is treated as hardened too: unexpanded it says
  nothing about the posture, while what it expands to is exactly what is being
  decided. Startup then confirms that decision against the posture the loaded
  document declares, and refuses when a `.env` was loaded before a document that
  turns out to be hardened. - `ORI_AUTOLOAD_DOTENV` otherwise reads a `.env`
  beside the configuration only. It also read one beside the process, which the
  unit now points at a runtime directory systemd empties on every stop; those
  values are expanded into the configuration the runtime then trusts, so a file
  found next to the process is not this installation's environment. A
  development workflow that ran `--config /elsewhere/ori.yaml` while relying on
  a `.env` in the current directory must move that file beside the configuration
  or export the variables; an installed service is unaffected, since its unit
  reads `EnvironmentFile`. - `health_socket.path`, `reasoning.model_path` and
  the `gateway.tls` material resolve against the directory holding the
  configuration when declared relative, as the store, log, evidence and skills
  paths do. A socket bound in the working directory would be unreachable at the
  path an operator was told to use, and TLS material resolved there would not be
  found at all. The firmware provisioning socket and CA paths already had to be
  absolute when that section is enabled, and still do. - `logging.file`,
  `evidence.db_path` and `evidence.key_path` resolve against the directory
  holding the configuration, as `database.path` and the skills directory already
  do. The evidence key is sealed on first use, so a runtime reading one
  configuration from two working directories would seal two device identities
  for one device. - `SECURITY.md` names Raspberry Pi OS Trixie as the
  production-supported Pi platform and Bookworm as a published bundle that is
  not a certified target, which is what `docs/linux-install.md` and the
  capability matrix already said. The installer now recognises Trixie, so
  `detect_platform` no longer returns nothing on the platform the matrix
  certifies.

- The accuracy floor of the ADS1115 current path is stated and held by test.
  A sampling window is a fixed span of time rather than a whole number of
  cycles — 860 samples a second does not divide a 50 Hz period, and the loop
  stops on a deadline — so at the geometry the bench measured it runs slightly
  past two cycles and carries about 2% worst-case error on correctly
  configured hardware. A supply drifting within its band does not add to that
  and can read better; declaring the wrong band does dominate it, at about 7%.
  Every one of those errors is worse downward than upward, and an under-report
  is a safety threshold reached late, so the bounds are not symmetric. No
  behaviour changes: `mains_frequency_hz` was always a declared fact the
  runtime cannot verify, and this says what it costs to get wrong and where
  the floor sits underneath it.
- A configuration mismatch found while connecting to an ADS1115 now refuses the
  chip for the life of the process rather than only the sensor. The bus claim is
  released on a failed connect and `ori.yaml` checks sensor ids for uniqueness
  rather than addresses, so a second sensor naming the same chip configured one
  that had just been refused — the writing contest the measurement-time
  quarantine exists to prevent. A readback that could not be performed still
  latches nothing, because a bus failure is evidence of nothing.
- A sensor that connected and then refuses a run of measurement windows now
  degrades the device's aggregate health. The per-sensor field has carried it
  since the loss was first made visible, but `status` did not, so a fleet view
  keyed on it read green while a channel went unmeasured — the same shape as a
  configured sensor that never connected, which has always degraded for the
  reason that applies here word for word.
- What the runtime does when it cannot establish a trustworthy measurement is
  written down in `docs/MEASUREMENT_SUPERVISION.md`, including the part that is
  uncomfortable to say plainly: a device reporting a withheld measurement is not
  protecting that channel, by design, and escalation tells a person that a
  channel is unprotected rather than protecting it. The document also records
  why a timed self-restart and watchdog-health coupling are both refused, why a
  configuration mismatch at connect is skipped rather than quarantined and what
  any reconnect design must say about it, the pair-scoped supervision mechanism
  that waits on the Stage 5 cutover, and the four prerequisites a reset-based
  response would have to meet before it could be considered.

## Fixed

- No record of a Tier D act runs ahead of it any longer, or ahead of the next
  act in the same event. The autonomous-dispatch entry in the override log was
  written before the executor ran, and each act's action-log row, firmware
  confirmation read and evidence signature were awaited before the next Tier D
  act was attempted and before the event's reasoning was scheduled, so a store
  busy with another write, or a signer that never returned, held a trip for as
  long as it lasted, and held every other act of the event behind it, an
  approved Tier C act included. A store held by another connection past its
  busy timeout delayed a trip by that timeout and then lost its override entry
  and action row, and lost an approved Tier C act's decision and action rows
  outright. These records are now opened before the act and written by tracked
  tasks once it settles, retried while the store is busy or locked, in the
  order they became writable, and shutdown waits for them while the store and
  the evidence attestor are still open, reporting any it could not write at
  CRITICAL. One writer takes them from an in-memory queue capped at 1024: a
  store that never answers cannot grow it further, and a record arriving at
  the ceiling is counted lost and logged CRITICAL — never waited for by an
  act. A lost record, or one waiting thirty seconds, degrades health `status`;
  a lost operator-decision record, a Tier C decision row or a rejection's
  override entry, makes it `critical`. That status is an alarm, not
  durability: an operator's decision can still be lost at the writer's
  ceiling, on a store error that is not a lock, or at shutdown, until the
  approval admission that follows makes a lost approved decision structurally
  impossible by committing the decision before it becomes one. This change
  removes the record from the act's path and stops a busy or locked store from
  dropping it; it does not yet make it durable. The mixed record queue has no
  contract field of its own; `runtime-health/v3`'s `action_records` belongs to
  that approval admission and is not reported here. A write still in flight
  when the writer closes at shutdown is given the store's busy timeout to land
  and is otherwise reported as outcome unknown rather than lost, because the
  statement runs on a thread the cancel does not reach and the store may still
  take it. The emergency SMS for a failed Tier D act is sent beside the next
  act rather than ahead of it, and shutdown waits for it with the other Tier D
  work. Only a locked or busy store is retried; any other store error counts
  the record lost with its identity — an operator decision always named — and
  a signer that does not answer within ten seconds leaves its row pending for
  reconciliation instead of holding the queue. Tier D acts of one discovery
  set start together, so an executor that never returns holds no protective
  act on another resource, and an act interrupted while its executor kept
  driving records what the executor reported. Because an operator's refusal is
  now recorded after the act, rejection memory lags it while the store is
  busy: a matching event evaluated before the pattern lands is not yet capped.
  A process that stops after an act and before its row is written leaves that
  act out of the action log; a row written and not yet signed stays pending
  and is signed as `reconciled_late` at the next start, as before.

- A trigger whose reasoning or approval is still running no longer matches
  again inside its own cooldown. The cooldown is charged when a trigger's plan
  settles, so every reading that arrived while its inference ran, or while its
  operator had not yet answered, matched it again and dispatched again: one
  continuous condition sent the operator a message per reading instead of one
  per window. A trigger with a cooldown is now held from the moment it is
  planned until its own plan is charged, and released in that same step, so a
  trigger that acted goes straight into cooldown, one refused at the resource
  gate can still re-raise on the next reading, and a notice is never held
  behind another trigger's approval in the same event. The cooldown is also
  read again when the hold is taken, so a match evaluated before another event
  charged the turn is dropped rather than dispatched a second time. A trigger with
  no cooldown is not held, and a plan granting Tier D is never held behind its
  own notice.
- Concurrent local reasoning no longer crashes the runtime. A llama.cpp
  context decoded from two threads at once aborts the process, and two
  triggers matching together each ran the local model in its own worker
  thread. Local inference now runs one decode at a time on the loaded model.
  A caller cancelled mid-inference cannot stop its decode, so that decode keeps
  the model until its thread returns, and later callers wait for it in the event
  loop rather than in worker threads, where a run of cancellations would
  otherwise fill the default executor. The model is loaded once, whichever
  caller asks first, because llama.cpp silences stdout and stderr process-wide
  while loading and two overlapping loads leave them silenced; a load that
  fails is retried by the next caller, including one that failed after every
  caller waiting on it was cancelled.
- Tier C and Tier D actions are signed into the evidence chain again. The
  dispatcher built the attestation row without the authority snapshot stored in
  the same action-log insert, so the attestor refused every Tier C and Tier D
  attestation terminally as having no licence. The row now carries that stored
  snapshot, never a rebuilt one, and the attestor call requires it, so an
  omitted licence is a programming error rather than a silent refusal. A row
  logged by a store that cannot hold the snapshot in the same insert is not
  marked for attestation at all. Only an approval licenses a Tier C action: a
  proposal the operator refused, left unanswered or never received ran its safe
  default under no approval, and it is refused rather than signed under
  `tier_c_approval`, which would record the opposite of the operator's
  decision. The dispatcher builds no licence for it, and the attestor refuses
  one on its own, including on reconciliation after a restart. The evidence
  contract has no licence kind for a declined proposal yet, so until it does,
  that decision is kept in the Tier C decision log and not in the chain.
- An unanswered Tier C approval is reported by why it ended. Only a window that
  ran out is a timeout. A request no channel accepted is recorded as
  `undelivered`, and a reply listener or local console that stopped before its
  window is recorded as `no_reply`. That value is used everywhere the timeout
  was reported: the log, the decision log, the override log and the SMS
  escalation to the secondary contact, which no longer tells a person that an
  operator who was never asked did not answer. The safe default still runs in
  every case. The WhatsApp escalation is a provider-approved template whose text
  says the proposal timed out, and it is sent unchanged until a template
  carrying the reason is approved.
- Ori processes no longer leave lgpio's notify pipe (`.lgd-nfy0`) in the
  directory they ran from. lgpio moves the process into `LG_WD`, or stays
  where it is when that is unset, and creates the pipe there by a relative
  path when imported, never removing it. An operator command run from the
  data directory therefore planted a named pipe in the install root, and the
  next upgrade was refused `unsafe_install_root`. Every process now points
  `LG_WD` at a directory it owns: the service's runtime directory under
  `/run`, or a private temporary directory under an absolute temporary base
  that is not at or below the working directory, removed at exit; an
  inherited `LG_WD` is not kept. The working directory lgpio moves the
  process out of is restored as soon as its import finishes, so relative
  paths keep resolving where they did. Where neither exists (no writable
  temporary base at all), `LG_WD` is left unset and lgpio behaves as before,
  rather than failing the GPIO import and with it the relay. Validating a
  configuration no longer imports the board's GPIO library at all: the I2C
  adapter loads its drivers when a sensor connects, not when its module is
  imported for the schemas.
- `commissioning deliver` replaces the staged binding in force with a verified
  revision without `--force`. The binding in force stays staged once accepted
  and the runtime retains it, so replacing it discards nothing; it is
  recognised by its signed content rather than its file bytes. Any other
  different document staged, a provisional one included, still needs
  `--force`, so the flag keeps protecting another installer's work instead of
  being passed on every revision. Deliveries are admitted one at a time, so a
  second one cannot stage a document between another's check and its write;
  it is refused `delivery_in_progress`. Each write goes through its own
  temporary file.
- The bridge's read commands -- `commissioning inventory`, `binding-export`
  and `proof-export`, `state action-log` and `state history` -- open the
  state database read-only. They previously opened it as the runtime does,
  which set WAL mode, narrowed its permissions and applied this release's
  migrations to an existing store, and a read-only open of a stopped
  runtime's database left `-wal` and `-shm` files owned by whoever ran the
  query. A store older than the release is now reported as
  `state_migration_required` and left as it was, an empty file is answered
  as no store rather than given the schema, and a file that is not a
  database is refused as `state_store_unavailable` rather than failing as an
  internal error.
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
- A device whose community trust anchor can verify nothing no longer reports
  healthy while every community skill it was configured with silently fails to
  load. The anchor is a property of the deployment rather than of the skill
  being read when it is noticed, so it is answered once before any skill
  directory is opened, and every way it can fail is decided there rather than
  only the two shapes that had a guard of their own. Health carries
  `community_skills`, `skills list` carries `community_anchor`, and the
  refusals are reported once against the anchor instead of once per skill under
  an identical detail. Reporting and attribution are separate: an anchor that is
  a well-formed key but not the Hub's cannot be blamed, because its refusal is a
  signature failure indistinguishable from a tampered manifest, but the count of
  community skills the device failed to admit carries it either way. **A device carrying any non-first-party skill directory
  will now report `degraded`** where it previously reported healthy, since the
  anchor a build ships with is unconfigured; no skill's admission changes,
  because none was being admitted.
- A `.env` loaded through `ORI_AUTOLOAD_DOTENV` beside a signed configuration is
  reported. The signature covers the document before expansion, so the file
  decides the effective value of a signed field without invalidating it.
  Staging and production refuse the autoload outright; a development deployment
  carrying a signature keeps running and reports `config_authority`, whose
  `unsigned_value_source` degrades the device while it holds. Both halves are
  measured: the autoload reports which variables it actually introduced, since
  `override=False` decides nothing the environment already carried, and the
  document is scanned for the variables its values name, so a `.env` the
  document never references is not reported as having supplied anything.
- Filesystem and configuration names in the runtime's log output are escaped
  rather than handed to a terminal to act on. A skill directory holds whatever
  was put in it, and a configuration scalar carries whatever `${VAR}` expanded
  into it, so neither is necessarily a name an operator chose.

- Both telemetry producers report a reading as delivered only when the
  receiver's answer accounts for it, under `runtime-telemetry/v2`. Before this,
  the Android payload exited the process on a failed upload, both producers
  treated any `2xx` as a delivery, a retry merged newer readings under a new
  sequence, and a batch the receiver declined was reported as exported — so a
  restart or a lost acknowledgement discarded readings a per-event receiver
  would have stored. A `2xx` now delivers a batch only when the accepted,
  duplicate and declined counts account for every event in it; a retained batch
  is re-sent as itself ahead of newer ones; a batch answered five times without
  confirmation is discarded and counted; and export suspends only on the
  contract's recorded terminal refusal. How an answer is read is one decision
  table driven from one vector set in both languages, so the two producers
  cannot disagree about the same bytes. The payload's HTTP client is now its
  own strict reader over rustls rather than `ureq`, which panicked on a header
  line without a colon and ended the process — the failure a phone hit on a
  Wi-Fi blip.

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
