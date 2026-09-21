# Startup stages

The design for decomposing `OriRuntime.start()`, written before any code
moves. It names the stages startup already has, every ordering between them
that exists for a safety reason, the orderings that exist for other reasons,
and what is deliberately unordered. The decomposition that follows must
preserve each named constraint and pin it with a test that reads the stage
order, so an ordering can only change by editing the constraint and its reason.

Nothing here changes behaviour. Anything found on the way that should behave
differently is its own issue.

## The shape of the seam

`start()` becomes one ordered tuple of stages. Each stage is a method
`_stage_<name>(self, context: StartupContext) -> None`, and its body is the
corresponding span of `start()` moved unchanged, with one substitution: a
local that today crosses a stage boundary becomes a field on the context. A
value that today is stored on the runtime stays stored on the runtime, in the
same stage, because moving it would change what `stop()`, a handler or a
later operation can see at a checkpoint.

A stage therefore reaches three things: the context, for values that cross
boundaries during startup; runtime attributes it reads or writes; and runtime
callables it calls, such as a handler it binds, a loop it starts, or a helper
it delegates to. None of the three is forbidden. Each is inventoried per
stage, and the guard holds the inventory.

The order is data, not control flow: a tuple of stage names, a constraint
table beside it of `(later, earlier, reason, safety)`, and a set of the
boundaries after which startup checks for a stop request. A test asserts the
tuple satisfies every constraint, that every constraint names stages that
exist, and that the checkpoint set is exactly the four the code has today.

Stages are cut at every existing checkpoint. No checkpoint moves: a
checkpoint that moved later would let startup go on acquiring resources after
an operator asked it to stop, and a stage that blocks on hardware would then
hold the stop.

## How the inventories below were made

They are derived from the body of `start()` rather than written by hand, by
the classification the guard will apply:

- The span of each stage is the run of top-level statements between two
  anchors in `start()` today.
- A **context field** is a local of `start()` stored in one span and loaded
  in a later one. A load inside a closure counts for the span that defines
  the closure, because an executor registered on the dispatcher is where a
  hidden dependency would otherwise live.
- A **runtime call** is `self.<name>(...)`. A **runtime write** is
  `self.<name>` as an assignment target, or as the root of an attribute or
  subscript that is assigned, since setting `self._safety_alert_sink.sender`
  mutates the sink. Every other `self.<name>` is a **runtime read**,
  including a method referenced without being called, which is a read of a
  bound callable.

One local is reused for an unrelated value in a later span: the relay's
`gpio_pin` in the safety envelope and the external watchdog's in the loops.
The derivation reports it as crossing the boundary because it cannot tell the
two apart; the implementation change renames the second, and it is not a
context field.

## The context

Exactly the locals of `start()` that a later span reads. The underscore
prefix three of them carry today is dropped on the context.

| Field | Set by | Read by |
| --- | --- | --- |
| `config` | configuration | every later stage |
| `commissioning_anchors` | configuration | safety envelope |
| `status_cfg` | configuration | loops |
| `status_indicator` | configuration | dispatcher, event path, loops, health and reconciliation |
| `whatsapp_action` | actions | alerting |
| `sms_action` | actions | alerting, dispatcher |
| `coap_action`, `logger_action`, `process_manager_action`, `system_control_action` | actions | dispatcher |
| `has_relay_config` | actions, then the safety envelope | safety envelope |
| `relay_action` | actions, then the safety envelope | safety envelope, dispatcher, event path, loops |
| `relay_enabled` | actions | dispatcher |
| `operator_contact`, `secondary_contact`, `approval_timeout`, `primary_alert_channel`, `rejection_expiry_days` | alerting | dispatcher |
| `alert_sender` | alerting | dispatcher, event path, loops, announce |
| `evidence_attestor` | evidence | dispatcher, services |
| `dispatcher` | dispatcher | event path, skills, loops |
| `elevator` | reasoning | event path, skills, loops |
| `local_llm` | reasoning | event path, loops |
| `posture_cfg` | reasoning | loops |
| `posture_tracker` | reasoning | event path, loops, services |
| `event_bus` | event path | sensors, services |

## The runtime surface of each stage

Every runtime attribute each stage reads, writes or calls, by the rules
above. A dash means none.

| Stage | Runtime reads | Runtime writes | Runtime calls |
| --- | --- | --- | --- |
| configuration | `_config_path`, `_dotenv_variables` | `_config`, `_config_env_placeholders`, `_device_id`, `_device_location`, `_device_policy_enabled`, `_device_timezone`, `_remote_command_lockout_config`, `_runtime_started_at_ms`, `_status_indicator` | - |
| store | `_state_store` | `_state_store` | `_load_remote_command_lockout_state` |
| actions | `_handle_remote_command`, `_handle_remote_command_incident`, `_state_store` | `_sms_action` | - |
| safety envelope | `_commissioning_state`, `_safety_alert_sink`, `_safety_commander`, `_safety_registry`, `_state_store` | `_commissioned_actuator`, `_safety_alert_sink`, `_safety_commander`, `_safety_registry` | `_load_commissioning` |
| alerting | - | `_alert_sender`, `_operator_contact`, `_primary_alert_channel`, `_safety_alert_sink`, `_secondary_contact` | `_configure_alert_outbox` |
| evidence | `_state_store` | `_evidence_attestor`, `_evidence_posture_problems`, `_firmware_confirmation_coordinator`, `_firmware_confirmation_reconciler` | - |
| dispatcher | `_binding_seq_in_force`, `_commissioned_actuator`, `_state_store` | `_dispatcher` | `_load_cached_device_policy`, `_maybe_refresh_remote_device_policy_once`, `_send_or_queue_alert` |
| reasoning | `_config_path` | `_capability_posture_tracker` | - |
| event path | - | `_deduplicator`, `_event_bus`, `_skill_reload_lock` | - |
| skills | `_config_path`, `_loaded_skills`, `_state_store` | `_dispatch_coordinator`, `_skill_loader`, `_skills_dir` | `_binding_view`, `reload_skills` |
| signals | `_request_stop` | - | `reload_skills` |
| sensors | `_adapters`, `_background_tasks`, `_connected_sensor_ids`, `_deduplicator`, `_safety_registry`, `_unconnected_sensors` | `_configured_sensors`, `_connected_sensor_ids`, `_last_alert_timestamps_by_channel`, `_last_alert_timestamps_by_trigger`, `_measurement_refusals`, `_measurement_valid_streak`, `_sensor_last_seen_ms`, `_sensor_poll_interval_ms`, `_stale_sensor_active`, `_unconnected_sensors` | `_emit_unconnected_sensor_warning`, `_poll_sensor`, `_restore_measurement_state` |
| loops | `_background_tasks`, `_deduplicator`, `_sensor_poll_interval_ms` | - | `_alert_delivery_loop`, `_capability_posture_loop`, `_compaction_loop`, `_device_policy_refresh_loop`, `_external_watchdog_loop`, `_heartbeat_loop`, `_sensor_staleness_loop`, `_status_signaling_loop`, `_stop_if_requested_during_startup`, `_watchdog_loop` |
| services | `_background_tasks`, `_deduplicator`, `_nudge_firmware_confirmations`, `_shutdown_event`, `_state_store` | `_evidence_inbound_subscriber`, `_evidence_outbound_publisher`, `_firmware_command_publisher`, `_firmware_command_service`, `_firmware_liveness_scheduler`, `_firmware_liveness_supervisor` | `_evidence_checkpoint_loop`, `_start_gateway_export_responder_if_enabled`, `_start_sms_webhook_if_enabled`, `_start_telemetry_export_if_enabled`, `_stop_if_requested_during_startup` |
| operator services | `_background_tasks`, `_build_health_snapshot`, `_shutdown_event` | `_runtime_node_heartbeat_publisher` | `_start_firmware_mqtt_operator_if_enabled`, `_stop_if_requested_during_startup` |
| health and reconciliation | `_background_tasks`, `_firmware_confirmation_reconciler`, `_shutdown_event` | - | `_drain_pending_firmware_confirmations`, `_reconcile_pending_attestations`, `_start_health_socket_if_enabled`, `_stop_if_requested_during_startup` |
| announce | `_background_tasks`, `_safety_registry`, `_shutdown_event` | - | `_complete_startup`, `_send_setup_success_notifications`, `stop` |

## The stages

Checkpoints are marked. The reads column names context fields only; the
runtime surface is the table above.

| # | Stage | What it does | Context reads | Checkpoint after |
| --- | --- | --- | --- | --- |
| 1 | configuration | Loads and validates the configuration, refuses an autoloaded dotenv under hardened posture, checks required capabilities, loads the commissioning anchors and refuses a collision with the provisioning anchor, installs the log handler, records device identity, connects the status indicator as STARTING | - | |
| 2 | store | Opens the state store, the one opener allowed to rebuild pre-receipt history, and loads the remote-command lockout state | config | |
| 3 | actions | Builds the remote-command verifier and the WhatsApp, SMS, CoAP, logger, process-manager and system-control actions; initialises the relay decision and drops the relay on a phone deployment | config | |
| 4 | safety envelope | Loads the commissioned binding under the anchors, resolves the zone for the declared pin, builds the safety registry over the in-force zones with the trip journal, takes the startup verdict, refuses active zones with no executor, connects the relay under the zone's polarity or defers acquisition, binds the commissioned actuator to the commander, commands the coil de-energised where no profile owns the zone, starts the registry | config, commissioning_anchors, has_relay_config, relay_action | |
| 5 | alerting | Resolves the operator numbers and the approval timeout, configures the outbox, builds the failover sender over the SMS and WhatsApp actions, hands the sender to the safety alert sink | config, sms_action, whatsapp_action | |
| 6 | evidence | Builds and starts the attestor, computes the evidence posture, builds the firmware confirmation coordinator and reconciler over the store | config | |
| 7 | dispatcher | Builds the dispatcher, loads the cached device policy and refreshes it once, sets every executor and resource resolver, the relay-backed ones only when an actuator is in force | config, status_indicator, sms_action, coap_action, logger_action, process_manager_action, system_control_action, relay_action, relay_enabled, operator_contact, secondary_contact, approval_timeout, primary_alert_channel, rejection_expiry_days, alert_sender, evidence_attestor | |
| 8 | reasoning | Builds the posture tracker, the local model (required under hardened posture when requested), the gateway reasoner and the elevator | config | |
| 9 | event path | Builds the event bus, attaches the elevator, pushes the first posture snapshot to the elevator, the dispatcher, the sender and the indicator, creates the reload lock and the deduplicator | config, status_indicator, relay_action, alert_sender, dispatcher, elevator, local_llm, posture_tracker | |
| 10 | skills | Anchors the skills directory to the configuration, binds the resource gate and the binding view to the dispatcher, builds the dispatch coordinator and the loader, loads the skills, logs the tier configuration | config, dispatcher, elevator | |
| 11 | signals | Installs the SIGTERM, SIGINT and SIGHUP handlers | - | |
| 12 | sensors | Restores measurement state, connects every adapter, tells the registry about a sensor that could not connect, starts a poll task per connected sensor | config, event_bus | |
| 13 | loops | Starts the staleness watch, the watchdogs, the heartbeat, compaction, alert delivery, policy refresh, the posture loop and status signalling | config, status_cfg, status_indicator, relay_action, alert_sender, dispatcher, elevator, local_llm, posture_cfg, posture_tracker | yes |
| 14 | services | Starts the SMS webhook, telemetry export, the gateway export responder and heartbeat subscriber, the evidence subscribers and checkpoint loop, and the firmware liveness stack, with the security posture warnings | config, event_bus, evidence_attestor, posture_tracker | yes |
| 15 | operator services | Starts the firmware operator and the node heartbeat | config | yes |
| 16 | health and reconciliation | Starts the health socket, drains pending firmware confirmations, starts the reconciler loop, reconciles pending attestations, sets the indicator NORMAL | config, status_indicator | yes |
| 17 | announce | Sends the setup notifications, starts the registry retry loop, completes startup and waits for shutdown | config, alert_sender | |

## Orderings that exist for a safety reason

Each of these is a constraint the decomposition must keep and the order test
must pin. The reason is the one the code carries today.

1. **Anchors before the binding.** The commissioning anchors are loaded and
   compared against the provisioning anchor in the configuration stage, before
   any binding is read. If a commissioning anchor were the provisioning
   anchor, the separation the binding contract rests on would not exist, and a
   binding verified under it would license actuation from the provisioning
   key.
2. **The binding before any pin is driven.** Polarity and what each coil state
   does to the protected circuit are commissioned facts. The relay is
   connected only under an accepted zone for its pin, and a declared pin with
   no zone in force is not driven and its actions do not exist.
3. **The registry's verdict before the relay connects.** Release-shipped
   profiles activate on the in-force zones first, and a refused activation
   refuses a hardened start exactly as a missing hardware backend does. A
   zone with an active profile and no executor to bind refuses a hardened
   start before anything is driven.
4. **Deferred acquisition is decided before connect.** On a zone whose
   de-energised terminal state closes the protected circuit and which has an
   active profile, connecting the line would itself close the circuit. The
   line stays untouched and the registry's first command is the acquisition.
5. **The actuator binds to the commander before any coil command.** The
   registry reaches the coil only through the commander, so a command issued
   before the bind would find nothing to drive.
6. **Startup commands the coil, it does not assume it.** A zone with no active
   profile is commanded de-energised through the commissioned polarity,
   whatever the platform default. A zone with an active profile is not: the
   registry issues the terminal-state-conditioned command, which honours a
   durable latch that a plain de-energise would release.
7. **The registry starts before any reading can arrive.** It starts in the
   safety envelope stage; sensors connect eight stages later, so no reading
   reaches a profile before its pairs exist.
8. **A sensor that failed to connect is reported to the registry at the
   moment it fails.** A pair must not wait out its loss bound for a fact the
   runtime already holds. The unconnected-sensor warning is sent only when no
   pair was told, so one event produces one notice.
9. **Relay-backed executors exist only when an actuator is in force.**
   `trip_relay`, `release_relay` and `close_gas_valve` exist on the dispatcher
   only when a commissioned actuator exists, so a skill's request for them is
   refused as missing rather than performed against nothing.
10. **Executors before skills.** A skill declaring an action above Tier A is
    checked at load, and the dispatcher must hold the executors a loaded
    skill can name before the loader runs.
11. **Evidence never gates safety.** The attestor starts after the registry
    and the evidence posture is computed after it; evidence trust that cannot
    be established fails closed for evidence and never for the runtime. This
    is an ordering the decomposition must keep in the negative: no stage
    after evidence may be made a precondition of the safety envelope.

## Orderings that exist for other reasons

- **Store before anything durable.** The journal, the outbox, the lockout
  state and the firmware registry all live in the store.
- **Actions before the safety envelope.** The safety envelope reads none of
  the action objects; it reads the relay decision the actions span
  initialises, whether a pin is declared, whether the relay is enabled, and
  the phone-deployment override of both. The order is also kept because a
  configuration that cannot build an action, such as a malformed SMS sender
  allow-list, aborts today before any pin is considered, and moving the stage
  later would change which error a bad configuration reports first.
- **The sender before the dispatcher and the executors.** Both send through
  it.
- **The attestor before the dispatcher and the confirmation coordinator.**
  The dispatcher attests actions; the coordinator reaches evidence state only
  through the attestor's backend, so the thread-bound connections stay on the
  thread that opened them.
- **Signal handlers before adapters connect.** A device that cannot be
  stopped for the whole of startup is worse than one that stops untidily, and
  adapter connects can block on hardware.
- **The event bus before the poll tasks**, and the first posture snapshot
  before events are processed.
- **The firmware command publisher connects before the liveness scheduler
  starts.** The first tick would otherwise sign a message, spend a sequence
  number and fail to publish it.
- **The firmware telemetry subscriber's reconnect callback is late-bound.**
  The reconciler is built in the evidence stage and the subscriber in the
  services stage; the callback reads the reconciler from the runtime when a
  reconnect happens rather than capturing it, so no construction order
  between the two is a constraint. The comment beside the subscriber's
  construction says the opposite and is stale; the implementation change
  corrects it.
- **Pending confirmations drain before the reconciler loop starts**, and
  pending attestations reconcile after the services are up.
- **The setup notification is last**, after the indicator reports NORMAL and
  after the final checkpoint, so a device that was told to stop during
  startup never announces that it is online.

## What is deliberately unordered

- Within the services stage, telemetry export, the
  gateway export responder and the heartbeat subscribers start in the order
  the code lists them and nothing depends on it.
- The skill reload on SIGHUP applies to new events only; in-flight tasks keep
  the previous configuration.
- The compaction loop, the staleness watch and the watchdogs are independent
  of each other.

## The stop protocol across stages

A stop signal before startup completes is recorded, not acted on: `stop()`
closes what startup is still building, and running the two concurrently is
how a resource is closed under a step that is using it. Startup unwinds at
its next checkpoint. A second signal tears down at once, because startup can
block in an adapter connect that never answers and an operator who asked
twice is owed a way out.

The four checkpoints sit after the loops, after the services, after the
operator services, and after health and reconciliation. Each is a stage
boundary in the tuple and the order test asserts the set is exactly these
four, so moving or adding one is a visible edit rather than a line found by
reading.

## What the decomposition must preserve, and how that is tested

- **No behaviour change.** The nine test files that drive `start()` and the
  runtime suite pass without a test being rewritten to accommodate the move.
  A test that has to change is evidence the move changed behaviour.
- **The order test.** A new test reads the stage tuple, the constraint table
  and the checkpoint set, and asserts every constraint holds, every
  constraint names existing stages, and the checkpoints are the four above.
- **The context test.** Each stage declares the context fields it reads and
  sets; the test walks the tuple and asserts every read is set by an earlier
  stage and every field has a later reader.
- **The surface inventory.** The guard applies the classification above to
  each stage method, closures included, and compares each of the four
  categories, context reads, runtime reads, runtime writes and runtime calls,
  with the stage's declaration, in both directions: an attribute nobody
  classified fails the suite, and a declaration with no access behind it
  fails too, so the tables describe the code rather than excusing it. This is
  an inventory, not a proof of isolation, and its failure message says so:
  it sees what a stage's own body touches, not what a method it calls
  reaches, and a helper the stage delegates to is a runtime method with a
  surface of its own that the inventory does not follow.
- **Re-certification** on both production-supported tuples, since shipped
  code changes.

## Observed while reading, not changed here

The safety alert sink is created in the safety envelope stage and receives
its sender in the alerting stage, one stage after the registry has started.
A notice the registry raises between those two points is refused and logged,
which the sink's docstring states as intended. Whether the sender should be
built before the registry starts is a behaviour question for its own issue,
not for this decomposition.

## Order of work

1. This design, reviewed.
2. The `store.py` split by domain behind its unchanged public surface, which
   depends on nothing here and is the lower-risk half.
3. The `StartupContext`, the stage tuple and the checkpoint set, moving each
   stage's body unchanged into its method, with the order test, the context
   test and the surface inventory landing in the same change.
