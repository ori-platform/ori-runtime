# Dispatcher seams

The design for splitting `ori/reasoning/action_dispatcher.py`, written before
any code moves. It names the seams the dispatcher already has, the state they
share, every ordering between and inside them that exists for a safety reason,
and the test that pins each one today. Where no test pins an ordering, this
document says so; those gaps are owed before the code under them moves.

Nothing here changes behaviour. The split moves code behind
`ActionDispatcher`'s unchanged public surface, rewrites no assertion to fit,
and anything found on the way that should behave differently is its own issue.

Line numbers are those of `ori/reasoning/action_dispatcher.py` at the commit
this document lands on (4,990 lines; the class runs 488–4990).

## The shape of the split

`ori.reasoning.action_dispatcher` becomes a package, keeping its import path,
composed as `ori.runtime` is: one class per seam in a private module, each a
base of `ActionDispatcher` (`ori/runtime/_runtime.py` composes `OriRuntime`
the same way), over a core class that holds `__init__` (506–608) and so every
attribute. A seam reads and writes the one instance's attributes, exactly as
the methods do today. No seam receives a copy of shared state: health
(`action_records`), the store reconciliation path and the gate all read the
instance, and a copy would change what they see.

Module-level helpers (1–487) move to the seam that uses them; a helper two
seams use moves to the core module. The package's `__init__.py` re-exports the
public surface (see the last section) and nothing else.

## The seams

Each seam with the methods it owns now and their line ranges. Totals are the
methods' own lines; module-level helpers are listed where they go.

| # | Seam | Responsibility | Methods (lines) | Lines | Module |
| --- | --- | --- | --- | --- | --- |
| 1 | Policy and capability | The device policy, relay enablement and comms posture the other seams consult | `update_policy` 688–694, `update_capability_posture` 696–697, `current_policy_version` 699–702, `get_policy_state_snapshot` 704–732, `permits_relay_action` 734–743, `permits_external_alert` 745–759, `permits_alert_class` 761–770, `_sync_policy_led_state` 4596–4615, `_tier_c_comms_available` 4617–4625 | 106 | `_policy.py` |
| 2 | Tier routing | Normalise and validate the tier, apply provenance, escalation and the registry floor, vet the safe default, apply relay policy, open the records, hand to admission | `dispatch` 977–1226; `_tier_rank` 466–467, `_TIER_RANK` 159–164, `_record_label` 278–285 | 250 | `_routing.py` |
| 3 | Resource admission | Resolve the resource, ask the gate, route by tier to execution or an approval workflow, retire or mark the resource uncertain, hand the row over | `bind_resource_gate` 612–615, `register_resource_resolver` 617–627, `_resource_for` 629–653, `_admit_and_run` 1228–1492, `_record_when_executor_reports` 1494–1518, `_retire_when_settled` 1587–1600, `_tier_b_requires_approval` 1603–1624; `_proposed_act_executed` 288–298, `_interrupted_result` 334–358 | 366 | `_admission.py` |
| 4 | Execution | The one place executors run; Tier D task tracking and the emergency notice | `register_executor` 655–686, `get_inflight_tier_d_tasks` 772–774, `_track_tier_d_task` 776–778, `_report_missing_executor` 1520–1543, `_log_to_dashboard_executor` 1628–1642, `_execute_immediately` 1646–1819, `_emergency_sms` 4560–4594; `_action_taken` 169–191, `UngovernedActionError` 470–471 | 286 | `_execution.py` |
| 5 | Safe defaults | Disqualify an actuating safe default; run a governed proposal's one safe-default intent | `_vet_safe_default` 957–975, `_safe_default_intent` 2248–2315 | 87 | `_safe_defaults.py` |
| 6 | Operator conversation | Compose and send the ask, mark it at the gate, listen, classify a reply, escalate an unanswered one; shared by both approval workflows | `_ask_operator` 1545–1585, `_listen_for_local_console_response` 4170–4238, `_audit_ignored_local_console_command` 4240–4262, `_listen_for_response` 4342–4379, `_format_approval_message` 4383–4456, `_measured_line` 4458–4478, `_format_local_time` 4481–4486, `_unanswered_approval_end` 4489–4493, `_escalate_to_secondary` 4495–4558; constants 118–133, 145–146; `_coerce_alert_send_receipt` 199–210, `_normalize_proposal_id` 311–313, `_safe_int_or_none` 316–317, `_storable_reply` 384–392, `_classifiable_reply` 395–404, `_classify_approval_response` 407–446, `_extract_structured_remote_command_text` 449–463 | 341 | `_conversation.py` |
| 7 | Host-state approval workflow | Tier C host actions and Tier B with approval: ask, decide, act or run the safe default, resolve on any failure | `_approval_workflow` 1821–1901, `_record_decision_after_failure` 1903–1936, `_resolve_failed_approval` 1990–2023, `_run_approval_workflow` 3517–4035; `_ApprovalProgress` 370–381 | 668 | `_host_approval.py` |
| 8 | Governed Tier C workflow | A physical Tier C action on a commissioned zone under `tier-c-approval/v1`: proposal row, admission transaction, live dispatch, outcome append | `tier_c_outcome_held_live` 2075–2082, `_governed_facts` 2084–2096, `_authority_now` 2098–2129, `_policy_inputs` 2131–2140, `_governed_notify` 2142–2169, `_close_now` 2171–2246, `_governed_approval_workflow` 2317–2509, `_run_governed_workflow` 2511–2975, `_governed_listen` 2977–3037, `_dispatch_admitted` 3039–3192, `_record_outcome` 3194–3263; `_PENDING_OUTCOME_CEILING` 137, `_MAX_REPLIES_PER_PROPOSAL` 141 | 1,110 | `_governed.py` |
| 9 | Tier C recovery and reconciliation | Settle a previous process's proposals at start, close open ones at stop, reconcile uncertain dispatches, report `action_records` | `action_records` 2027–2053, `action_records_degrade_health` 2055–2063, `mark_tier_c_recovery_failed` 2065–2073, `recover_tier_c_at_start` 3265–3363, `_recovery_context` 3365–3381, `_abort_open_proposal` 3383–3418, `close_open_proposals` 3420–3427, `reconcile_tier_c` 3429–3479, `reconcile_from_commissioned_feedback` 3481–3515 | 291 | `_recovery.py` |
| 10 | Record writer | The one ordered, bounded writer every record goes through after its act; shutdown drain and loss accounting; the override, decision and rejection records | `pending_record_count` 780–782, `record_backlog` 784–793, `decision_records_lost` 795–797, `_note_decision_lost` 799–800, `drain_records` 802–810, `abandon_records` 812–835, `_defer_record` 837–881, `_record` 883–895, `_record_after_holder` 897–930, `_log_tier_d_override_for` 932–941, `_log_tier_d_override` 943–955, `_defer_tier_c_decision` 1938–1988, `_log_tier_c_decision` 4037–4168, `_store_rejection_pattern` 4264–4340; `_receipt_audit_fields` 213–222, `_stamp_correlation_id` 301–308, `_RecordMeta` 361–367, `_RECORD_QUEUE_CEILING` 157 | 426 | `_records.py` |
| 11 | Action recording and attestation | What one action-log row holds, and signing it into the evidence chain | `_log_action` 4627–4804, `_build_firmware_registration_snapshot` 4806–4828, `_attest_action` 4830–4950, `_firmware_source_confirmed` 4952–4985, `_resolve_state_store` 4987–4990; `_input_attestation_evidence` 225–250, `_input_firmware_freshness` 253–275, `_ATTESTATION_BOUND_S` 153, `_INPUT_*` 165–166 | 360 | `_recording.py` |

The core keeps `__init__` and the helpers more than one seam calls:
`_generate_proposal_id` 194–196 (both workflows), `_cancelled_here` 324–331
(host workflow, governed workflow, the governed listener), and
`_holds_tier_d_authority` 474–485 (routing and execution).

Calls that cross seams, which the split turns into calls between base classes
on one instance: routing → admission (`_admit_and_run`), safe defaults, policy
(`permits_relay_action`), writer; admission → execution, both workflows,
writer; both workflows → conversation, execution, writer, policy
(`_tier_c_comms_available`); governed and recovery → safe defaults
(`_safe_default_intent`); recovery → governed (`_close_now`,
`_governed_notify`); execution and routing → recording (`_log_action`, inline);
writer → recording.

## Shared state

Every attribute more than one seam reads or writes. Writes in `__init__` are
not listed. Attributes only one seam touches (`_records`, `_records_awaiting`,
`_unsettled_at_close`, `_decision_records_lost`, `_executors`,
`_inflight_tier_d_tasks`, `_proposal_deadlines`, `_append_failed`, `_clock`,
`_binding_view`, `_resource_resolvers`, `_capability_posture` and the rest)
stay with that seam's code but still live on the core.

| Attribute | Written outside `__init__` by | Read by |
| --- | --- | --- |
| `_resource_gate` | admission: `bind_resource_gate` 614 | admission 631, 1253; conversation 1581–1584; host 3845–3846; governed 3098–3100 |
| `_held_by_executor` | admission: 1506, 1509; writer: 923, 926 | routing 1224 |
| `_policy` | policy: `update_policy` 693 | policy; governed `_policy_inputs` 2132–2133 |
| `_relay_b_c_enabled` | none (tests assign it) | policy 743; governed 2139 |
| `_status_indicator` | none | policy 4597–4615; admission 1374–1384, 1463–1466; host 3570–3571, 4026–4028; governed 2485–2505 |
| `_tier_c_recovery_failed` | recovery: `mark_tier_c_recovery_failed` 2067 | governed 2377; recovery 2062 |
| `_pending_outcomes` | governed: 3133, 3218, 3253 | recovery `action_records` 2037–2046 |
| `_unknown_live` | governed: 3219; recovery: 3478, 3513 | governed 2081; recovery 2051 |
| `_uncertain` | governed: 3256; recovery: 3335, 3477, 3512 | recovery 2041–2044, 3493 |
| `_pending_ceiling` | none (tests assign it) | governed 2782, 3214; recovery 2050, 2061 |
| `_alert_sender` | none | policy 4624; conversation; governed 2145, 2157 |
| `_offline_token_verifier` | none | host 3801–3808; governed 2704–2706 |
| `_approval_require_scoped_replies` | none | conversation 4221; host 3765; governed 2696 |
| `_log_action_decisions` | none | admission 1432; execution 1538, 1740 |
| `_config` | none | policy, execution, conversation, both workflows, writer |

Tests assign `_relay_b_c_enabled`, `_pending_ceiling` and `_clock` on the
instance and replace `_listen_for_response` and `_dispatch_admitted` on it.
One instance composed of base classes keeps every such assignment working.

## Orderings that exist for a safety reason

Each row is a constraint the split must keep, with the reason the code or the
contract gives, where it is enforced, and the test that pins it today.
Test paths are under `tests/`. **None** marks an ordering no test pins; the
summary at the end of this section lists them.

### Tier routing (`dispatch`)

| # | Ordering | Reason | Enforced | Pinned by |
| --- | --- | --- | --- | --- |
| R1 | The tier is upper-cased before any comparison | Case is not authority: a lowercase `d` must reach the safety-critical path | 1021 | `test_action_dispatcher.py::TestUnknownTier::test_lowercase_tier_routes_to_the_real_tier` |
| R2 | An unknown tier is refused before escalation or the floor sees it | Both rank an unknown tier 0 and would "raise" it into an executable one | 1028–1045 | `test_action_dispatcher.py::TestUnknownTier::test_unknown_tier_is_refused_not_executed` |
| R3 | Tier D without first-party provenance is lowered to C before escalation and the floor | Tier D is granted, never assumed; absence of the attribute is absence of the grant | 1059–1067 | `test_skill_authority_boundary.py::test_dispatch_lowers_tier_d_from_a_non_first_party_skill`, `::test_absent_provenance_is_not_trusted_provenance` |
| R4 | The skill's declaration may only raise, and escalation into D is capped at C; the registry floor is applied after it | The declaration is untrusted input; Tier D comes from the trigger alone; the runtime registry always wins | 1069–1126 | `test_skill_authority_boundary.py::test_skill_cannot_escalate_an_action_into_tier_d`, `::test_dispatch_raises_a_tier_a_relay_action`; `test_action_dispatcher.py::TestCapabilityTierGuard` |
| R5 | The safe default is vetted before relay policy substitutes it for the action | A safe default runs without approval; the downgrade at 1175 makes it the action | 1131, then 1175 | **None.** No test drives a policy suppression with an ineligible safe default. The floor check in `_execute_immediately` (1706) would refuse such a substitute on its own |
| R6 | Relay policy is decided after the floor, on the governed outcome, not the name | Every action resolving to a protected-circuit outcome is the relay's; a relay declared Tier A is suppressed only once raised to C | 1152–1156 | `test_skill_authority_boundary.py::test_dispatch_raises_a_tier_a_relay_action`; `test_tier_c_governed_approval.py::TestRelayPolicyIsDecidedByClass::test_no_protected_circuit_action_is_proposed_when_withheld` |
| R7 | The suppression row is written before the downgrade rewrites the action | So the attempted relay action is preserved in `action_log` | 1157–1176 | `test_tier_c_governed_approval.py::TestRelayPolicyIsDecidedByClass::test_no_protected_circuit_action_is_proposed_when_withheld` (asserts the `suppressed` row under the original name) |
| R8 | Every record is opened before the act and written after it; a Tier D override is registered ahead of the row, so it lands after the act and before the row | A busy store or a signer must never hold a trip; the shutdown drain must count a record while its executor drives (`docs/DISPATCH_PLAN.md`, the evidence record) | 1187–1206 | `test_tier_d_never_waits_on_evidence.py::TestTheRecordLandsAfterTheAct::test_no_record_begins_before_the_executor_has_run`, `::TestAStopBetweenTheActAndItsRecord::test_the_override_entry_lands_while_the_action_row_is_held` |
| R9 | A record left unsettled on exit is cancelled unless an executor still holds it | A dispatch that left without a result has nothing to record and must not wedge the writer | 1218–1226 | `test_tier_d_never_waits_on_evidence.py::test_a_dispatch_cancelled_before_its_act_does_not_wedge_the_writer`; `test_contributor_records.py::test_a_dispatch_cancelled_at_the_gate_leaves_no_record_unsettled` |

### Resource admission (`_admit_and_run`)

| # | Ordering | Reason | Enforced | Pinned by |
| --- | --- | --- | --- | --- |
| A1 | The resource is resolved before the gate; an unresolved one is refused unless the registry proves the action inert | An action that looks arbitrated and is not is the failure this boundary exists to prevent | 1252–1275 | `test_dispatch_plan.py::TestTheBoundaryFailsClosed` (both tests) |
| A2 | The gate decides before any executor, whatever called the dispatcher | Contention is decided on the resource driven, never the name; the gate is consulted at the last point before an executor runs (595–599) | 1282–1366 | `test_dispatch_plan.py::TestExecutionBoundary::test_the_dispatcher_admits_against_the_gate_whatever_called_it` |
| A3 | A joined request returns without acting or waiting, and its row is handed over only after the holder's | Execution is merged, authority never is; the holder's row is written first so a holder still deciding never appears missing | 1303–1335, 897–930 | `test_contributor_records.py::test_a_request_joining_a_held_trip_is_a_contributor`, `::test_a_request_joining_an_uncertain_holder_does_not_wait`, `::test_a_holder_still_running_is_not_reported_missing` |
| A4 | Whether the act awaits an operator is decided before the gate request; `mark_running` precedes the executor only on paths that await none; an approval path reaches RUNNING only through `reply_admitted` after the decision | A proposal is not an attempt: Tier D invalidates a proposal it would otherwise have to wait behind (`docs/DISPATCH_PLAN.md`, the five states) | 1295–1301, 1370–1371; `ori/reasoning/resource_gate.py:540–569` | `test_dispatch_plan.py::TestTierDDoesNotWaitOnAnApproval` (both tests) |
| A5 | Tier D sets the indicator, then runs in its own tracked task, awaited through `shield` | Shutdown drains Tier D work; a cancellation of the caller must not abandon the act | 1373–1384 | `test_action_dispatcher.py::TestCancellationHandling::test_asyncio_shield_prevents_tier_d_abandonment_on_cancellation`, `::TestTierD::test_tier_d_tasks_are_tracked_without_task_attribute_hacks` |
| A6 | If the caller is cancelled while the shielded executor drives, the resource is marked uncertain and retired only when the executor settles | Retiring while a command is in flight would admit the opposite command to the same actuator | 1468–1479, 1587–1600 | `test_dispatch_plan.py::TestACancelledTripDoesNotFreeTheResource` (four tests) |
| A7 | The resource is retired after the act, as accepted only if the proposed act ran | A safe default after a NO is never the proposed physical act; a joiner must not report one | 1481, 288–298 | `test_tier_c_governed_approval.py::test_a_joiner_on_the_host_state_workflow_is_not_executed_after_a_no`, `::TestAJoinedContributorReportsTheProposedAct::test_an_uncertain_command_settles_on_the_proposed_act` |
| A8 | A row whose executor still drives waits for what it reports, and the dispatch answers rather than raising; otherwise the row is handed over before the caller's cancellation is re-raised | What the dispatch can say at interruption is not what happened | 1483–1491, 1494–1518 | `test_tier_d_never_waits_on_evidence.py::test_an_interrupted_act_records_what_its_executor_reported`; `test_action_dispatcher.py::TestCancellationHandling::test_a_tier_d_dispatch_still_driving_answers_rather_than_raises`, `::test_a_cancelled_dispatch_is_recorded_then_propagates`, `::test_a_cancellation_from_before_the_dispatch_is_not_handed_back` |
| A9 | Tier C always reaches an approval workflow: physical to the governed one, host-state to the host one; Tier B asks only when the matched trigger requires approval | CLAUDE.md, the Action Tier Framework | 1389–1429, 1603–1624 | `test_action_dispatcher.py::TestTierC::test_always_calls_approval_workflow`, `::TestTierBWithApproval`; `test_tier_c_governed_approval.py::TestTheProposalIsCommittedBeforeTheAsk` |

### Execution (`_execute_immediately`)

| # | Ordering | Reason | Enforced | Pinned by |
| --- | --- | --- | --- | --- |
| X1 | Tier D provenance is checked again before any executor, and refused rather than lowered | This method is reachable directly and every path converges here; no approval workflow is left to fall into | 1680–1698 | `test_skill_authority_boundary.py::test_execute_immediately_refuses_tier_d_without_provenance` |
| X2 | The registry floor is checked again, and refused rather than raised | The approval path has been passed or skipped; raising here would execute with the authority missing | 1706–1726 | `test_skill_authority_boundary.py::test_execute_immediately_refuses_below_the_floor` |
| X3 | `executed` is false until an executor ran and reported success | An approved action with no executor once sealed an attestation that nothing backed (`docs/DISPATCH_PLAN.md`, what `executed` has to mean) | 1733–1752 | `test_action_dispatcher.py::TestMissingExecutorNeverReportsExecution` |
| X4 | A Tier D action reporting itself suppressed is treated as a failure, before the escalation decision | It would otherwise skip the emergency notice | 1770–1779 | **None** |
| X5 | A failed Tier D act's emergency notice is sent beside the next act in a tracked task, never ahead of it | A channel that does not answer must not hold another trip | 1781–1801 | `test_tier_d_never_waits_on_evidence.py::TestAFailedTripsNoticeDoesNotHoldTheNextTrip`; `test_dispatch_never_waits_on_delivery.py::TestAFailedTripStillRaisesTheAlarm`; `test_action_dispatcher.py::TestTierD::test_executor_failure_logs_critical_and_calls_emergency_sms` |

### Host-state approval workflow

| # | Ordering | Reason | Enforced | Pinned by |
| --- | --- | --- | --- | --- |
| H1 | The safe default is vetted again inside the workflow | This is the method that runs it without approval; it does not trust the caller | 3557 | `test_skill_authority_boundary.py::TestSafeDefaultsCannotActuate::test_rejected_tier_c_does_not_actuate_via_the_fallback` (calls the workflow directly) |
| H2 | The proposal id and start time are recorded on the progress object before the ask | Whatever fails later, the failure path resolves the proposal under its id | 3559–3562, 3610 | `test_action_dispatcher.py::test_a_fault_before_any_decision_runs_the_safe_default` |
| H3 | The gate marks the resource as a proposal only once the ask was accepted for delivery or a local listener is attached | An ask that never went out is not a proposal a later arrival should treat as one | 1578–1584 | `test_gate_foreclosure_by_event.py::TestTheDispatcherMarksAnAskOnlyWhenOneWentOut::test_ask` |
| H4 | A reply is made storable and classifiable before classification; text UTF-8 cannot carry is no decision | Escaping must never turn a reply into a valid approval | 3755–3756 | `test_action_dispatcher.py::test_escaping_a_reply_never_makes_it_a_valid_approval`, `::test_a_remote_reply_the_store_cannot_hold_still_resolves` |
| H5 | A v1 offline token is refused for any physical or Tier C action before a verifier is consulted | A v1 token names no proposal, target or zone (`tier-c-approval/v1`, Admission) | 3789–3800 | `test_action_dispatcher.py::TestOfflineTokenApproval::test_a_v1_token_never_approves_a_tier_c_action` |
| H6 | An approval is checked against the gate after classification and before the act | Acting on a displaced proposal would undo the act that displaced it, for Tier D a trip | 3845–3858 | `test_dispatch_plan.py::TestALateApprovalCannotUndoATrip::test_a_yes_on_an_invalidated_proposal_is_refused`; `test_late_refused_approval_record.py::TestALateRefusalUsesNoSafeDefault` |
| H7 | What was acted is stored on the progress object immediately after the act, before any record or escalation | A later fault reports the act as it ran and never runs the safe default after an approved act | 3863–3916, 1871–1881 | `test_action_dispatcher.py::test_a_fault_after_an_approved_act_reports_the_act`, `::test_a_fault_after_the_safe_default_ran_does_not_run_it_again`; `test_decision_record_after_failure.py::test_a_fault_after_a_rejection_still_records_it` |
| H8 | A cancellation after the act queues its decision and carries the act before propagating | The row must say what happened | 1847–1864 | `test_decision_record_after_failure.py::test_a_cancellation_after_the_act_still_records_the_decision_and_the_act`; `test_action_dispatcher.py::test_an_approval_survives_a_cancel_while_the_approved_act_runs` |
| H9 | On an unanswered end the safe default runs before the secondary recipient is told | The escalation reports the safe default's outcome (4527, 4533) | 3897–3926 | **None.** `TestAnUnansweredApprovalSaysWhyItEnded` and `test_tier_c_timeout_escalates_to_secondary` assert only the headline and the recipient |
| H10 | The decision record is deferred after the act and queued exactly once | A busy store must not drop what the operator decided, nor hold the act | 3996–4023, 1903–1936 | `test_tier_d_never_waits_on_evidence.py::test_the_operator_decision_is_held_until_the_store_takes_it`; `test_decision_record_after_failure.py::test_a_decision_queued_once_is_not_queued_again` |

### Governed Tier C workflow

The order is `tier-c-approval/v1` (The Proposal, Admission, Dispatch,
Reconciliation, Safe Defaults) and `docs/DISPATCH_PLAN.md` ("Governed
approval"); the rows cite those rather than restate them.
`test_tier_c_approval_sequences.py::test_admission_sequence` replays every
sequence of `tests/vectors/tier_c_approval/admission.json` through the real
dispatcher; where a row says "corpus", that is the pin, and the six sequences
it pins as not representable are listed in `EXPECTED_NOT_REPRESENTED` there.

| # | Ordering | Reason | Enforced | Pinned by |
| --- | --- | --- | --- | --- |
| G1 | Before any row: no zone, outcome or snapshot refuses; then incomplete recovery refuses; then relay policy refuses, on its own though dispatch decided it already | No proposal over proposals this process never read; each layer fails closed on its own | 2343–2450 | `test_tier_c_governed_approval.py::test_a_physical_action_with_no_zone_is_refused_not_asked`, `::TestRecoveryThatDidNotComplete`, `::TestRelayPolicyIsDecidedByClass::test_the_governed_path_refuses_on_its_own_when_dispatch_did_not`; `test_safe_default_used_records_execution.py::TestGovernedRefusalsBeforeAProposal` |
| G2 | The safe default is admitted under the contract's rule before the row binds it | Safe Defaults: informational and eligible, or refused | 2451–2458 | **None** at the dispatcher; `test_tier_c_approval_vectors.py` tests `safe_default_admitted` alone |
| G3 | The monotonic deadline is fixed before the row commits | Admission and dispatch expiry are decided on it alone (The Proposal) | 2460–2465 | corpus (the wall-clock jump sequences) |
| G4 | An outcome this process holds unappended blocks creation before the store is asked | Reconciliation: one the live runtime could not append blocks creation | 2554–2555 | `test_safe_default_used_records_execution.py::test_a_proposal_refused_for_an_unresolved_outcome` (`live`); corpus |
| G5 | An identifier already in use is replaced by a fresh one, never the old row | A new proposal must not inherit another proposal's row | 2567–2573 | **None** |
| G6 | The row commits before the operator is asked; a row not committed means no ask, the safe default attempted, nothing claimed durable | The Proposal | 2574–2612, then 2614–2644 | `test_tier_c_governed_approval.py::TestTheProposalIsCommittedBeforeTheAsk` (three tests); `test_safe_default_used_records_execution.py::test_a_proposal_row_the_store_could_not_commit` |
| G7 | A token is verified and its attempt audited before admission; its claim happens inside the admission transaction | Admission; `offline-tokens/v2` | 2701–2751, 2801 | `test_tier_c_governed_approval.py::TestOfflineTokensV2`; `test_tier_c_approval_sequences.py::test_token_binding_sequence` |
| G8 | Expiry is checked on the monotonic clock before the reply is admitted | A reply after expiry is not an approval (The Proposal) | 2762–2767 | `test_tier_c_governed_approval.py::TestExpiry::test_a_reply_after_the_deadline_is_not_an_approval`; corpus |
| G9 | The facts are re-read for the proposal's own zone, then binding, authority, the same-outcome block, the reservation and the token are decided in one store transaction | Admission; Reconciliation (the block is evaluated again at admission) | 2770–2803 | `test_tier_c_governed_approval.py::TestBindingAndBlocking::test_a_changed_binding_makes_the_reply_no_approval`, `::test_a_reply_the_store_cannot_admit_is_retried_by_a_later_reply`; corpus |
| G10 | Replies that decide nothing cannot close a proposal: after twenty, listening slows to once a second until the deadline | A noisy channel must neither hold the loop nor retire the proposal | 2659–2670, 2686 | `test_tier_c_governed_approval.py::TestNoiseNeverClosesAProposal` |
| G11 | After the commit: the deadline is checked again, then the gate (`reply_admitted`, which moves the holder to RUNNING), then the executor, with nothing written ahead of it; the dispatch marker is a task beside the act | Dispatch: no write between commit and executor; expiry before dispatch is `approval_expired_undispatched` | 3070–3153 | `test_tier_c_governed_approval.py::TestExpiry::test_an_approval_that_outlives_its_window_in_the_commit_grants_nothing`, `::TestBindingAndBlocking::test_a_contended_resource_refuses_the_approved_act`, `::TestLiveImmediateDispatch::test_nothing_is_written_between_the_commit_and_the_act` |
| G12 | The outcome is appended after the act, retried while live, never claimed durable early; past the ceiling it is a live unknown | Dispatch (the reserved record, `unknown_live`) | 3171–3263 | `test_tier_c_governed_approval.py::TestLiveImmediateDispatch` (outcome tests), `::TestHealth`; corpus ("a full pending structure…", "an outcome that cannot be appended…", "a blocked outcome writer…") |
| G13 | A cancellation while the approved act runs records `dispatch_outcome_unknown` before re-raising | The executor may still be driving; the outcome is unknown, not failed | 3154–3160 | **None** |
| G14 | A proposal that did not dispatch is closed, with its safe-default intent in the same transaction, before the safe default runs and before the decision is reported; a close the store will not take is reported `_unrecorded` and counted lost | The live result never says what the durable row does not | 2873–2932, 2171–2246 | `test_tier_c_governed_approval.py::TestTerminalDecisionsAreDurableBeforeTheyAreReported`, `::TestARefusedTransitionIsNeverReportedAsRecorded`, `::TestSafeDefaultIntentsAreObligations::test_a_rejection_whose_close_cannot_land_is_a_lost_decision` |
| G15 | The safe-default intent is ensured before the attempt and marked after it | The intent is the obligation; at most one per proposal (Safe Defaults) | 2265–2315 | `test_tier_c_governed_approval.py::TestSafeDefaultIntentsAreObligations::test_a_restart_attempts_a_pending_intent_once_and_then_never_again`, `::TestRestart::test_a_repeated_restart_creates_one_safe_default_intent`; `test_safe_default_used_records_execution.py::test_an_intent_already_attempted_is_not_claimed_by_this_record` |
| G16 | On an unanswered end the safe default runs before the secondary recipient is told | As H9 | 2898–2910 | **None** |

### Tier C recovery and reconciliation

| # | Ordering | Reason | Enforced | Pinned by |
| --- | --- | --- | --- | --- |
| C1 | Recovery runs after every executor is registered and before any sensor connects; a failure fails Tier C closed and nothing else | The safe default needs its executor; no proposal is raised over unsettled ones; Tier D consults none of this | `ori/runtime/_startup.py:271–298`; refusal at 2377 | `test_startup_stages.py` (`SAFETY_ORDERINGS`: tier C recovery after the dispatcher, sensors after tier C recovery); `test_runtime.py::test_a_failing_recovery_refuses_tier_c_and_lets_the_start_finish` |
| C2 | An approval left without an outcome is recorded uncertain, never replayed: `dispatch_started` becomes `dispatch_outcome_unknown`, `approved_pending_dispatch` becomes `dispatch_not_proven` | Restart: an absent marker proves nothing | 3297–3333 | `test_tier_c_governed_approval.py::TestRestart::test_a_restart_replays_nothing`; corpus |
| C3 | An open proposal is closed before its safe default runs, and the safe default before the operator is told | Restart: closed `proposal_aborted_restart` with its one safe default | 3393–3418 | `test_tier_c_governed_approval.py::TestRestart::test_a_repeated_restart_creates_one_safe_default_intent`; corpus |
| C4 | Pending safe-default intents are resumed after the rows are settled, each re-admitted as a safe default first | The intent is the obligation; a stored action is re-checked | 3345–3362 | resumption: `test_tier_c_governed_approval.py::test_a_restart_attempts_a_pending_intent_once_and_then_never_again`; the re-admission at 3350 and 3391: **None** |
| C5 | A graceful stop cancels the sensor loops, then closes open proposals | No live process remains to admit a reply | `ori/runtime/_shutdown.py:105–131` | `test_tier_c_governed_approval.py::TestGracefulStop`; `test_runtime.py::test_a_graceful_stop_closes_an_open_proposal` |
| C6 | A reconciliation's arguments are refused before the store is asked; the in-memory blocks clear only after the store records it | `operator-socket` order; health must not clear what the store did not take | 3451–3479 | `test_tier_c_governed_approval.py::TestRestart::test_a_reconcile_request_is_refused_in_the_contracts_order`; corpus |
| C7 | Feedback reconciles only when its commissioned mapping proves the outcome | Reconciliation (b) | 3490 | corpus (the feedback sequences) |

### Recording

| # | Ordering | Reason | Enforced | Pinned by |
| --- | --- | --- | --- | --- |
| W1 | One writer takes records in the order they become writable and retries a busy store; a contributor's row follows its holder's | A record that cannot land holds the ones behind it rather than being overtaken | 837–930 | `test_tier_d_never_waits_on_evidence.py::test_rows_land_in_the_order_the_acts_settled`; `test_contributor_records.py::test_a_holder_still_running_is_not_reported_missing` |
| W2 | The Tier D override entry is decided when written, after the act, and only for an autonomous dispatch, never a contributor | A request that joined another dispatch's act dispatched nothing autonomously | 932–941 | **None.** No test asserts a Tier D joiner writes no override entry |
| W3 | The registration snapshot and the licence are built before the insert and land in the row's own insert | A follow-up write would leave a row with no provenance that can never be reconciled | 4683–4766 | `test_action_dispatcher.py::TestFirmwareProvenanceAtomicity::test_snapshot_is_in_the_initial_action_row_insert`; `test_tier_d_never_waits_on_evidence.py::test_the_firmware_snapshot_is_retried_with_its_row` |
| W4 | Signing follows the committed row, and only for a dispatch row inserted with its licence | Option B atomicity (`DECISIONS.md`); a contributor holds no licence | 4718–4722, 4767–4771, 4790 | `test_action_dispatcher.py::TestTierDIsIndependentOfEvidence::test_attestation_runs_after_the_action_not_before`; `test_contributor_records.py::test_a_request_joining_a_held_trip_is_a_contributor` |
| W5 | The source's confirmation is read before signing, fails closed, and both are bounded | Firmware evidence is signed only under a confirmed epoch; a signer that never answers must not hold the writer | 4893–4912, 4952–4985 | bound: `test_tier_d_never_waits_on_evidence.py::test_a_signer_that_never_answers_leaves_its_row_pending`; the confirmation gate on this path: **None** (`evidence/test_reconciliation.py::TestFirmwareConfirmationGate` pins `OriRuntime._firmware_source_confirmed`, a different function) |
| W6 | A durable write raises to the writer rather than being swallowed | A swallowed failure would read to the writer as a record written | 4160–4164, 4332–4336, 4696–4699, 4779–4783 | `test_durable_record_failures.py::test_a_locked_decision_write_is_retried_and_lands`; `test_tier_d_never_waits_on_evidence.py::TestEveryRecordSurvivesALockedStore`, `::test_a_permanent_store_error_is_counted_lost_not_retried` |

### Orderings no test pins

R5, X4, H9, G2, G5, G13, G16, C4 (re-admission of a stored safe default), W2
and W5 (the confirmation gate). Each is owed a test that fails when the
ordering is reversed, before the seam that holds it moves.

The pins above were identified by reading the tests, not by mutating the code:
a pin listed here is a test that exercises the ordering, and whether it fails
when the ordering is reversed is part of the guard work, not established here.

## Boundaries that must stay independent

"A check that holds only because an earlier check held is not a boundary"
(CLAUDE.md). The dispatcher repeats these checks on purpose; each copy must
stay in the seam that acts, and no move may hoist one into a caller or fold
two into a shared helper called once.

| Check | First | Again, where it acts |
| --- | --- | --- |
| Tier D provenance | routing 1059 | execution 1680 |
| Registry floor | routing 1116 | execution 1706 |
| Safe default eligibility | routing 1131 | host 3557; governed 2451 (`safe_default_admitted`); recovery 3350, 3391 |
| Relay policy | routing 1156 | governed 2417 |
| Resource gate | admission 1299 | host 3846, governed 3100 (`reply_admitted`) |
| Proposal deadline | governed 2762 | governed 3070, after the commit |

## Proposed move order

Each step is one reviewable change: code moved unchanged, the public surface
and every assertion unchanged, the module-size ceiling lowered to what is
left.

1. **Package skeleton and core.** The module becomes the package; `__init__`
   and the shared helpers move to the core; the class is composed from the
   core alone. The source readers are pointed at the package as
   `tests/package_layout.py` does for `ori/runtime/`: the keys
   `ori/reasoning/action_dispatcher.py::<qualname>` in
   `tests/test_firmware_command_action_boundary.py`, `tests/test_module_size.py`
   and `tests/test_function_size.py`; the path derived from
   `ActionDispatcher.__module__` in
   `tests/firmware/test_reading_age_presentation.py:167`. First because every
   later step depends on it and it moves no logic.
2. **The missing pins.** The ten tests above, against the code as it stands,
   so each later move is checked by a test that already passed before it.
3. **Leaves with no ordering of their own:** policy and capability (1), then
   action recording (11). Each is called by others and calls back into none.
4. **Record writer (10).** Holds W1, W2 and R8's mechanism; every other seam
   writes through it, so it moves before the seams that call it.
5. **Operator conversation (6)** and **safe defaults (5)**, separately. Both
   approval workflows call them; moving them first leaves each workflow move
   holding only its own orderings.
6. **Execution (4).** Holds X1–X5; called by admission, both workflows and
   safe defaults.
7. **Governed workflow (8),** then **recovery (9).** Recovery calls
   `_close_now` and `_governed_notify` and shares four attributes with it, so
   it follows.
8. **Host-state workflow (7).**
9. **Routing (2) and admission (3),** the spine that holds the cross-seam
   orderings, last, once everything they call has moved.
10. **Function size.** In separate changes after the moves, the oversized
    methods are cut at their existing phase boundaries, with the progress
    object as the only state crossing a cut:
    `_run_approval_workflow` at ask (3554–3610), listen (3612–3750),
    classify (3752–3838), decide and act (3840–3972) and record
    (3974–4024); `_run_governed_workflow` at its numbered steps, proposal row
    (2550–2612), ask (2614–2644), listen and admit (2646–2871), resolve
    (2873–2944) and record (2946–2975). Each cut keeps the order of
    statements, so every row above holds as before.

## What the split must not change

- **The public surface of `ActionDispatcher`.** The constructor signature
  (506–518) and the methods: `bind_resource_gate`,
  `register_resource_resolver`, `register_executor`, `update_policy`,
  `update_capability_posture`, `current_policy_version`,
  `get_policy_state_snapshot`, `permits_relay_action`,
  `permits_external_alert`, `permits_alert_class`,
  `get_inflight_tier_d_tasks`, `pending_record_count`, `record_backlog`,
  `decision_records_lost`, `drain_records`, `abandon_records`, `dispatch`,
  `action_records`, `action_records_degrade_health`,
  `mark_tier_c_recovery_failed`, `tier_c_outcome_held_live`,
  `recover_tier_c_at_start`, `close_open_proposals`, `reconcile_tier_c`,
  `reconcile_from_commissioned_feedback`. The module's names: `ActionDispatcher`,
  `ActionTier` and `SkillContext` (re-exported and imported through it by
  tests), `UngovernedActionError`, `_classify_approval_response` (imported by
  `tests/test_action_dispatcher.py`). The patch targets tests reach through
  the module: `_generate_proposal_id` (both workflows must see a patch of it),
  `now_ms`, `logger`, `asyncio.wait_for` and `_ATTESTATION_BOUND_S`; each must
  stay reachable at the binding its readers look up, as `patch_runtime` does
  for the runtime package.
- **The dispatch order in CLAUDE.md.** The discovery barrier and Tier D first
  live in `ori/reasoning/dispatch_coordinator.py`, outside this module; the
  dispatcher's part is step 5, which rows A1–A9 and X1–X5 hold.
- **Every row above**, and the independence of every check in the boundaries
  table.
- **The record path.** No record is awaited ahead of an act, the writer stays
  one instance, and the shutdown drain counts what it counts now.

## Observed while reading, not changed here

Each is its own issue if it should change.

- **The Tier C pending indicator can stay lit.** The host-state workflow sets
  it at 3570–3571; the `try` whose `finally` clears it opens at 3758. A
  failure or cancellation between them, in composing the message, the ask or
  the listen, leaves it set: `_approval_workflow`'s failure path (1846–1901)
  resolves the proposal and never clears it. Confirmed by driving a host-state
  Tier C dispatch with `_format_approval_message` raising: the indicator
  received `set` and no `clear`. The governed workflow clears in a `finally`
  (2501–2509).
- **A governed proposal can stay open while the process lives.** After the
  row commits (2559), nothing in `_governed_approval_workflow` (2489–2509) or
  `_run_governed_workflow` catches a failure; it reaches `_admit_and_run`
  (1441–1461), which records an interrupted result. The row stays `proposed`
  and no safe default runs until a graceful stop (C5) or the next start (C3)
  closes it. Confirmed with `_format_approval_message` raising: result
  `action_taken=""`, row `proposed`, no executor ran. Nothing actuates, but
  the docstring's "whatever fails, the proposal resolves" (2334–2335) holds
  only across a restart.
- **`_admit_and_run`'s last branch runs an unknown tier as Tier A**
  (1431–1439). Unreachable while `dispatch` refuses one first (R2), which is
  the shape the boundary rule forbids.
- **Recovery does not check what `advance_tier_c_proposal` answered** at 3298
  and 3317, unlike `_close_now` (2211–2230); a refused move is still counted
  and reported uncertain. Impact not established.
- **Some refusals are written inline,** not through the writer: the unknown
  tier (1044), the relay-policy suppression (1168, ahead of the safe default
  it substitutes) and `_execute_immediately`'s two refusals (1697, 1725). If
  either of the latter were reached through `dispatch`, the caller's deferred
  row would record the same refusal a second time.
- **`reconcile_from_commissioned_feedback` has no caller in `ori/`**; only the
  sequence corpus drives it.
