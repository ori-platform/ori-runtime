# The Dispatch Plan

What the runtime decides when a sensor reading matches more than one trigger:
which actions run, at what authority, in what order, against which physical
resource, and what the record of it says afterwards.

This document settles the contract. It changes no control flow on its own, and
it exists because three defects in the current dispatch path have fixes that
contradict each other unless the vocabulary is fixed first. It is a design
contract at **proposed** proof level; every measurement quoted below is
host-measured against the current tree and labelled where it is not.

## Why a contract rather than three fixes

Three defects sit on this path. A Tier D trip is shadowed by an earlier Tier A
trigger, because the rule engine returns the first match in declaration order
and the elevator selects a winner by comparing that one name against the
handler's own trigger. Every action in a plan is dispatched at the *trigger's*
tier, so a Tier C plan cannot notify anyone and a Tier D plan seals
notifications into the evidence chain as safety-critical actions. And shipped
Tier D triggers name protective actions that are not in the action registry at
all.

Taken separately, the obvious repair to the second breaks Tier D. Dispatching
each action at its own tier, floored by the registry entry, is the natural
reading — and the registry deliberately refuses to hold a Tier D floor:

> No entry may set a Tier D floor. The registry exists to add operator
> authority, and Tier D is the one tier that removes it. `trip_relay` is
> registered at C for exactly this reason: a skill may propose it for
> approval, and it reaches D only when a safety condition licenses the outcome
> it resolves to.

So an action's own tier, floored by the registry, cannot reach D. Applying that
rule sends the safety trip into the approval workflow and waits for a human,
which is the precise outcome Tier D exists to avoid. The tier an action is
dispatched at is not a property of the action alone, and saying so is most of
what this contract does.

## Two tiers, not one

The tier letter folds two independent decisions together, and this contract
depends on them being separate. **Consequence class** — informational, soft,
hard — is what an action does to the world, and the runtime registry owns it
because reversibility is a fact about site wiring established at commissioning.
**Authority basis** — autonomous, operator approval, or a release-owned safety
condition — is what licenses one dispatch. A is informational and autonomous; D
is hard under a safety condition. They share an authority basis while sitting at
opposite ends of the letter ordering, which is why every rule below that takes a
maximum over tiers has to exempt informational actions. `skills-package/v3.md`
in `ori-specs` carries the model and its reasoning.

**Incident tier** is the matched trigger's `action_tier`. It describes the
severity of what the device observed. It belongs to the trigger, travels with
the reasoning result, and belongs in the evidence record.

**Action tier** is the authority one action needs before it may take effect. It
belongs to the action, is floored by the runtime's registry, and decides
whether the action fires immediately, enters the approval workflow, or is
refused.

Today these are one value. A WhatsApp message accompanying an overcurrent trip
is dispatched at Tier D because the incident is Tier D, and a WhatsApp message
accompanying a Tier C proposal waits for someone to approve sending it — the
message that would ask for the approval is itself pending approval.

## The plan

One dispatch plan per skill per event, built once from an exhaustive
evaluation. It replaces the current arrangement, in which the loader subscribes
one handler per trigger, every handler fires for every event, and each handler
re-evaluates all rules and returns silently unless the single winning rule is
its own.

A plan holds the event, its correlation id, every trigger that matched with its
incident tier, and for each of those triggers the actions its `actions.defaults`
names. Nothing in the plan is decided by the order triggers appear in
`skill.yaml`.

## Assigning the action tier

A safety condition licenses **one commissioned outcome on one resource**. It
does not license everything that happens to share a plan with it. So the
incident tier is not an input that other actions inherit:

```text
dispatch_tier(action) =
    A                             if informational(action)
    D                             if action is the outcome the safety
                                  condition licenses, and the Tier D grant
                                  below holds in full
    min(C, max(registry_floor, declared_tier))   otherwise
```

`informational(action)` is true only when the runtime's own registry holds an
entry with `minimum_tier == "A"` and `physical is False`. The skill's
declaration does not decide it, and an action with no registry entry is never
informational — the runtime cannot prove that something it does not govern is
inert.

**Nothing inherits authority from the incident.** An ancillary action in a Tier
D plan runs at its own authority, capped at C, or is refused. A notification in
a Tier C plan is Tier A. This is what "consequence class does not travel between
actions" has to mean to be worth stating, and an earlier form of this rule took
the maximum over the incident tier, which travelled it in both directions: it
raised every non-informational action in a Tier D plan to D, and it promoted a
reversible Tier B action in a Tier C plan into the hard-physical approval
workflow.

The cap at C on the third branch is the same rule the loader already applies to
a package's action list. An action reaches D through the licensed-outcome branch
or not at all.

| Incident | Action | Floor | Licensed outcome | Dispatched | |
|---|---|---|---|---|---|
| D | `close_gas_valve` | C | yes | **D** | the licensed protective act fires autonomously |
| D | `release_relay` | C | no | **C** | closing the circuit is not what the leak condition licenses; it waits for a human |
| D | `terminate_process` | B | no | **B** | ancillary, keeps its own authority |
| D | `alert_whatsapp` | A | — | **A** | a notice is a notice |
| C | `alert_whatsapp` | A | — | **A** | fixes the plan that could not notify anybody |
| C | `trip_relay` | C | — | **C** | approval workflow, always |
| C | `terminate_process` | B | — | **B** | a reversible action is not promoted by a hard incident |
| A | `terminate_process` | B | — | **B** | the registry floor still raises |

### Consequence class is resolved against the binding, not the name alone

The registry classifies an action by name, and reversibility is a property of
the commissioned zone. `release_relay` resolves to `close_protected_circuit`,
and whether that isolates or reconnects the load is established per channel at
commissioning. So the registry gives the class an action *can* have, and the
binding decides what it means on this device.

The two must compose into one floor, or an implementer has to invent whether the
binding may raise, lower, or only refuse:

```text
effective_consequence(action, binding) =
    informational        only if the registry proves it informational
    binding-resolved     otherwise: soft or hard, as the zone establishes

ordinary_dispatch_tier =
    min(C, max(floor_of(effective_consequence), declared_tier))
```

**The binding may raise and may never lower.** A registry floor of B on a zone
whose mapping makes the act irreversible resolves to hard, and the action
dispatches at C. The converse is refused rather than applied: a registry floor
of C is never lowered to B because a binding claims the act is reversible, since
the registry floor is the runtime's own reviewed judgement and a binding is site
data. Disagreement in that direction is a commissioning error and is reported.

Where an action **requires a commissioned physical binding** and none covers its
resource, it is not dispatched at all — the runtime has no basis to say what it
would do. That is scoped deliberately: `terminate_process` and
`reset_kernel_subsystem` change host state and resolve through no commissioned
zone, so they take their registry floor and are unaffected. The rule binds the
actions that drive a commissioned actuator, which are the ones whose meaning a
zone establishes.

### `physical is False` is reviewed, not proven

The informational exemption rests on registry metadata that no mechanism
enforces. Every current A-floor entry — `alert_whatsapp`, `alert_sms`,
`log_to_dashboard` — stays inside the notification and record path, but that is
a fact about today's executors rather than an invariant. Any change to an
informational executor, and any new A-floor entry, carries a test obligation:
show that it mutates no host, actuator or supply state. Without that, the
exemption is a hole that opens quietly.

## Granting Tier D

Tier D removes the operator, so it is granted rather than declared, and it is
granted **to one outcome on one resource** rather than to an action name or a
plan. An action is dispatched at Tier D only when every one of these holds:

1. the incident is Tier D — a matched trigger declaring `action_tier: D`, with
   `bypass_llm` enforced true by the loader;
2. the trigger belongs to a first-party skill, by `Skill.first_party`, which the
   loader sets from the package layout and never reads from YAML;
3. the action resolves to a **commissioned outcome on a resource the condition
   covers**, and that outcome is the protective one for this condition. A gas
   leak licenses `open_protected_circuit` on the zone carrying the valve. It
   does not license `close_protected_circuit` on that zone, and it licenses
   nothing on any other zone. This is the clause that stops a Tier D plan
   conferring its authority on whatever else it happens to name;
4. the action is named in that trigger's own `actions.defaults` list. The list
   **narrows and never grants**: it can only select from what clause 3 already
   licensed;
5. the action is not informational, by the registry test above;
6. the action has a registered executor. Without one there is no protective act
   for the authority to attach to. The dispatcher already reports this case at
   CRITICAL and marks the result failed, which is the one tier that reports an
   absent executor honestly today.

An action that fails clause 3 is not refused outright — it is dispatched at its
own authority under the third branch of the rule above, capped at C. Failing to
be the licensed protective act is not misconduct; it only means the safety
condition is not what authorises it.

**An ungoverned action is refused at admission**, with reason
`ungoverned_action`, rather than assigned a tier and left to fail at a missing
executor. `register_executor()` already refuses a name with no registry entry,
so such an action can never actuate; letting it travel as far as dispatch turns
a declaration error into a runtime one, and at Tier D that is the worst possible
place to discover it.

Nothing else confers Tier D. Not a signature, not an entitlement, not a remote
command, not a model. A signature proves who wrote a skill, not that the
runtime granted it autonomous safety authority, and an issuer that could grant
it would give safety an expiry and a revocation path.

### Clauses 1 and 2 are containment, and are the part that is temporary

They restrict which *author* may declare a Tier D trigger. That is not the same
as the runtime owning the decision, and it leaves the safety envelope a property
of which skills are installed, written as untyped numbers in manifest YAML.
`safety-profile/v1.md` is the end state: release-owned typed conditions bound to
a commissioned zone, with no deployment-supplied parameters at all, activated by
ratification. When the safety registry becomes the sole Tier D path, clauses 1
and 2 are replaced by a ratified profile and clause 3 becomes the whole of the
grant — which is why clause 3 is written in the vocabulary of zones and outcomes
rather than of skills.

Every packaged `action_tier: D` declaration is legacy against that contract, and
the evidence record already says so: `tier_d_legacy_skill` is the licensing
basis such an action is sealed under, and a verifier is required not to present
it as runtime-owned protection.

## Resource identity

A physical action is admitted against the resource it drives, never against its
name. Two names can be one act, and one name can be two acts on different zones.

**The resource and the outcome are separate fields**, and conflating them
defeats the purpose. If the outcome were part of the identity, opening and
closing a circuit would carry different identities and would never be seen to
conflict — which is the one collision the gate exists to catch.

```text
resource_key    = zone.identity_key            # what is being driven
desired_outcome = open_protected_circuit | close_protected_circuit
```

Contention is decided on `resource_key` alone. `desired_outcome` then decides
whether two admitted actions coalesce or conflict.

- Actions resolving through the commissioned actuator take the zone's
  `identity_key` as `resource_key`. `trip_relay` and `close_gas_valve` both
  resolve to `open_protected_circuit` and share a single executor, so on one
  zone they are the same act and coalesce. `release_relay` resolves to
  `close_protected_circuit`, the same `resource_key` with the opposite outcome,
  and conflicts.
- `coap_command` takes its configured URI as `resource_key` and its method and
  payload identity as the outcome.
- `terminate_process` and `reset_kernel_subsystem` take the resolved target as
  `resource_key`; their outcome is the action itself, so two of the same
  coalesce and there is no opposite to conflict with.
- Informational actions hold no resource and are never admitted against one.

A device carries at most one commissioned zone today, so the conflict domain is
currently small. The identity is defined per zone rather than per device so that
it stays correct when it is not.

## Admission

### The barrier comes before the gate

A lock on a resource is not enough to make Tier D preemptive. Plans are built
per skill, and one skill can have its reasoning scheduled before another skill
has even been evaluated — so a Tier A notice from skill X races a Tier D trip in
skill Y that nothing has discovered yet. A resource lock cannot fix that,
because at that moment the Tier D action does not exist to take it.

So admission has two phases, and the first is **event-wide**:

1. **Discovery barrier.** For one event, evaluate every registered skill
   exhaustively and assemble the full set of matched triggers across all of
   them, before any action is dispatched and before any reasoning task is
   scheduled. A Tier D match anywhere in that set is attempted before any
   reasoning task is scheduled anywhere in it, and forecloses lower-authority
   state changes **on the resources it licenses** — not on unrelated ones. The
   barrier exists so that a Tier D match is *known* before lower-tier work
   starts; the resource gate decides what that knowledge forecloses.
2. **Resource admission.** Then admit actions against the gate below.

Without phase 1, "Tier D is attempted first" is true only within a skill, which
is not what it claims and not what the decision tree promises.

### The gate

One runtime-global gate keyed by `resource_key`, shared across skills and
concurrent events, taken before any executor runs.

The gate holds an **in-flight record** per resource, not merely a lock:
the admitted `desired_outcome`, the dispatch tier, the contributing triggers,
and the state of the attempt. A bare mutex would let a later request wait for
release and then perform the same physical act a second time, which is the
opposite of coalescing.

### The five states a resource can be in

Contention is not one situation. Precedence depends on how far the holder has
got, and the distinction decides whether a physical act occurs, so the states
are enumerated rather than left to an implementer.

| Holder state | Same outcome arrives | Opposing outcome arrives |
|---|---|---|
| **Known at the barrier** — both in one discovery set, nothing admitted | admitted once, contributors merged | higher tier admitted; equal tiers both refused |
| **Reserved, not started** | joins the reservation | higher tier takes it, holder refused; equal tiers both refused |
| **Proposal awaiting approval** | Tier D invalidates and attempts; equal or lower tier joins the proposal | higher tier invalidates; equal or lower is refused |
| **Executor running** | joins the running attempt, takes its result | not interrupted. A Tier D arrival latches as `tripped`/`command_pending` and the registry retries it; any lower authority is **refused**, with a recorded reason |
| **Retired** | a new act | a new act |

Two rules fall out of that table and are easy to get wrong.

**Tier D never joins an unapproved proposal, even for the same outcome.** A
proposal is not an attempt. Joining one would make a safety trip wait for a
human, the exact inversion Tier D exists to prevent. Tier D invalidates the
proposal, refuses any late operator reply to it, and starts its own attempt.
Both the invalidation and the refused reply are recorded.

**"Refused entirely" applies only where refusal is still possible.** Equal-tier
opposing requests are both refused when both are known at the discovery barrier,
or when neither has started. Once one is reserved or running the gate cannot
retroactively un-perform it: the later arrival is refused against a holder that
stands, and the pair is recorded as a conflict resolved by timing rather than by
authority — which is a defect in the skill set and has to be visible as one.

### Joining is keyed on more than the outcome

A join makes one physical act stand for several contributors, so the key must
cover everything that would otherwise make them different acts: `resource_key`,
`desired_outcome`, the binding revision and actuator identity in force, and any
command parameter that materially changes what happens. A `coap_command` to one
URI with a different payload is not the same act.

Each contributor keeps its own authority and provenance in the record. Joining
merges execution, never licensing — and a Tier D trigger that joined a shared
attempt still degrades safety status if that attempt fails or is delayed. Its
obligation is not discharged by someone else's failure.

Coalescing spans the in-flight attempt only. Once the record retires, a later
request for the same outcome is a new act: a repeat trip after a repeat
condition is a real event and must not be silently absorbed.

**Two Tier D outcomes that oppose on one resource are an unresolved safety
conflict, not an ordinary refusal.** Nothing acts, so nothing is protected, and
that must be reported as its own condition and degrade safety status. Filing it
as a routine refusal would let a device that protects nothing look like a device
that made a decision.

**Preemption of a held resource.** A Tier D action arriving for a resource held
by a Tier C proposal takes it, as the table says. This is the only case in which
a held resource changes hands.

**An in-flight act that cannot be recalled.** If an opposing physical action has
begun and its executor has not returned, the arriving action does not interrupt
it — issuing opposite commands concurrently to one actuator is worse than
waiting.

**Below Tier D the arrival is refused**, not queued. A pended lower-authority
action would need its own persistence, expiry, re-licensing, approval validity
and restart semantics, and every one of those is a way for a stale intention to
actuate later against conditions nobody rechecked. Refusing it is recorded, and
the next event re-raises it against the state that actually obtains.

### A displaced Tier D action is not the gate's to retry

The obligation already has an owner, and it is not this gate. Under
`safety-profile/v1.md` the pair is **`tripped` with a command status of
`command_pending`**, and the safety registry keeps attempting the outcome on a
bounded-backoff schedule **with no terminal attempt limit, from a loop that does
not depend on sensor delivery**. That loop stops only when the driver reports
acceptance, a local reset succeeds, or the consumer shuts down.

So the rule here is a constraint on the gate, not a second retry mechanism:

- **The gate records and yields; the registry retries.** Displacement sets the
  pair `tripped` / `command_pending`. Building a retry loop in the dispatch path
  would duplicate the registry's and could diverge from it — two loops issuing
  the same physical command is the failure the resource gate exists to prevent.
- **The gate must never starve that loop.** No holder, and no admission rule
  here, may prevent the registry from re-attempting a latched trip. A resource
  reservation is not a licence to block a `tripped` pair indefinitely.
- **A deadline marks a breach; it never terminates.** Health may report that a
  pending command has exceeded its expected time, and that is a reportable
  condition. It is not permission to stop: the contract has no terminal attempt
  limit, and a deadline that stopped retrying would contradict it.
- **The obligation survives its own justification going stale.** It is not
  discharged because the originating reading aged, because cooldown was charged,
  or because a later evaluation of the condition returns false. Latched means
  latched.
- **Retry and reset are serialised.** Once a reset has licensed closing the
  circuit, no previously scheduled retry of that trip's open command may
  execute. The gate participates in that serialisation rather than defining its
  own.

### An executor that never returns

"Re-evaluate when the holder retires" is not a liveness guarantee, because a
holder can hang. The registry's retry loop is unaffected — it does not wait on
this gate — but the gate must not turn a hung executor into a pair of opposing
commands:

- **Every driver call carries its own timeout.** A call that does not return
  within it leaves the command **uncertain**: not `command_issued`, and not
  known to have failed.
- **An uncertain command is never treated as accepted, and never as refused.**
  Acceptance is what the driver reports, and silence is not a report. The status
  stays `command_pending`, which is exactly what keeps the registry retrying.
- **No opposing outcome is admitted on a resource with an uncertain command in
  flight.** This is the rule that stops a timeout becoming two contradictory
  commands to one actuator. The opposing arrival is refused, with the
  uncertainty as its recorded reason, however long the uncertainty lasts.
- **A resource whose command is uncertain is reported as such** — the health
  surface says the command was issued and its physical outcome is unverified,
  never that the outcome executed.

**Preempt** means Tier D is *evaluated and attempted before lower-authority
work*, across the whole discovery set rather than within one skill. It does not
mean it displaces everything: Tier A notices still run, actions on unrelated
resources still proceed, and an opposing act already running is not interrupted.
What it forecloses is a lower-tier state change on the same resource, and any
reasoning task being scheduled ahead of a Tier D attempt.

A Tier A informational action is never suppressed by a Tier D trip. It is the
operator's account of what happened, and it runs after the trip has been
attempted.

Every refusal, preemption, coalescing, invalidation and delay is recorded. A
dropped Tier C proposal that leaves no trace is indistinguishable from one that
was never raised.

## Cooldown

One owner: the plan builder. But "the plan was admitted" is not a fine enough
event to charge against, because a trigger can be admitted and still reach no
attempt, or reach an attempt someone else is already making. Consumption is
charged against the durable outcome the trigger actually reached:

| Outcome | Consumes | Why |
|---|---|---|
| `attempted` | yes | an executor ran, whatever it returned |
| `joined_attempt` | yes | the act happened and this trigger contributed to it |
| `proposal_opened` | yes | an operator was asked; asking again immediately is the noise cooldown exists to stop |
| `fully_refused` | no | nothing was attempted and nobody was asked |
| `preempted` | no | a higher authority took the resource; the trigger did not get its turn |
| `condition_false` | no | it never matched |

A trigger contributing several actions consumes once, on the strongest outcome
any of them reached, ordered `attempted` > `joined_attempt` > `proposal_opened` >
`preempted` > `fully_refused` > `condition_false`. `attempted` outranks
`proposal_opened` because something happened rather than was asked about; the
ordering is written down so two implementations cannot disagree about a trigger
that both acted and proposed. A trigger whose only actions were informational consumes on
`attempted` like any other — a notice that fired is a notice the operator
received.

This requires the rule engine to stop recording a fire while evaluating, and the
loader to stop recording one before the condition is known to match. Accounting
it in two places, on events that are not the trigger firing, is why a trigger
that lost — or never matched — currently spends its cooldown.

## The evidence record

This half is not the runtime's to choose, and it is constrained further than it
first appears. `runtime_action` is not an opaque payload: `evidence/v2.md` in
`ori-specs` specifies it, and **requires** an `authority` object on every one —
a discriminated union whose `kind` selects the remaining required fields, where
an unrecognised kind, a missing field, or a field belonging to another kind is a
rejection.

| `kind` | Required fields | Licensed by |
|---|---|---|
| `tier_c_approval` | `proposal_id` | an operator's scoped approval |
| `tier_d_profile` | `profile_id`, `zone_id`, `binding_seq` | a ratified safety profile |
| `tier_d_qualification` | `profile_id`, `zone_id`, `binding_seq`, `fixture_hash` | an open qualification session over a candidate |
| `tier_d_legacy_skill` | `skill_name`, `skill_version`, `trigger_name` | a first-party skill's `action_tier: D` declaration |

The last kind is named *legacy* deliberately, and the contract requires a
verifier not to present such a row as runtime-owned protection: it records that
a skill declaration fired, which is the authority model the safety registry
exists to replace. It is truthful about today and is not a protection claim.

Three consequences settle this half.

**`authority` names the licence, and that is not the same as naming the
incident.** `tier_d_legacy_skill` carries the skill, its version and the
trigger; `tier_c_approval` carries the proposal. That is enough to answer "what
authorised this action", which is the question a verifier must be able to
answer, and it is why this contract adds no parallel `incident_tier` field: a
second spelling of the licence would be a field no verifier is required to read
and a producer is free to disagree with.

It is **not** enough to carry incident provenance in full, and the contract
should not pretend otherwise:

- a coalesced action has several contributing triggers, and a single
  `trigger_name` names one of them;
- `tier_c_approval` identifies a proposal, not the condition that raised it;
- an incident that produced no state-changing action has no row at all, so its
  provenance has nowhere to live.

The first two need a normative contributor structure and the third needs an
incident record; both are `ori-specs` changes, and neither is in scope here.
What this contract requires is narrower and unblocked: emit `authority` as
already specified, and stop claiming the incident is fully represented until
those land.

**The runtime does not emit it.** `_action_payload` builds fourteen fields and
`authority` is not among them, so by the merged contract every Tier C/D row the
runtime has sealed is one whose licensing authority a verifier must treat as
unknown, must not present as a protection action, and must distinguish in a
finding from a row that declared one. That is not a gap this contract can
absorb — it is prior work this contract sits on, and it is tracked separately.

Nothing caught this, because the requirement is exercised by no vector: the
`evidence_v2` corpus carries two `runtime_action` payloads and neither has an
`authority` object, so the shape the amendment forbids is the one published as
the example. Raised against `ori-specs`.

**`trigger_name` therefore stops being cosmetic.** It is a required field of
`tier_d_legacy_skill`, and the nearest value the runtime holds is wrong: on the
evidence path the dispatcher assigns `context.event.sensor_id` while
`SkillContext` carries the real trigger name a few frames away. A producer
emitting the sensor id there is non-conforming on a required field rather than
merely imprecise.

The remaining runtime-side rule is unchanged by any of this: **seal on the
action's dispatch tier.** Only actions dispatched at C or D become
`SAFETY_ACTION_EXECUTED`, whatever incident accompanied them. Correlated
informational outcomes ride inside the sealed row of the physical action they
accompanied, so that "the operator was notified" survives without a WhatsApp
message being typed as a physical-authority event.

### The item that is not the runtime's alone

A Tier C or Tier D incident that produces **no** state-changing action seals
nothing under this contract. That is not a corner case: it describes every Tier
D trigger the runtime ships today, whose protective actions are either absent
from the registry or deliberately omitted until relay wiring has been verified.
Today such a plan does seal a row, because the notification inherits Tier D —
the record exists only by way of the defect this contract removes.

"Tier D fired and nothing protected" is close to the most important thing a
tamper-evident record can hold. But entering it means widening
`SAFETY_ACTION_EXECUTED` from "a physical action executed" to "a
physical-authority incident occurred", and that type is defined in
`evidence/v2.md`, not here. It would also need an `authority` kind of its own:
the four defined kinds all licence an action, and an incident that produced no
action was licensed by none of them.

So it is a contract change in `ori-specs` and it is out of scope for this
document. Until it is settled the runtime seals on the action, and the gap is
what this paragraph is for.

## What `executed` has to mean

An action row's `executed` must mean that an executor ran and reported success.
Below Tier D it does not.

When this contract was written, a registry entry with no executor — there were
three — dispatched at Tier C with the operator replying YES returned
`executed=True`, `approved=True`, and that row was sealed into the chain as a
signed attestation that a circuit was opened when nothing was driven. Tier D
alone reported it honestly.

Two things closed that. `executed` now means an executor ran and reported
success, at every tier. And the registry no longer holds a physical name with
nothing behind it: the three entries were retired rather than given executors,
because a physical capability is an outcome on a commissioned zone, not a name.
The names that remain are the legacy set `safety-profile/v1` carries as
normative vocabulary, each resolving to one protected-circuit outcome; new
physical capability arrives as an outcome defined in the specs and bound by
commissioning, never as a registry name.

Tracked separately. The contract depends on it, because sealing on the action
tier buys nothing if the field being sealed is not true.

## Out of scope

- Refusing overlapping trigger conditions at load. It enforces syntax rather
  than safety, and once matching is exhaustive,
  identical conditions at different tiers are the complementary design a shipped
  skill already intends. A load-time diagnostic that states plainly that it
  detects exact duplicates only is still worth having.
- The general capability grant binding skill identity, trigger, action and
  permitted maximum tier. It governs Tier A to C and must never be able to
  confer Tier D — an issuer that could grant Tier D gives autonomous safety
  authority an expiry, a revocation path and a party the runtime never
  reviewed. A grant is not a weaker form of the eventual model; it is
  permanently the wrong instrument for D, and it is specs work for the tiers
  below it.
- Community hook execution, which remains blocked.

## What has to be true before this is implemented

- Shipped triggers must name only actions the registry holds, first or in the
  same branch. An exhaustive matcher that reaches actions which cannot resolve
  is worse than one that never reaches them, because it reaches them at Tier D.
- The `executed` defect, for the reason above.
- The missing `authority` object. Sealing correctly on the action tier produces
  a conforming row only if the row conforms at all, and the incident this
  contract wants named is named there rather than in a field of its own.
- The widening question above, or an explicit decision to seal on the action
  and carry the gap. It does not block the rest.

## Test obligations

- `[A, D]` and `[D, A]` declaration orders produce identical outcomes, and
  tests permute declaration order rather than asserting one arrangement.
- A matching Tier D action is attempted before any Tier A reasoning begins.
- A matching Tier D suppresses matching Tier B and Tier C state changes on the
  same resource, and does not suppress the Tier A notice.
- A Tier C plan's notification is sent with no approval round trip.
- A Tier D plan's notification is not sealed as a Tier D action, and the trip
  in the same plan is.
- The sealed payload carries a conforming `authority` object, and its
  `tier_d_legacy_skill.trigger_name` names the trigger rather than the sensor.
- Two triggers resolving to one resource and outcome produce one executor call
  and a coalescing record.
- Opposing same-resource actions at equal tier are refused, and the refusal is
  recorded.
- A false condition consumes no cooldown; a preempted trigger consumes none; a
  failed executor consumes one.
- An action with no registered executor never reports `executed=True` at any
  tier.
- The `energy-anomaly-detector` 99 A reproduction reaches the Tier D attempt
  through the public runtime event path, not by driving a handler directly.
