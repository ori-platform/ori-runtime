# Measurement Supervision

What the runtime does when it cannot establish a trustworthy measurement, what
it deliberately does not do, and what would have to be true before it could do
more.

## The statement this document exists to make

**A device reporting a withheld measurement is not protecting that channel.**
That is by design, not a gap. A measurement the runtime cannot stand behind is
withheld rather than published, and a safety condition defined over a channel
with no measurement is not evaluated. The device stays up, reports the loss in
health and to the operator, and keeps reporting it — but the channel is
unprotected for as long as the condition lasts. It does not reach the evidence
chain; that gap is named below rather than glossed.

Nothing in this document restores protection. Escalation tells a person that a
channel is unprotected; it does not protect it. No text in the code, in an
operator message or in this file should ever say otherwise.

## This has no live safety effect yet

Every safety profile the release ships is a `candidate`, so no zone is bound to
an active runtime-owned pair, and a pair-scoped supervision rule binds to
nothing on any real device. It gains effect when profiles are ratified and the
Stage 5 cutover in #324 makes the safety registry the sole Tier D path.

Until then everything below improves operator awareness and nothing else. It is
stated here rather than inside the design, because it governs what any of this
can claim.

## What exists today

| Behaviour | Where |
|---|---|
| A window that cannot be shown to be a measurement is refused, and no reading is published | `ori/hal/ac_measurement.py`, `ori/hal/i2c_adapter.py` |
| Three consecutive refusals mark the sensor degraded; five consecutive good windows clear it | `MEASUREMENT_REFUSALS_BEFORE_DEGRADED`, `MEASUREMENT_WINDOWS_TO_RECOVER` |
| A chip found running a configuration this runtime did not set is quarantined for the life of the process | `_refuse_if_configuration_moved` |
| Health reports the degradation per sensor and in the aggregate `status` | `_build_health_snapshot` |
| Affected safety pairs are told their measurement is unavailable — **dormant**, since `note_sensor_unavailable` returns false while every profile is a candidate | the safety registry |
| A Tier A notice fires on the transition into degraded, then at 6 h, 12 h and daily, escalating to the secondary contact | `MEASUREMENT_REMINDER_AFTER_MS` and the constants beside it |

Recovery is deliberately slower than failure. A measurement path that
alternates is not trustworthy, and flapping between degraded and healthy
produces an alert stream operators learn to ignore.

The escalation has **no give-up**. A still-unprotected channel must not become
permanently silent, so nothing stops it on a message count or a delivery cost.
Two further stop conditions are sanctioned and neither is implemented: removal
of the affected safety pair, which belongs with the supervision design below,
and a locally audited maintenance acknowledgement with a short expiry, which
needs an inbound audited authority surface of its own.

## Two responses that are not adopted, and why

### A timed self-restart

Refused. A restart clears the quarantine and reconfigures the chip while the
competing writer may still be there, which is the configuration contest the
quarantine exists to avoid; losing it intermittently produces a plausible
number rather than a refusal, and an intermittent wrong reading is worse than
an outage because nothing about it looks wrong.

It also makes the process boundary meaningless. The quarantine is
process-scoped because a person is expected to intervene, and an automatic
restart turns that into a retry loop with extra steps.

And it is not scoped to the fault. Sensors are inputs; the protected thing is
the commissioned zone-and-profile pair. A restart taken to recover one sensor
removes protection for every other active pair on the device for its duration,
and a restart loop never restores it.

### Coupling watchdog feeding to measurement health

Refused. Withholding the feed does not report a problem — it resets the
controller. `docs/evidence/2026-09-01-pi4-gpio-controller-loss.md` measured that
a reset clears the driving pad and de-energises the coil, and states explicitly
that a genuine watchdog reset was not among the conditions tested. What
de-energising does to the protected circuit is commissioned per channel, and
for a zone whose mapping makes `de_energised` the closed state, a watchdog
reset **reconnects the load** at the exact moment the runtime cannot measure
whether that is safe.

## The connect-time contention case

A configuration mismatch found at `connect()` is refused and the sensor is
skipped; it is **not** quarantined, the way the same mismatch found during a
measurement is. That asymmetry is stated here because any later recovery design
has to say what it does with it rather than assume the quarantine settled it.

Three facts decide it, and two of them cut against the intuitive reading:

- **A connect-time mismatch is the weaker evidence of a competing writer, not
  the stronger one.** The readback after connect is also what identifies the
  part: `_select_ads1115_channel_single_shot` says so directly — a device whose
  word happens to carry the conversion-complete bit gets past the wait, "and the
  configuration readback that follows is what refuses it". So a mismatch there
  is ambiguous between a device at that address that is not an ADS1115, a driver
  that does not honour the pin, a write that silently failed, and a competing
  writer. A *measurement*-time mismatch has the first three excluded already,
  because connect proved this chip ran this adapter's exact configuration word.
  Timing precision is not evidential specificity.
- **A connect-time mismatch latches the chip, not the sensor.** It did not
  until recently, and the difference mattered: the quarantine is keyed
  `(bus, address)` and refuses every later adapter, while the sensor skip
  records an id in `_unconnected_sensors` and protects nothing about the chip.
  The bus claim is released on a failed connect, and `ori.yaml` checks sensor
  ids for uniqueness rather than addresses, so a configuration naming two
  `ads1115_current` sensors at one address had the second adapter configuring a
  chip the first had just refused. The ambiguity above is what makes latching on
  it correct rather than merely convenient: a device that is not an ADS1115
  should not be driven, a write that did not take means the chip is not
  accepting configuration, and a competing writer is the case the quarantine was
  built for — every reading of the fault justifies refusing the chip.
- **A readback that could not be performed still does not latch.** A bus failure
  mid-readback is evidence of nothing: not a competing writer, not a wrong part,
  not a failed write. It refuses that connect and quarantines no chip, which is
  the same line the measurement path draws.
- **Retrying would be the writing contest.** Any design that reconnects on a
  schedule turns a connect-time mismatch into repeated writes to a chip
  something else may also be writing. That is the failure mode the quarantine
  exists to prevent, reintroduced at a different layer.

**What a recovery or reconnect design must therefore state**, explicitly, before
it is built:

1. How it tells a competing writer apart from a wrong or misbehaving part,
   given that the connect-time readback cannot, and that the wrong part is the
   likelier of the two.
2. What clears the latch. It is process-scoped today, so a restart clears it
   whether or not the cause is gone — which is deliberate while a person is
   expected to intervene, and is a decision a reconnect design revisits rather
   than inherits.
3. What it does about every *other* active pair on the device while a reconnect
   is in progress, since a reconnect writes a shared bus.

## The supervision mechanism — what exists, and what is missing

Pair-scoped supervision is **implemented and dormant**, not absent. It is easy
to conclude otherwise, because it cannot fire on any shipped device, so this
section says what is there before saying what is not.

`SafetyRegistry.watch_measurement_loss` runs per pair from the retry loop. A
pair with no credible reading for longer than its bound — five poll intervals,
never sooner than the floor — is degraded, alerted under suppression, and holds
its trip state, because v1 never opens a circuit on loss. The pair-scoped health
view exists too: `measurement_degraded` and `last_credible_at_ms` per pair in
the registry's snapshot, and `measurement_degraded` on each entry of
`safety_zones` in `runtime-health/v2`.

**What is genuinely missing**, and what an implementer at the Stage 5 cutover
would still have to decide:

- *Sensor attribution on the pair entry.* The registry holds `entry.sensor_id`
  and does not emit it, so a reader sees that a pair's measurement is degraded
  and cannot see which input is responsible.
- *Duration.* `last_credible_at_ms` is a timestamp a reader must difference
  against a clock it does not have; how long the pair has been unsupervised is
  the field an operator acts on.
- *Evidence records.* Nothing under `ori/security/evidence/` refers to
  measurement at all. Entry and exit of the unsupervised state, with the sensor,
  the pair, the reason and the notices issued, belongs in the chain: a channel
  that was unprotected for six hours is a fact about a commissioned undertaking,
  not only a log line. This half is undesigned — the record type, its position
  in the chain and its clearing semantics are all open.
- *Whether the loss-watch bound is the supervision trigger or a separate one.*
  Five poll intervals is a bound chosen for the trip state; it is not obviously
  the right threshold for telling an operator a channel is unsupervised.

**Dependence.** None of this binds until the Stage 5 cutover in #324, because
every shipped profile is a `candidate` and the registry holds no active pair.
The gaps are recorded now so the cutover does not arrive with them undiscovered,
and #565 is where the work lands.

**What it must not do.** Invent physical authority. It observes, reports and
notifies. It does not actuate, does not select a safe state, and does not decide
that a pair should be removed — removal is an operator act with its own
authority, which is why the escalation schedule names it as a sanctioned stop
condition rather than performing it.

## When a reset-based response could ever be enabled

Not on the strength of any argument available today. Each of the following is a
separate prerequisite, and all of them are necessary:

1. **Platform qualification of what a reset does to the actuator.**
   `docs/evidence/2026-09-01-pi4-gpio-controller-loss.md` covers power loss, a
   process killed outright, a controlled stop, and a `sysrq-b` reset. A genuine
   watchdog expiry was not induced, and is not implied by the `sysrq-b` result.
   Required evidence: the measured pad and coil state through a real watchdog
   reset to a cleared pad, per board.
2. **Commissioning evidence of what that actuator state does to the site
   circuit.** De-energised is not a synonym for safe; the protected circuit's
   behaviour is established per channel at commissioning by observing it.
   Required evidence: the zone's recorded terminal state for the coil state a
   reset produces.
3. **A hardware-in-the-loop proof, through the qualification fixture.** Not a
   host test and not a bench improvisation — the fixture exists so that a
   result like this is evidence toward ratification rather than a protection
   claim someone made on a bench.
4. **A measured statement of what happens to every other active pair on the
   device during the reset**, since a reset is device-scoped and protection is
   pair-scoped. Required evidence: the protection state of every other active
   pair through the same reset, observed rather than reasoned about.
5. **An answer to the three objections raised against the timed self-restart
   above**, because a reset is a superset of a restart and every one of them
   carries: it clears the quarantine into a possible writing contest, it turns a
   process boundary a person was expected to cross into an automatic loop, and
   it removes protection for every other pair for its duration. Satisfying the
   first four and ignoring these builds a reset loop that contests the bus.

Absent all four, a reset is a device taking a physical action, at the moment it
has established that it cannot measure, on the basis of an assumption about
what that action does. That is the shape of decision the Action Tier Framework
exists to prevent.

## The shape of the real answer

Protection that survives a controller which cannot establish trustworthy
measurement is not a matter of restarting the controller harder. It is an
independent, qualified interlock that can act when the runtime cannot — which
this estate already has a place for as the firmware orphan-mode backstop,
rather than something to invent here.

Independent means independent of the failed measurement path itself: a
qualified firmware or hardware interlock, not a second retry loop inside the
same runtime that has just failed to establish what it is measuring.

A runtime staying up was never what made a device protected, and no amount of
process churn makes an unmeasurable channel safe.
