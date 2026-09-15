// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

//! Bounded telemetry delivery that outlives a failed upload.
//!
//! `runtime-telemetry/v2` requires that a transport failure never end a
//! producer: the payload keeps reading its meter, retains what it could not
//! deliver within a bounded queue, retries with backoff, and reports what it
//! had to drop. Only a recorded terminal refusal stops export, and even that
//! leaves the process running.
//!
//! A batch is retained **as a batch**. Pushing its events back onto the queue
//! is what let a retry merge newer readings in under a new sequence, which a
//! receiver keying on the batch discarded whole.

use serde_json::Value as JsonValue;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::delivery::{DeliveryOutcome, DeliveryVerdict, TERMINAL_REFUSAL_DETAIL};

/// The shortest wait after a failed attempt. Below a second a phone that has
/// lost its network spins its radio for nothing.
pub const BACKOFF_FLOOR: Duration = Duration::from_secs(1);
/// The longest wait. A device offline for hours must not take hours to notice
/// that it is back.
pub const BACKOFF_CEILING: Duration = Duration::from_secs(300);
/// Answers from the receiver's application that did not confirm a batch,
/// after which it is abandoned and counted. Enough to ride out a receiver
/// mid-deploy answering inconsistently; few enough that one batch a receiver
/// will never confirm cannot hold the head of the queue for good. The Python
/// exporter holds the same number.
pub const MAX_UNCONFIRMED_ATTEMPTS: u32 = 5;

/// A batch and the identity it keeps across every attempt.
#[derive(Debug, Clone)]
pub struct PendingBatch {
    pub sequence: u64,
    pub events: Vec<JsonValue>,
    /// Attempts the receiver's application answered without confirming.
    pub unconfirmed_attempts: u32,
}

/// What the payload is holding and what it has lost. Reported, not just logged.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportCounters {
    /// Events discarded because in-memory telemetry was full.
    pub dropped_events: usize,
    /// Events the receiver reported as rejected. Permanently refused.
    pub declined_events: usize,
    /// Events the receiver reported it already held. Delivered, not lost.
    pub duplicate_events: usize,
    /// Events discarded because a terminal refusal suspended export.
    pub refused_events: usize,
    /// Events the receiver confirmed it holds.
    pub delivered_events: usize,
    /// Events abandoned after the receiver answered, repeatedly, without
    /// accounting for them. Never counted as delivered.
    pub unconfirmed_events: usize,
    /// Answers that were 2xx and could not be read.
    pub unreadable_responses: usize,
    /// Answers missing a response member the contract requires.
    pub nonconformant_responses: usize,
}

/// One attempt's result, as the caller needs to see it.
#[derive(Debug, PartialEq, Eq)]
pub enum FlushOutcome {
    /// Nothing was pending.
    Idle,
    /// Every pending batch is now held by the receiver.
    Drained,
    /// At least one batch was not confirmed and is retained.
    Retained,
    /// Export is suspended for this credential.
    Suspended,
}

pub struct Exporter {
    batch_size: usize,
    max_queue_size: usize,
    queue: VecDeque<JsonValue>,
    retained: VecDeque<PendingBatch>,
    retained_events: usize,
    sequence: u64,
    counters: ExportCounters,
    suspended: bool,
    backoff: Duration,
    next_attempt: Option<Instant>,
}

impl Exporter {
    pub fn new(batch_size: usize, max_queue_size: usize) -> Self {
        Self {
            batch_size,
            max_queue_size,
            queue: VecDeque::new(),
            retained: VecDeque::new(),
            retained_events: 0,
            sequence: 0,
            counters: ExportCounters::default(),
            suspended: false,
            backoff: BACKOFF_FLOOR,
            next_attempt: None,
        }
    }

    pub fn counters(&self) -> &ExportCounters {
        &self.counters
    }

    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    pub fn queued_events(&self) -> usize {
        self.queue.len()
    }

    pub fn retained_events(&self) -> usize {
        self.retained_events
    }

    /// Events held in memory, queued and retained together.
    fn in_memory_events(&self) -> usize {
        self.queue.len() + self.retained_events
    }

    /// Take one reading. Overflow discards the newest, per the contract.
    ///
    /// The newest is dropped rather than the oldest retained batch because a
    /// retained batch is already a delivery the receiver has not confirmed, and
    /// discarding it would lose the only record of an interval.
    pub fn enqueue(&mut self, event: JsonValue) {
        if self.suspended {
            self.counters.refused_events += 1;
            return;
        }
        if self.in_memory_events() >= self.max_queue_size {
            self.counters.dropped_events += 1;
            eprintln!(
                "[ori-runtime-mobile] in-memory telemetry is full; dropped a reading. \
                 queued={} retained={} dropped_total={}",
                self.queue.len(),
                self.retained_events,
                self.counters.dropped_events
            );
            return;
        }
        self.queue.push_back(event);
    }

    /// Whether an attempt is due. Backoff is a floor on retries, never on the
    /// meter: reading continues whatever the network is doing.
    pub fn attempt_due(&self, now: Instant) -> bool {
        match self.next_attempt {
            None => true,
            Some(at) => now >= at,
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.queue.is_empty() || !self.retained.is_empty()
    }

    /// Retained batches oldest first, then at most one newly formed batch.
    fn take_pending(&mut self) -> Vec<PendingBatch> {
        let mut pending: Vec<PendingBatch> = self.retained.drain(..).collect();
        self.retained_events = 0;

        let take = self.batch_size.min(self.queue.len());
        if take > 0 {
            let events: Vec<JsonValue> = self.queue.drain(..take).collect();
            self.sequence += 1;
            pending.push(PendingBatch {
                sequence: self.sequence,
                events,
                unconfirmed_attempts: 0,
            });
        }
        pending
    }

    /// Hold batches for a later attempt, oldest first, within the bound.
    fn retain(&mut self, batches: Vec<PendingBatch>) {
        for batch in batches.into_iter().rev() {
            self.retained_events += batch.events.len();
            self.retained.push_front(batch);
        }
        // A backstop, not the overflow policy. Everything retained here was
        // counted against the bound when `enqueue` admitted it, and `flush` runs
        // to completion before `enqueue` can admit more, so this loop cannot run
        // while that admission rule holds. It stays so the bound fails closed on
        // its own if that ever changes, dropping the newest retained batch to
        // match the policy that does run: `enqueue` keeps what is already held
        // and refuses the new reading.
        while self.in_memory_events() > self.max_queue_size {
            let Some(stale) = self.retained.pop_back() else {
                break;
            };
            self.retained_events -= stale.events.len();
            self.counters.dropped_events += stale.events.len();
            eprintln!(
                "[ori-runtime-mobile] in-memory telemetry is full; dropped retained \
                 batch sequence={} events={} dropped_total={}",
                stale.sequence,
                stale.events.len(),
                self.counters.dropped_events
            );
        }
    }

    /// Nothing survives a suspension, retained batches included.
    ///
    /// A retained batch would otherwise sit through the suspension and be sent
    /// the moment a new credential resumed export, delivering readings under a
    /// credential that never sent them and past the interval they describe.
    fn discard_everything_as_refused(&mut self) {
        while let Some(batch) = self.retained.pop_front() {
            self.retained_events -= batch.events.len();
            self.counters.refused_events += batch.events.len();
        }
        self.counters.refused_events += self.queue.len();
        self.queue.clear();
    }

    fn succeeded(&mut self) {
        self.backoff = BACKOFF_FLOOR;
        self.next_attempt = None;
    }

    fn failed(&mut self, now: Instant) {
        self.next_attempt = Some(now + self.backoff);
        self.backoff = (self.backoff * 2).min(BACKOFF_CEILING);
    }

    /// Send what is pending, using `send` for each batch.
    ///
    /// `send` returns a verdict for every answer the endpoint gives, and `None`
    /// when this payload cannot send the batch at all -- a batch it cannot
    /// represent will not become representable on a later attempt, so retrying
    /// it is a loop with no exit. That is this payload's own loss and is counted
    /// as dropped rather than as anything the receiver said.
    ///
    /// No path through this function can end the process. The caller supplies
    /// `send` so the transport stays out of this module and out of its tests.
    pub fn flush<F>(&mut self, now: Instant, mut send: F) -> FlushOutcome
    where
        F: FnMut(&PendingBatch) -> Option<DeliveryVerdict>,
    {
        if self.suspended {
            self.discard_everything_as_refused();
            return FlushOutcome::Suspended;
        }
        let mut pending = self.take_pending();
        if pending.is_empty() {
            return FlushOutcome::Idle;
        }

        for index in 0..pending.len() {
            let batch = &pending[index];
            let Some(verdict) = send(batch) else {
                self.counters.dropped_events += batch.events.len();
                eprintln!(
                    "[ori-runtime-mobile] batch sequence={} cannot be sent and is \
                     discarded; dropped_total={}",
                    batch.sequence, self.counters.dropped_events
                );
                continue;
            };
            match verdict.outcome {
                DeliveryOutcome::Suspend => {
                    // The remaining batches are not attempted: the credential
                    // they would present is the one that was refused.
                    // The verdict counts this batch; the rest are refused
                    // without being attempted, because the credential they
                    // would present is the one that was refused.
                    let refused: usize = verdict.refused_events
                        + pending[index + 1..]
                            .iter()
                            .map(|item| item.events.len())
                            .sum::<usize>();
                    self.suspended = true;
                    self.counters.refused_events += refused;
                    // Everything still held is counted as refused rather than
                    // cleared. Clearing the queue without counting it lost
                    // readings the report was still naming as queued, and under
                    // `--once` the process ended before anything noticed.
                    self.discard_everything_as_refused();
                    eprintln!(
                        "[ori-runtime-mobile] endpoint refused this device ({TERMINAL_REFUSAL_DETAIL}); \
                         telemetry export suspended until the credential changes or the payload \
                         restarts. Reading the meter continues. refused_total={}",
                        self.counters.refused_events
                    );
                    self.failed(now);
                    return FlushOutcome::Suspended;
                }
                DeliveryOutcome::Retain => {
                    if verdict.body_unreadable {
                        self.counters.unreadable_responses += 1;
                    }
                    if verdict.receiver_answered {
                        let batch = &mut pending[index];
                        batch.unconfirmed_attempts += 1;
                        if batch.unconfirmed_attempts >= MAX_UNCONFIRMED_ATTEMPTS {
                            // The receiver's own answer, repeated, does not
                            // account for this batch and will not start to.
                            // Abandoning it lets newer readings through, and
                            // against a receiver still keying batches on
                            // `sequence` bounds a restart's loss to what that
                            // receiver discards anyway, counted, rather than
                            // making it permanent.
                            self.counters.unconfirmed_events += batch.events.len();
                            eprintln!(
                                "[ori-runtime-mobile] batch sequence={} abandoned after {} \
                                 answers that did not confirm it ({}); unconfirmed_total={}",
                                batch.sequence,
                                batch.unconfirmed_attempts,
                                verdict.reason,
                                self.counters.unconfirmed_events
                            );
                            continue;
                        }
                    }
                    let batch = &pending[index];
                    eprintln!(
                        "[ori-runtime-mobile] batch sequence={} not confirmed ({}); retained",
                        batch.sequence, verdict.reason
                    );
                    // Stop here rather than trying the rest. Retained batches
                    // go ahead of newer ones in the order first attempted, and
                    // sending a later batch now would break that order for no
                    // gain against an endpoint that has just failed.
                    let remaining = pending[index..].to_vec();
                    self.retain(remaining);
                    self.failed(now);
                    return FlushOutcome::Retained;
                }
                DeliveryOutcome::Delivered => {
                    self.counters.duplicate_events += verdict.duplicate_events;
                    if verdict.declined_events > 0 {
                        self.counters.declined_events += verdict.declined_events;
                        eprintln!(
                            "[ori-runtime-mobile] receiver declined {} of {} events in \
                             sequence={}; they are not retried",
                            verdict.declined_events,
                            batch.events.len(),
                            batch.sequence
                        );
                    }
                    if verdict.nonconformant_body {
                        self.counters.nonconformant_responses += 1;
                    }
                    self.counters.delivered_events += batch.events.len() - verdict.declined_events;
                }
            }
        }
        self.succeeded();
        FlushOutcome::Drained
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(value: u64) -> JsonValue {
        json!({"event_id": format!("event-{value}"), "value": value})
    }

    fn delivered() -> DeliveryVerdict {
        DeliveryVerdict {
            outcome: DeliveryOutcome::Delivered,
            declined_events: 0,
            duplicate_events: 0,
            refused_events: 0,
            nonconformant_body: false,
            body_unreadable: false,
            receiver_answered: false,
            reason: "accepted".into(),
        }
    }

    fn retain() -> DeliveryVerdict {
        DeliveryVerdict {
            outcome: DeliveryOutcome::Retain,
            declined_events: 0,
            duplicate_events: 0,
            refused_events: 0,
            nonconformant_body: false,
            body_unreadable: false,
            receiver_answered: false,
            reason: "HTTP 503".into(),
        }
    }

    fn suspend(events: usize) -> DeliveryVerdict {
        DeliveryVerdict {
            outcome: DeliveryOutcome::Suspend,
            declined_events: 0,
            duplicate_events: 0,
            refused_events: events,
            nonconformant_body: false,
            body_unreadable: false,
            receiver_answered: false,
            reason: "terminal refusal HTTP 403".into(),
        }
    }

    #[test]
    fn a_failed_upload_retains_the_batch_and_never_reports_delivery() {
        // The defect: the first failed POST ended the process and lost the batch.
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));

        let outcome = exporter.flush(Instant::now(), |_| Some(retain()));

        assert_eq!(outcome, FlushOutcome::Retained);
        assert_eq!(exporter.retained_events(), 1);
        assert_eq!(exporter.counters().delivered_events, 0);
        assert_eq!(exporter.counters().dropped_events, 0);
    }

    #[test]
    fn a_retried_batch_keeps_its_sequence_and_its_events() {
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        exporter.flush(Instant::now(), |_| Some(retain()));

        // A reading taken while the batch was undelivered.
        exporter.enqueue(event(2));

        let mut seen: Vec<(u64, Vec<String>)> = Vec::new();
        exporter.flush(Instant::now(), |batch| {
            seen.push((
                batch.sequence,
                batch
                    .events
                    .iter()
                    .map(|e| e["event_id"].as_str().unwrap().to_string())
                    .collect(),
            ));
            Some(delivered())
        });

        assert_eq!(seen[0].0, 1, "the retry reused its own sequence");
        assert_eq!(seen[0].1, vec!["event-1".to_string()]);
        assert_eq!(
            seen[1].0, 2,
            "the newer reading went under its own sequence"
        );
        assert_eq!(seen[1].1, vec!["event-2".to_string()]);
    }

    #[test]
    fn retained_batches_go_ahead_of_newer_ones_in_attempt_order() {
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        exporter.flush(Instant::now(), |_| Some(retain()));
        exporter.enqueue(event(2));
        exporter.flush(Instant::now(), |_| Some(retain()));

        let mut order: Vec<u64> = Vec::new();
        exporter.flush(Instant::now(), |batch| {
            order.push(batch.sequence);
            Some(delivered())
        });

        assert_eq!(order, vec![1, 2]);
    }

    #[test]
    fn retention_and_the_queue_share_the_configured_bound() {
        let mut exporter = Exporter::new(1, 2);
        for value in 1..=6 {
            exporter.enqueue(event(value));
            exporter.flush(Instant::now(), |_| Some(retain()));
        }
        assert!(exporter.queued_events() + exporter.retained_events() <= 2);
        assert!(exporter.counters().dropped_events > 0);
    }

    #[test]
    fn backoff_grows_from_the_floor_and_stops_at_the_ceiling() {
        let mut exporter = Exporter::new(1, 100);
        let start = Instant::now();
        let mut waits: Vec<Duration> = Vec::new();
        for _ in 0..12 {
            exporter.enqueue(event(1));
            exporter.flush(start, |_| Some(retain()));
            waits.push(exporter.next_attempt.unwrap() - start);
        }
        assert_eq!(waits[0], BACKOFF_FLOOR);
        assert!(waits[1] > waits[0], "the wait grows after a second failure");
        assert!(
            waits.iter().all(|wait| *wait <= BACKOFF_CEILING),
            "no wait exceeds the ceiling"
        );
        assert_eq!(*waits.last().unwrap(), BACKOFF_CEILING);
    }

    #[test]
    fn a_success_resets_the_backoff() {
        let mut exporter = Exporter::new(1, 100);
        exporter.enqueue(event(1));
        exporter.flush(Instant::now(), |_| Some(retain()));
        assert!(exporter.next_attempt.is_some());

        exporter.flush(Instant::now(), |_| Some(delivered()));

        assert!(exporter.next_attempt.is_none(), "a success clears the wait");
        assert!(exporter.attempt_due(Instant::now()));
    }

    #[test]
    fn backoff_delays_the_next_attempt_but_not_the_meter() {
        let mut exporter = Exporter::new(1, 100);
        let start = Instant::now();
        exporter.enqueue(event(1));
        exporter.flush(start, |_| Some(retain()));

        assert!(!exporter.attempt_due(start), "the retry waits");
        assert!(exporter.attempt_due(start + BACKOFF_FLOOR));

        // Reading continues regardless: enqueue is never gated on the backoff.
        exporter.enqueue(event(2));
        assert_eq!(exporter.queued_events(), 1);
    }

    #[test]
    fn a_terminal_refusal_suspends_export_and_discards_what_is_held() {
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        exporter.flush(Instant::now(), |_| Some(retain()));
        assert_eq!(exporter.retained_events(), 1);

        exporter.enqueue(event(2));
        let outcome = exporter.flush(Instant::now(), |batch| Some(suspend(batch.events.len())));

        assert_eq!(outcome, FlushOutcome::Suspended);
        assert!(exporter.is_suspended());
        assert_eq!(exporter.retained_events(), 0);
        assert_eq!(exporter.queued_events(), 0);
        // Exact, not a lower bound: this is the number that tells an operator
        // how much a suspended credential cost, and `>=` on a counter asserts
        // something weaker than the counter's name.
        assert_eq!(
            exporter.counters().refused_events,
            2,
            "the refused batch and the one behind it that was never attempted"
        );
        assert_eq!(
            exporter.counters().declined_events,
            0,
            "a refusal is not a decline"
        );
    }

    #[test]
    fn a_suspension_refuses_the_batches_it_never_attempted() {
        // Two batches pending, the first refused. The second is not sent --
        // the credential it would present is the one refused -- and its events
        // are counted, not silently dropped.
        let mut exporter = Exporter::new(1, 20);
        exporter.enqueue(event(1));
        exporter.flush(Instant::now(), |_| Some(retain()));
        exporter.enqueue(event(2));
        exporter.flush(Instant::now(), |_| Some(retain()));
        assert_eq!(exporter.retained_events(), 2);

        let mut attempts = 0;
        exporter.flush(Instant::now(), |batch| {
            attempts += 1;
            Some(suspend(batch.events.len()))
        });

        assert_eq!(attempts, 1, "the second batch was never attempted");
        assert_eq!(exporter.counters().refused_events, 2);
        assert_eq!(exporter.counters().dropped_events, 0);
    }

    #[test]
    fn a_suspension_clears_a_queue_that_take_pending_did_not_drain() {
        // With a batch size below the queue length, `take_pending` leaves
        // readings behind. They must be refused at the suspension rather than
        // surviving it: under `--once` the process ends first and they would
        // vanish uncounted while the report still named them as queued.
        let mut exporter = Exporter::new(1, 20);
        for value in 1..=5 {
            exporter.enqueue(event(value));
        }
        assert_eq!(exporter.queued_events(), 5);

        exporter.flush(Instant::now(), |batch| Some(suspend(batch.events.len())));

        assert!(exporter.is_suspended());
        assert_eq!(
            exporter.queued_events(),
            0,
            "nothing survives the suspension"
        );
        assert_eq!(exporter.retained_events(), 0);
        assert_eq!(
            exporter.counters().refused_events,
            5,
            "every held reading is counted as refused, not lost"
        );
    }

    #[test]
    fn enqueue_refuses_a_reading_once_the_bound_is_reached() {
        // The bound at the enqueue point, pinned on its own. It and the bound
        // inside `retain` were each satisfied only by the other's presence, so
        // neither was individually held by any test.
        let mut exporter = Exporter::new(10, 3);
        for value in 1..=6 {
            exporter.enqueue(event(value));
        }
        assert_eq!(exporter.queued_events(), 3, "the queue stops at the bound");
        assert_eq!(exporter.counters().dropped_events, 3);
    }

    #[test]
    fn a_full_bound_keeps_the_oldest_retained_batches_and_refuses_new_readings() {
        // The overflow policy that actually runs. With the bound full of
        // retained batches, `enqueue` refuses each new reading; the batches
        // already held, which record the start of the outage, are kept.
        let mut exporter = Exporter::new(1, 2);
        for value in 1..=4 {
            exporter.enqueue(event(value));
            exporter.flush(Instant::now(), |_| Some(retain()));
        }

        assert!(exporter.retained_events() <= 2);
        let kept: Vec<u64> = exporter.retained.iter().map(|b| b.sequence).collect();
        assert_eq!(
            kept,
            vec![1, 2],
            "the oldest retained batches are the ones kept"
        );
        assert!(exporter.counters().dropped_events > 0);
    }

    #[test]
    fn a_suspended_exporter_still_counts_readings_it_refuses() {
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        exporter.flush(Instant::now(), |batch| Some(suspend(batch.events.len())));

        exporter.enqueue(event(2));
        exporter.enqueue(event(3));

        assert_eq!(
            exporter.queued_events(),
            0,
            "nothing queues while suspended"
        );
        assert_eq!(exporter.counters().refused_events, 3);
    }

    #[test]
    fn a_batch_that_cannot_be_sent_is_dropped_not_retried() {
        // An unrepresentable batch will not become representable, so retrying
        // it is a loop with no exit. It is this payload's loss, not a decline.
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));

        let outcome = exporter.flush(Instant::now(), |_| None);

        assert_eq!(outcome, FlushOutcome::Drained);
        assert_eq!(exporter.retained_events(), 0);
        assert_eq!(exporter.counters().dropped_events, 1);
        assert_eq!(exporter.counters().declined_events, 0);
        assert_eq!(exporter.counters().delivered_events, 0);
    }

    fn answered_but_unconfirmed() -> DeliveryVerdict {
        DeliveryVerdict {
            outcome: DeliveryOutcome::Retain,
            declined_events: 0,
            duplicate_events: 0,
            refused_events: 0,
            nonconformant_body: false,
            body_unreadable: false,
            receiver_answered: true,
            reason: "response counts do not account for the batch".into(),
        }
    }

    #[test]
    fn a_batch_the_receiver_keeps_answering_without_confirming_is_abandoned() {
        // The answer a receiver still keying batches on `sequence` gives after a
        // restart. Bounded, counted, and the next batch goes through.
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        for _ in 0..MAX_UNCONFIRMED_ATTEMPTS - 1 {
            exporter.flush(Instant::now(), |_| Some(answered_but_unconfirmed()));
            assert_eq!(
                exporter.retained_events(),
                1,
                "retained while attempts remain"
            );
        }

        exporter.enqueue(event(2));
        let mut sent: Vec<u64> = Vec::new();
        exporter.flush(Instant::now(), |batch| {
            sent.push(batch.sequence);
            if batch.sequence == 1 {
                Some(answered_but_unconfirmed())
            } else {
                Some(delivered())
            }
        });

        assert_eq!(sent, vec![1, 2], "the newer batch went through behind it");
        assert_eq!(exporter.counters().unconfirmed_events, 1);
        assert_eq!(exporter.counters().delivered_events, 1);
        assert_eq!(
            exporter.counters().dropped_events,
            0,
            "abandonment is not overflow"
        );
        assert_eq!(exporter.retained_events(), 0);
    }

    #[test]
    fn the_attempt_bound_is_the_fifth_unconfirmed_answer() {
        // The contract fixes the number, so two producers count the same loss.
        assert_eq!(MAX_UNCONFIRMED_ATTEMPTS, 5);
    }

    #[test]
    fn a_transport_failure_between_unconfirmed_answers_does_not_reset_them() {
        // Resetting on every failed POST would hold a batch an unmigrated
        // receiver never confirms for as long as one attempt in two fails.
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        for round in 0..8 {
            let verdict = if round % 2 == 0 {
                answered_but_unconfirmed()
            } else {
                retain()
            };
            exporter.flush(Instant::now(), |_| Some(verdict.clone()));
            assert_eq!(exporter.retained_events(), 1, "round {round}");
        }
        exporter.flush(Instant::now(), |_| Some(answered_but_unconfirmed()));
        assert_eq!(
            exporter.counters().unconfirmed_events,
            1,
            "abandoned on the fifth"
        );
        assert_eq!(exporter.retained_events(), 0);
    }

    #[test]
    fn each_batch_counts_its_own_unconfirmed_answers() {
        // The batch behind an abandoned one is attempted in the same flush, and
        // that answer counts: it starts at one, not zero and not five.
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        for _ in 0..4 {
            exporter.flush(Instant::now(), |_| Some(answered_but_unconfirmed()));
        }
        exporter.enqueue(event(2));
        let mut attempts = 0;
        exporter.flush(Instant::now(), |_| {
            attempts += 1;
            Some(answered_but_unconfirmed())
        });
        assert_eq!(attempts, 2, "both batches were attempted");
        assert_eq!(exporter.counters().unconfirmed_events, 1);
        assert_eq!(exporter.retained_events(), 1);

        for _ in 0..3 {
            exporter.flush(Instant::now(), |_| Some(answered_but_unconfirmed()));
            assert_eq!(exporter.counters().unconfirmed_events, 1);
        }
        exporter.flush(Instant::now(), |_| Some(answered_but_unconfirmed()));
        assert_eq!(
            exporter.counters().unconfirmed_events,
            2,
            "its own fifth answer"
        );
    }

    #[test]
    fn an_unreadable_answer_never_abandons_a_batch() {
        // A captive portal's 200 is not the receiver speaking, so it is retried.
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        let unreadable = || DeliveryVerdict {
            body_unreadable: true,
            ..retain()
        };
        for _ in 0..MAX_UNCONFIRMED_ATTEMPTS * 2 {
            exporter.flush(Instant::now(), |_| Some(unreadable()));
        }
        assert_eq!(exporter.counters().unconfirmed_events, 0);
        assert_eq!(exporter.retained_events(), 1);
        assert_eq!(
            exporter.counters().unreadable_responses,
            (MAX_UNCONFIRMED_ATTEMPTS * 2) as usize,
            "each unreadable answer is counted"
        );
    }

    #[test]
    fn a_non_conformant_answer_is_counted() {
        // On the phone this counter is the only sign the receiver has not
        // migrated, so it is asserted rather than assumed.
        let mut exporter = Exporter::new(1, 10);
        exporter.enqueue(event(1));
        exporter.flush(Instant::now(), |_| {
            Some(DeliveryVerdict {
                nonconformant_body: true,
                ..delivered()
            })
        });
        assert_eq!(exporter.counters().nonconformant_responses, 1);
        assert_eq!(exporter.counters().unreadable_responses, 0);
    }

    #[test]
    fn a_declined_event_is_counted_and_not_retried() {
        let mut exporter = Exporter::new(2, 10);
        exporter.enqueue(event(1));
        exporter.enqueue(event(2));

        exporter.flush(Instant::now(), |_| {
            Some(DeliveryVerdict {
                outcome: DeliveryOutcome::Delivered,
                declined_events: 1,
                duplicate_events: 0,
                refused_events: 0,
                nonconformant_body: false,
                body_unreadable: false,
                receiver_answered: false,
                reason: "partial".into(),
            })
        });

        assert_eq!(exporter.counters().declined_events, 1);
        assert_eq!(
            exporter.counters().delivered_events,
            1,
            "a declined event is never counted as delivered"
        );
        assert_eq!(exporter.retained_events(), 0, "a decline is permanent");
    }

    #[test]
    fn an_idle_exporter_sends_nothing() {
        let mut exporter = Exporter::new(1, 10);
        let mut attempts = 0;
        let outcome = exporter.flush(Instant::now(), |_batch| {
            attempts += 1;
            Some(delivered())
        });
        assert_eq!(outcome, FlushOutcome::Idle);
        assert_eq!(attempts, 0, "no empty batch is ever posted");
    }

    #[test]
    fn a_batch_never_exceeds_the_configured_size() {
        let mut exporter = Exporter::new(2, 10);
        for value in 1..=5 {
            exporter.enqueue(event(value));
        }
        let mut sizes: Vec<usize> = Vec::new();
        exporter.flush(Instant::now(), |batch| {
            sizes.push(batch.events.len());
            Some(delivered())
        });
        assert_eq!(
            sizes,
            vec![2],
            "one batch per flush, at the configured size"
        );
        assert_eq!(exporter.queued_events(), 3, "the rest waits its turn");
    }
}
