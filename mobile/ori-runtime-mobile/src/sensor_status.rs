// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

//! What this payload observed of its own sensors, per `runtime-telemetry/v2`.
//!
//! A meter that stops answering produces no readings, and silence alone cannot
//! be told from a quiet meter or a dead network. The sensor-status route makes
//! the payload's observation expressible: for every declared sensor, whether
//! the most recent read succeeded, why it did not, when one last did, and how
//! many have failed since.
//!
//! The payload reports observations, never severity. There is no threshold and
//! no "degraded" state -- a window deciding what counts as a fault would be a
//! deployment-supplied number -- and no free-text detail, which would be
//! unbounded input a receiver renders and the obvious place for a path to leak.
//!
//! Status is state, not history. A snapshot is sent once and never retained: a
//! state change lost to a failed post is carried by the next snapshot, which
//! the interval guarantees.

use crate::delivery::{
    body_is_wanted, count, field, is_terminal_refusal, parse_strict_json, readable_header_section,
};
use serde_json::{json, Value as JsonValue};
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

pub const STATUS_SCHEMA_VERSION: &str = "runtime.sensor_status.v1";
pub const STATUS_ROUTE_SUFFIX: &str = "/sensor-status";

/// The least time between two snapshots when the second is sent for a change.
///
/// A change is otherwise sent at once, so without this a meter that answers
/// every other poll sends a snapshot on every poll. Fixed rather than
/// configured: the contract admits no setting that tunes this route.
pub const CHANGE_SPACING: Duration = Duration::from_secs(5);

/// The closed set of states, each decidable from the payload's own attempts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorState {
    Reading,
    Failing,
    NeverRead,
}

impl SensorState {
    pub fn as_str(self) -> &'static str {
        match self {
            SensorState::Reading => "reading",
            SensorState::Failing => "failing",
            SensorState::NeverRead => "never_read",
        }
    }
}

/// The closed set of reasons: facts about a read attempt, not diagnoses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusReason {
    None,
    NoResponse,
    MalformedResponse,
    IntegrityFailed,
    InterfaceAbsent,
    InterfaceDenied,
    NotConfigured,
    NotAttempted,
}

impl StatusReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StatusReason::None => "none",
            StatusReason::NoResponse => "no_response",
            StatusReason::MalformedResponse => "malformed_response",
            StatusReason::IntegrityFailed => "integrity_failed",
            StatusReason::InterfaceAbsent => "interface_absent",
            StatusReason::InterfaceDenied => "interface_denied",
            StatusReason::NotConfigured => "not_configured",
            StatusReason::NotAttempted => "not_attempted",
        }
    }
}

/// A read that did not produce a reading, classified where it failed.
///
/// The reason is a value from the start rather than recovered from an error
/// message afterwards: a class matched out of message text changes silently
/// the day the message is reworded. `detail` is for this payload's log only and
/// never leaves the phone.
#[derive(Debug)]
pub struct ReadFailure {
    pub reason: StatusReason,
    pub detail: String,
}

impl fmt::Display for ReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.detail, self.reason.as_str())
    }
}

impl ReadFailure {
    pub fn new(reason: StatusReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// The interface could not be reached or went away during the exchange.
    ///
    /// A refused permission is `interface_denied`; anything else is
    /// `interface_absent`. A socket cannot tell an unplugged adapter from a
    /// bridge that is not serving, so both are `interface_absent`, and the
    /// payload does not claim more than that.
    pub fn interface(context: &str, error: &io::Error) -> Self {
        let reason = match error.kind() {
            io::ErrorKind::PermissionDenied => StatusReason::InterfaceDenied,
            _ => StatusReason::InterfaceAbsent,
        };
        Self::new(reason, format!("{context}: {error}"))
    }

    /// Waiting for an answer failed after `received` bytes of it had arrived.
    ///
    /// Nothing within the timeout is the meter not answering -- no mains, wrong
    /// baud, crossed wiring, wrong slave id -- and is `no_response`. Part of a
    /// frame followed by silence is an answer that did not parse. An error that
    /// is not a timeout is the bridge failing, which is the interface.
    pub fn awaiting_answer(received: usize, error: &io::Error) -> Self {
        let timed_out = matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        );
        if !timed_out {
            return Self::interface("failed to read Modbus response", error);
        }
        if received == 0 {
            Self::new(
                StatusReason::NoResponse,
                format!("no Modbus response within the read timeout: {error}"),
            )
        } else {
            Self::new(
                StatusReason::MalformedResponse,
                format!("Modbus response stopped after {received} bytes: {error}"),
            )
        }
    }

    /// The bridge closed the connection after `received` bytes of an answer.
    pub fn closed_awaiting_answer(received: usize) -> Self {
        if received == 0 {
            Self::new(
                StatusReason::InterfaceAbsent,
                "USB bridge closed the connection before any response",
            )
        } else {
            Self::new(
                StatusReason::MalformedResponse,
                format!("USB bridge closed the connection after {received} response bytes"),
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SensorHealth {
    sensor_id: String,
    sensor_type: String,
    state: SensorState,
    reason: StatusReason,
    last_success_ms: Option<u64>,
    consecutive_failures: u64,
}

impl SensorHealth {
    fn to_json(&self) -> JsonValue {
        let mut entry = json!({
            "sensor_id": self.sensor_id,
            "sensor_type": self.sensor_type,
            "state": self.state.as_str(),
            "reason": self.reason.as_str(),
            "consecutive_failures": self.consecutive_failures,
        });
        // Absent rather than null on never_read: two spellings of one fact is
        // two code paths in every receiver.
        if let Some(at) = self.last_success_ms {
            entry["last_success_ms"] = json!(at);
        }
        entry
    }
}

/// What the status route has cost and carried. Reported, not just logged.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StatusCounters {
    /// Snapshots the receiver accepted, in whole or with entries rejected.
    pub accepted_snapshots: usize,
    /// Snapshots discarded on any other answer, or on none.
    pub discarded_snapshots: usize,
    /// Sensor entries a receiver rejected. Not retried; the next snapshot
    /// supersedes them.
    pub rejected_sensor_entries: usize,
}

/// Per-sensor observation, and when a snapshot of it is owed.
pub struct StatusTracker {
    sensors: Vec<SensorHealth>,
    interval: Duration,
    /// The (state, reason) of every sensor as last sent. A change against this
    /// is an edge, and an edge is sent without waiting for the interval.
    last_sent: Option<Vec<(SensorState, StatusReason)>>,
    last_sent_at: Option<Instant>,
    /// Whether the receiver accepted the last snapshot. Only then does a change
    /// send before the interval: a receiver that discarded it has shown nothing
    /// that an earlier request would reach.
    last_accepted: bool,
    counters: StatusCounters,
}

impl StatusTracker {
    /// Every declared sensor starts `never_read` / `not_attempted`. A payload
    /// that has not polled a sensor has no read to describe, and must not claim
    /// a failure it has not observed.
    pub fn new<'a>(
        declared: impl IntoIterator<Item = (&'a str, &'a str)>,
        interval: Duration,
    ) -> Self {
        let sensors = declared
            .into_iter()
            .map(|(sensor_id, sensor_type)| SensorHealth {
                sensor_id: sensor_id.to_string(),
                sensor_type: sensor_type.to_string(),
                state: SensorState::NeverRead,
                reason: StatusReason::NotAttempted,
                last_success_ms: None,
                consecutive_failures: 0,
            })
            .collect();
        Self {
            sensors,
            interval,
            last_sent: None,
            last_sent_at: None,
            last_accepted: false,
            counters: StatusCounters::default(),
        }
    }

    /// A declared sensor this payload has no way to read.
    ///
    /// It is reported rather than left out, because a snapshot names every
    /// declared sensor, as `never_read` / `not_configured` with no failed
    /// attempts, since none is ever made.
    pub fn mark_not_configured(&mut self, sensor_id: &str) {
        if let Some(sensor) = self.sensor(sensor_id) {
            sensor.reason = StatusReason::NotConfigured;
        }
    }

    pub fn counters(&self) -> &StatusCounters {
        &self.counters
    }

    pub fn declared_sensors(&self) -> usize {
        self.sensors.len()
    }

    fn sensor(&mut self, sensor_id: &str) -> Option<&mut SensorHealth> {
        self.sensors.iter_mut().find(|s| s.sensor_id == sensor_id)
    }

    /// A read succeeded at `at_ms`.
    pub fn record_success(&mut self, sensor_id: &str, at_ms: u64) {
        if let Some(sensor) = self.sensor(sensor_id) {
            sensor.state = SensorState::Reading;
            sensor.reason = StatusReason::None;
            sensor.last_success_ms = Some(at_ms);
            sensor.consecutive_failures = 0;
        }
    }

    /// A read failed for `reason`.
    ///
    /// `None` and `NotAttempted` describe the absence of a failure, so neither
    /// can be recorded as one; a caller passing either is corrected to
    /// `not_configured` rather than allowed to report a failure as health.
    pub fn record_failure(&mut self, sensor_id: &str, reason: StatusReason) {
        let reason = match reason {
            StatusReason::None | StatusReason::NotAttempted => StatusReason::NotConfigured,
            other => other,
        };
        if let Some(sensor) = self.sensor(sensor_id) {
            sensor.state = if sensor.last_success_ms.is_some() {
                SensorState::Failing
            } else {
                SensorState::NeverRead
            };
            sensor.reason = reason;
            sensor.consecutive_failures = sensor.consecutive_failures.saturating_add(1);
        }
    }

    fn edges(&self) -> Vec<(SensorState, StatusReason)> {
        self.sensors.iter().map(|s| (s.state, s.reason)).collect()
    }

    /// Whether a snapshot is owed: at the first opportunity; once the interval
    /// has passed; and for a change of any sensor's state or reason, once
    /// `CHANGE_SPACING` has passed, if the receiver accepted the last snapshot.
    ///
    /// A counter moving is not a change, so a meter silent for a day is one
    /// snapshot when it stops and one per interval after. A snapshot counts as
    /// sent whatever became of it, and after one that was not accepted only the
    /// interval sends: a receiver that has not implemented this route then costs
    /// one request per interval however often a sensor changes. A change the
    /// spacing or a discard delays is carried by the next snapshot.
    pub fn snapshot_due(&self, now: Instant) -> bool {
        let (Some(sent), Some(at)) = (&self.last_sent, self.last_sent_at) else {
            return true;
        };
        let elapsed = now.saturating_duration_since(at);
        if elapsed >= self.interval {
            return true;
        }
        self.last_accepted && elapsed >= CHANGE_SPACING && *sent != self.edges()
    }

    /// The full snapshot, marked as sent. Every declared sensor is in it, so a
    /// receiver never has to remember which sensors it has heard about.
    pub fn take_snapshot(&mut self, device_id: &str, sent_at_ms: u64, now: Instant) -> JsonValue {
        self.last_sent = Some(self.edges());
        self.last_sent_at = Some(now);
        json!({
            "schema_version": STATUS_SCHEMA_VERSION,
            "device_id": device_id,
            "sent_at_ms": sent_at_ms,
            "sensors": self.sensors.iter().map(SensorHealth::to_json).collect::<Vec<_>>(),
        })
    }

    /// Count what became of a snapshot. Nothing is retained either way.
    pub fn record_outcome(&mut self, outcome: StatusOutcome) {
        self.last_accepted = matches!(outcome, StatusOutcome::Accepted { .. });
        match outcome {
            StatusOutcome::Accepted { rejected_sensors } => {
                self.counters.accepted_snapshots += 1;
                self.counters.rejected_sensor_entries += rejected_sensors;
            }
            StatusOutcome::Discarded | StatusOutcome::Suspend => {
                self.counters.discarded_snapshots += 1;
            }
        }
    }
}

/// What the payload does with a snapshot it just sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusOutcome {
    /// Accepted, in whole or with some entries rejected.
    Accepted { rejected_sensors: usize },
    /// Not accepted, and not retained: the next snapshot supersedes it.
    Discarded,
    /// The recorded terminal refusal. It is a statement about the credential,
    /// so it suspends export on both routes.
    Suspend,
}

/// Read a parsed answer to a snapshot, under the same header-section rules as
/// the reading route, so the two routes read one answer alike.
pub fn read_status_answer(
    status: u16,
    fields: &[(String, Vec<u8>)],
    body: Option<&[u8]>,
    sensors_sent: usize,
) -> StatusOutcome {
    if !readable_header_section(fields) {
        return StatusOutcome::Discarded;
    }
    let body = if body_is_wanted(fields) { body } else { None };
    read_status_response(
        Some(status),
        &field(fields, "content-type").unwrap_or_default(),
        field(fields, "www-authenticate").as_deref(),
        body,
        sensors_sent,
    )
}

/// Read the answer to a snapshot of `sensors_sent` sensors.
///
/// The body is read under the same strict rules as a reading batch's answer,
/// and a terminal refusal is recognised by the same rule, because one suspends
/// both routes and two readings of it would suspend one route and not the
/// other. No input to this function can panic.
pub fn read_status_response(
    status: Option<u16>,
    content_type: &str,
    www_authenticate: Option<&str>,
    body: Option<&[u8]>,
    sensors_sent: usize,
) -> StatusOutcome {
    let discarded = StatusOutcome::Discarded;
    let Some(status) = status else {
        return discarded;
    };
    let decoded = body.and_then(parse_strict_json);
    if is_terminal_refusal(status, content_type, www_authenticate, decoded.as_ref()) {
        return StatusOutcome::Suspend;
    }
    if !(200..300).contains(&status) {
        return discarded;
    }
    let Some(answer @ JsonValue::Object(_)) = decoded else {
        return discarded;
    };

    // There is no `duplicate` on this route: a snapshot is state, and sending
    // the same state again is not a duplicate of anything.
    match answer.get("status") {
        Some(JsonValue::String(value)) if value == "accepted" || value == "partial" => {}
        _ => return discarded,
    }
    let Some(accepted) = count(&answer, "accepted_sensors", sensors_sent) else {
        return discarded;
    };
    // Absent is read as none rejected, as the reading route reads an absent
    // `rejected_events`, and the counts must still account for the snapshot.
    let entries: &[JsonValue] = match answer.get("rejected_sensors") {
        None => &[],
        Some(JsonValue::Array(entries)) => entries,
        Some(_) => return discarded,
    };
    let mut named = std::collections::HashSet::new();
    for entry in entries {
        match entry.get("sensor_id") {
            Some(JsonValue::String(id)) if !id.is_empty() && named.insert(id.as_str()) => {}
            _ => return discarded,
        }
    }
    if accepted.checked_add(entries.len()) != Some(sensors_sent) {
        return discarded;
    }
    StatusOutcome::Accepted {
        rejected_sensors: entries.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    const GOLDEN_STATUS_BODY: &str = r#"{"device_id":"phone-gateway-ikeja-01","schema_version":"runtime.sensor_status.v1","sensors":[{"consecutive_failures":120,"last_success_ms":1718999400000,"reason":"no_response","sensor_id":"phone-main-power","sensor_type":"usb_power","state":"failing"},{"consecutive_failures":0,"last_success_ms":1719000000000,"reason":"none","sensor_id":"phone-battery","sensor_type":"battery_percent","state":"reading"},{"consecutive_failures":43,"reason":"interface_absent","sensor_id":"phone-inverter","sensor_type":"usb_power","state":"never_read"}],"sent_at_ms":1719000000000}"#;

    const JSON: &str = "application/json";

    fn tracker() -> StatusTracker {
        StatusTracker::new(
            [
                ("phone-main-power", "usb_power"),
                ("phone-battery", "battery_percent"),
                ("phone-inverter", "usb_power"),
            ],
            Duration::from_secs(30),
        )
    }

    #[test]
    fn a_tracker_driven_to_the_fixture_state_emits_the_fixture_bytes() {
        // Reached by recording attempts, not by writing the JSON, so the
        // tracker's own encoding is what is held to the contract's bytes.
        let mut t = tracker();
        t.record_success("phone-main-power", 1_718_999_400_000);
        for _ in 0..120 {
            t.record_failure("phone-main-power", StatusReason::NoResponse);
        }
        t.record_success("phone-battery", 1_719_000_000_000);
        for _ in 0..43 {
            t.record_failure("phone-inverter", StatusReason::InterfaceAbsent);
        }
        let snapshot = t.take_snapshot("phone-gateway-ikeja-01", 1_719_000_000_000, Instant::now());
        let body = crate::canonical_telemetry_json(&snapshot).expect("canonical");
        assert_eq!(body, GOLDEN_STATUS_BODY.as_bytes());

        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(&body)),
            "59bd6c5b96f02d21874df60d195ccd9adb409dee448710c0ba518efa3b5b41cf"
        );
        assert_eq!(
            crate::telemetry_signature(b"test-runtime-telemetry-key", b"1719000000123", &body)
                .expect("HMAC"),
            "f38b4e3c689b302bd0ff9faae2e13e2e58a14f48d9b9eae370132aee4f4177e2"
        );
    }

    #[test]
    fn a_new_tracker_reports_every_sensor_as_not_yet_attempted() {
        let mut t = tracker();
        let snapshot = t.take_snapshot("d", 1, Instant::now());
        for sensor in snapshot["sensors"].as_array().unwrap() {
            assert_eq!(sensor["state"], "never_read");
            assert_eq!(sensor["reason"], "not_attempted");
            assert_eq!(sensor["consecutive_failures"], 0);
            assert!(
                sensor.get("last_success_ms").is_none(),
                "absent, never null"
            );
        }
    }

    #[test]
    fn a_sensor_that_worked_and_stopped_is_failing_and_one_that_never_worked_is_not() {
        let mut t = tracker();
        t.record_success("phone-main-power", 10);
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        t.record_failure("phone-battery", StatusReason::NoResponse);
        let snapshot = t.take_snapshot("d", 1, Instant::now());
        let sensors = snapshot["sensors"].as_array().unwrap();
        assert_eq!(sensors[0]["state"], "failing");
        assert_eq!(sensors[0]["last_success_ms"], 10);
        assert_eq!(sensors[1]["state"], "never_read");
        assert!(sensors[1].get("last_success_ms").is_none());
    }

    #[test]
    fn recovery_resets_the_failure_count_and_clears_the_reason() {
        let mut t = tracker();
        t.record_failure("phone-main-power", StatusReason::IntegrityFailed);
        t.record_failure("phone-main-power", StatusReason::IntegrityFailed);
        t.record_success("phone-main-power", 99);
        let snapshot = t.take_snapshot("d", 1, Instant::now());
        let sensor = &snapshot["sensors"][0];
        assert_eq!(sensor["state"], "reading");
        assert_eq!(sensor["reason"], "none");
        assert_eq!(sensor["consecutive_failures"], 0);
        assert_eq!(sensor["last_success_ms"], 99);
    }

    #[test]
    fn repeated_failures_of_one_kind_owe_no_further_snapshot_within_the_interval() {
        let start = Instant::now();
        let mut t = tracker();
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        assert!(t.snapshot_due(start));
        t.take_snapshot("d", 1, start);

        for _ in 0..50 {
            t.record_failure("phone-main-power", StatusReason::NoResponse);
        }
        assert!(
            !t.snapshot_due(start + Duration::from_secs(29)),
            "a counter moving is not an edge"
        );
        assert!(
            t.snapshot_due(start + Duration::from_secs(30)),
            "the interval still reports"
        );
    }

    #[test]
    fn a_change_of_reason_owes_a_snapshot_once_the_spacing_has_passed() {
        let start = Instant::now();
        let mut t = tracker();
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        t.take_snapshot("d", 1, start);
        t.record_outcome(StatusOutcome::Accepted {
            rejected_sensors: 0,
        });
        t.record_failure("phone-main-power", StatusReason::InterfaceAbsent);
        assert!(!t.snapshot_due(start + CHANGE_SPACING - Duration::from_millis(1)));
        assert!(t.snapshot_due(start + CHANGE_SPACING));
    }

    #[test]
    fn a_sensor_changing_on_every_poll_costs_one_snapshot_per_spacing() {
        // A meter that answers every other poll. Unbounded, each poll's change
        // would be a snapshot.
        let start = Instant::now();
        let mut t = tracker();
        let mut sent = 0;
        for poll in 0..100_u64 {
            if poll % 2 == 0 {
                t.record_success("phone-main-power", poll);
            } else {
                t.record_failure("phone-main-power", StatusReason::NoResponse);
            }
            let now = start + Duration::from_millis(200 * poll);
            if t.snapshot_due(now) {
                t.take_snapshot("d", 1, now);
                t.record_outcome(StatusOutcome::Accepted {
                    rejected_sensors: 0,
                });
                sent += 1;
            }
        }
        // Twenty seconds of polls: at 0, 5, 10 and 15 seconds, and no others.
        assert_eq!(sent, 4, "{sent} snapshots");
    }

    #[test]
    fn a_change_of_state_with_the_same_reason_is_an_edge() {
        // never_read/no_response to failing/no_response cannot happen, since a
        // success clears the reason; reading to failing is the state edge.
        let start = Instant::now();
        let mut t = tracker();
        t.record_success("phone-main-power", 1);
        t.take_snapshot("d", 1, start);
        t.record_outcome(StatusOutcome::Accepted {
            rejected_sensors: 0,
        });
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        assert!(t.snapshot_due(start + CHANGE_SPACING));
    }

    #[test]
    fn recovery_is_an_edge() {
        let start = Instant::now();
        let mut t = tracker();
        t.record_success("phone-main-power", 1);
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        t.take_snapshot("d", 1, start);
        t.record_outcome(StatusOutcome::Accepted {
            rejected_sensors: 0,
        });
        t.record_success("phone-main-power", 2);
        assert!(t.snapshot_due(start + CHANGE_SPACING));
    }

    #[test]
    fn an_unchanged_state_owes_nothing_before_the_interval_after_an_acceptance() {
        let start = Instant::now();
        let mut t = tracker();
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        t.take_snapshot("d", 1, start);
        t.record_outcome(StatusOutcome::Accepted {
            rejected_sensors: 0,
        });
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        assert!(
            !t.snapshot_due(start + Duration::from_secs(29)),
            "the spacing permits a change; it does not send without one"
        );
    }

    #[test]
    fn a_discard_after_an_acceptance_holds_changes_to_the_interval() {
        let start = Instant::now();
        let mut t = tracker();
        t.take_snapshot("d", 1, start);
        t.record_outcome(StatusOutcome::Accepted {
            rejected_sensors: 0,
        });
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        let second = start + CHANGE_SPACING;
        assert!(t.snapshot_due(second));
        t.take_snapshot("d", 2, second);
        t.record_outcome(StatusOutcome::Discarded);
        t.record_success("phone-main-power", 3);
        assert!(
            !t.snapshot_due(second + Duration::from_secs(29)),
            "the discard, not the earlier acceptance, decides"
        );
        assert!(t.snapshot_due(second + Duration::from_secs(30)));
    }

    #[test]
    fn a_discarded_snapshot_is_not_resent_before_the_interval() {
        // A receiver that has not implemented the route answers 404 to every
        // snapshot. Re-sending on the next poll would be a request per poll.
        let start = Instant::now();
        let mut t = tracker();
        t.record_failure("phone-main-power", StatusReason::NoResponse);
        t.take_snapshot("d", 1, start);
        t.record_outcome(read_status_response(Some(404), JSON, None, Some(b"{}"), 3));
        t.record_failure("phone-main-power", StatusReason::InterfaceAbsent);
        assert!(
            !t.snapshot_due(start + Duration::from_secs(29)),
            "after a discard, not even a change sends before the interval"
        );
        assert!(t.snapshot_due(start + Duration::from_secs(30)));
        assert_eq!(t.counters().discarded_snapshots, 1);
    }

    #[test]
    fn outcomes_are_counted() {
        let mut t = tracker();
        t.record_outcome(StatusOutcome::Accepted {
            rejected_sensors: 2,
        });
        t.record_outcome(StatusOutcome::Accepted {
            rejected_sensors: 1,
        });
        t.record_outcome(StatusOutcome::Discarded);
        t.record_outcome(StatusOutcome::Suspend);
        assert_eq!(
            t.counters(),
            &StatusCounters {
                accepted_snapshots: 2,
                discarded_snapshots: 2,
                rejected_sensor_entries: 3,
            },
            "a refusal is a snapshot that was not accepted"
        );
    }

    #[test]
    fn a_declared_sensor_the_payload_cannot_read_is_reported_as_not_configured() {
        let mut t = tracker();
        t.mark_not_configured("phone-battery");
        let snapshot = t.take_snapshot("d", 1, Instant::now());
        let entry = &snapshot["sensors"][1];
        assert_eq!(entry["state"], "never_read");
        assert_eq!(entry["reason"], "not_configured");
        assert_eq!(entry["consecutive_failures"], 0, "no attempt is made");
    }

    #[test]
    fn a_success_or_not_attempted_cannot_be_recorded_as_a_failure() {
        let mut t = tracker();
        t.record_failure("phone-main-power", StatusReason::None);
        t.record_failure("phone-battery", StatusReason::NotAttempted);
        let snapshot = t.take_snapshot("d", 1, Instant::now());
        assert_eq!(snapshot["sensors"][0]["reason"], "not_configured");
        assert_eq!(snapshot["sensors"][1]["reason"], "not_configured");
    }

    #[test]
    fn an_undeclared_sensor_is_ignored_rather_than_added() {
        let mut t = tracker();
        t.record_failure("stranger", StatusReason::NoResponse);
        let snapshot = t.take_snapshot("d", 1, Instant::now());
        assert_eq!(snapshot["sensors"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn io_errors_are_classified_where_they_fail() {
        let refused = Error::from(ErrorKind::ConnectionRefused);
        let denied = Error::from(ErrorKind::PermissionDenied);
        let timeout = Error::from(ErrorKind::TimedOut);
        let would_block = Error::from(ErrorKind::WouldBlock);
        let reset = Error::from(ErrorKind::ConnectionReset);

        assert_eq!(
            ReadFailure::interface("c", &refused).reason,
            StatusReason::InterfaceAbsent
        );
        assert_eq!(
            ReadFailure::interface("c", &denied).reason,
            StatusReason::InterfaceDenied
        );
        assert_eq!(
            ReadFailure::awaiting_answer(0, &timeout).reason,
            StatusReason::NoResponse
        );
        assert_eq!(
            ReadFailure::awaiting_answer(0, &would_block).reason,
            StatusReason::NoResponse
        );
        assert_eq!(
            ReadFailure::awaiting_answer(3, &timeout).reason,
            StatusReason::MalformedResponse
        );
        assert_eq!(
            ReadFailure::awaiting_answer(0, &reset).reason,
            StatusReason::InterfaceAbsent
        );
        assert_eq!(
            ReadFailure::awaiting_answer(0, &denied).reason,
            StatusReason::InterfaceDenied
        );
        assert_eq!(
            ReadFailure::closed_awaiting_answer(0).reason,
            StatusReason::InterfaceAbsent
        );
        assert_eq!(
            ReadFailure::closed_awaiting_answer(4).reason,
            StatusReason::MalformedResponse
        );
    }

    #[test]
    fn a_status_answer_is_accepted_only_when_its_counts_account_for_the_snapshot() {
        let ok = br#"{"status":"accepted","accepted_sensors":3,"rejected_sensors":[]}"#;
        assert_eq!(
            read_status_response(Some(200), JSON, None, Some(ok), 3),
            StatusOutcome::Accepted {
                rejected_sensors: 0
            }
        );
        let partial = br#"{"status":"partial","accepted_sensors":2,"rejected_sensors":[{"sensor_id":"x","reason":"unknown_state"}]}"#;
        assert_eq!(
            read_status_response(Some(200), JSON, None, Some(partial), 3),
            StatusOutcome::Accepted {
                rejected_sensors: 1
            }
        );
    }

    #[test]
    fn anything_else_discards_the_snapshot() {
        let short = br#"{"status":"accepted","accepted_sensors":2,"rejected_sensors":[]}"#;
        let unnamed =
            br#"{"status":"partial","accepted_sensors":2,"rejected_sensors":[{"reason":"x"}]}"#;
        let duplicate = br#"{"status":"duplicate","accepted_sensors":3,"rejected_sensors":[]}"#;
        let empty_id =
            br#"{"status":"partial","accepted_sensors":2,"rejected_sensors":[{"sensor_id":""}]}"#;
        let twice = br#"{"status":"partial","accepted_sensors":1,"rejected_sensors":[{"sensor_id":"a"},{"sensor_id":"a"}]}"#;
        let wraps = br#"{"status":"accepted","accepted_sensors":18446744073709551615,"rejected_sensors":[{"sensor_id":"a"},{"sensor_id":"b"},{"sensor_id":"c"},{"sensor_id":"d"}]}"#;
        let too_many = br#"{"status":"partial","accepted_sensors":0,"rejected_sensors":[{"sensor_id":"a"},{"sensor_id":"b"},{"sensor_id":"c"},{"sensor_id":"d"}]}"#;
        let repeated = br#"{"status":"accepted","accepted_sensors":0,"accepted_sensors":3,"rejected_sensors":[]}"#;
        let negative_zero = br#"{"status":"partial","accepted_sensors":-0,"rejected_sensors":[{"sensor_id":"a"},{"sensor_id":"b"},{"sensor_id":"c"}]}"#;
        for (label, verdict) in [
            ("no answer", read_status_response(None, "", None, None, 3)),
            (
                "route not implemented",
                read_status_response(Some(404), JSON, None, Some(b"{}"), 3),
            ),
            (
                "server fault",
                read_status_response(Some(503), "", None, None, 3),
            ),
            (
                "unreadable",
                read_status_response(Some(200), "text/html", None, Some(b"<html>"), 3),
            ),
            (
                "counts short",
                read_status_response(Some(200), JSON, None, Some(short), 3),
            ),
            (
                "unnamed rejection",
                read_status_response(Some(200), JSON, None, Some(unnamed), 3),
            ),
            (
                "no duplicate status on this route",
                read_status_response(Some(200), JSON, None, Some(duplicate), 3),
            ),
            (
                "empty sensor_id",
                read_status_response(Some(200), JSON, None, Some(empty_id), 3),
            ),
            (
                "one sensor rejected twice",
                read_status_response(Some(200), JSON, None, Some(twice), 3),
            ),
            (
                "a count that would wrap",
                read_status_response(Some(200), JSON, None, Some(wraps), 3),
            ),
            (
                "more rejected than sent",
                read_status_response(Some(200), JSON, None, Some(too_many), 3),
            ),
            (
                "a repeated member",
                read_status_response(Some(200), JSON, None, Some(repeated), 3),
            ),
            (
                "-0 is not a count",
                read_status_response(Some(200), JSON, None, Some(negative_zero), 3),
            ),
        ] {
            assert_eq!(verdict, StatusOutcome::Discarded, "{label}");
        }
    }

    #[test]
    fn a_rejected_sensors_that_is_not_an_array_discards() {
        for body in [
            br#"{"status":"accepted","accepted_sensors":3,"rejected_sensors":{}}"#.as_slice(),
            br#"{"status":"accepted","accepted_sensors":3,"rejected_sensors":null}"#.as_slice(),
        ] {
            assert_eq!(
                read_status_response(Some(200), JSON, None, Some(body), 3),
                StatusOutcome::Discarded
            );
        }
    }

    #[test]
    fn an_absent_rejected_sensors_is_read_as_none_rejected() {
        let missing = br#"{"status":"accepted","accepted_sensors":3}"#;
        assert_eq!(
            read_status_response(Some(200), JSON, None, Some(missing), 3),
            StatusOutcome::Accepted {
                rejected_sensors: 0
            }
        );
        let short = br#"{"status":"accepted","accepted_sensors":2}"#;
        assert_eq!(
            read_status_response(Some(200), JSON, None, Some(short), 3),
            StatusOutcome::Discarded,
            "the counts must still account for the snapshot"
        );
    }

    #[test]
    fn the_recorded_refusal_on_this_route_suspends() {
        let refusal = br#"{"detail":"device is suspended"}"#;
        assert_eq!(
            read_status_response(Some(403), JSON, None, Some(refusal), 3),
            StatusOutcome::Suspend
        );
        // The same properties the reading route requires, so a proxy's 403
        // cannot suspend export through the route that carries no readings.
        for (label, verdict) in [
            (
                "challenge",
                read_status_response(Some(403), JSON, Some("Bearer"), Some(refusal), 3),
            ),
            (
                "html",
                read_status_response(Some(403), "text/html", None, Some(refusal), 3),
            ),
            (
                "other detail",
                read_status_response(Some(403), JSON, None, Some(br#"{"detail":"no"}"#), 3),
            ),
            (
                "repeated detail",
                read_status_response(
                    Some(403),
                    JSON,
                    None,
                    Some(br#"{"detail":"no","detail":"device is suspended"}"#),
                    3,
                ),
            ),
        ] {
            assert_eq!(verdict, StatusOutcome::Discarded, "{label}");
        }
    }
}
