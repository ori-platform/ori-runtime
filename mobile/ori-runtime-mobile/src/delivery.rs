// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

//! How this payload reads a receiver's answer to a telemetry batch.
//!
//! `runtime-telemetry/v2` makes the ingest response the only thing that says
//! whether readings were stored. Reading it is a pure decision over the status
//! line, the media type, the authentication challenge and the body, so it lives
//! apart from the HTTP client that fetched them, and the same vector set that
//! drives the Python exporter drives this.

use serde_json::Value as JsonValue;

/// The refusals the endpoint repeats for as long as this credential is
/// presented. The enumeration belongs to the receiver; the runtime's
/// `tests/vectors/telemetry_refusals` pins both halves.
pub const TERMINAL_REFUSAL_STATUS: u16 = 403;
pub const TERMINAL_REFUSAL_DETAIL: &str = "device is suspended";

/// A response body is remote input on a phone's memory. The conformant answer
/// is a few hundred bytes and three containers deep; these are ceilings, not
/// sizes. Both are checked here rather than left to serde_json, whose own
/// nesting limit is an implementation detail, so the Python producer can hold
/// exactly the same bounds and neither reads a body the other refuses.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub const MAX_JSON_DEPTH: usize = 32;

/// The most bytes of field names and values a readable header section holds.
pub const MAX_HEADER_FIELD_BYTES: usize = 100 * 1024;

const BATCH_STATUSES: [&str; 3] = ["accepted", "duplicate", "partial"];

/// What the payload does with the batch it just sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryOutcome {
    Delivered,
    Retain,
    Suspend,
}

#[derive(Debug, Clone)]
pub struct DeliveryVerdict {
    pub outcome: DeliveryOutcome,
    pub declined_events: usize,
    /// Events the receiver already held. Delivered, and counted apart.
    pub duplicate_events: usize,
    pub refused_events: usize,
    pub nonconformant_body: bool,
    /// Whether the answer itself could not be read, as opposed to being read
    /// and saying the batch was not delivered. A field rather than something a
    /// caller matches out of `reason`, whose own documentation says it is for
    /// logs: rewording a message would silently zero the counter.
    pub body_unreadable: bool,
    /// Whether the receiver's application answered: a 2xx carrying a JSON
    /// object. Such an answer is deterministic, so a batch it keeps failing to
    /// confirm is abandoned after a bounded number of attempts. An unreadable
    /// or absent answer is not the receiver speaking, and is retried.
    pub receiver_answered: bool,
    pub reason: String,
}

impl DeliveryVerdict {
    fn retain(reason: impl Into<String>) -> Self {
        Self {
            outcome: DeliveryOutcome::Retain,
            declined_events: 0,
            duplicate_events: 0,
            refused_events: 0,
            nonconformant_body: false,
            body_unreadable: false,
            receiver_answered: false,
            reason: reason.into(),
        }
    }

    fn unreadable(reason: impl Into<String>) -> Self {
        Self {
            body_unreadable: true,
            ..Self::retain(reason)
        }
    }

    fn unconfirmed(reason: impl Into<String>, speaks_contract: bool) -> Self {
        Self {
            receiver_answered: speaks_contract,
            ..Self::retain(reason)
        }
    }
}

/// A header's values as one, in order, or None when it was absent.
///
/// Joined with ", " as HTTP permits and as the Python producer's client
/// presents them, so a header sent twice is read the same way by both: a JSON
/// media type followed by another is not a JSON media type, whichever came
/// first.
pub fn join_header_values(values: &[&str]) -> Option<String> {
    (!values.is_empty()).then(|| values.join(", "))
}

/// The fields the verdict reads, or frames the body by.
const VERDICT_FIELDS: [&str; 5] = [
    "content-type",
    "www-authenticate",
    "content-encoding",
    "content-length",
    "transfer-encoding",
];

/// Whether a parsed response's header section can be read alike by every
/// producer.
///
/// Parsing has already refused what h11 refuses. Two things remain that a
/// parser accepts and producers would still read differently: a byte outside
/// visible ASCII, space and tab in a field the verdict reads -- decoded one way
/// by one client's header text and another way by the next -- and a response
/// framed by both a transfer coding and a length, which clients resolve
/// differently. Bytes in any other field are left alone: an unrelated header
/// carrying a site name in UTF-8 is not a reason to hold readings for good.
pub fn readable_header_section(fields: &[(String, Vec<u8>)]) -> bool {
    // Measured on the parsed fields rather than the bytes received: the Python
    // producer's parser enforces its own limit only while a section is still
    // incomplete, which depends on how the bytes arrived, and a section it read
    // whole cannot be measured there any other way.
    let size: usize = fields
        .iter()
        .map(|(name, value)| name.len() + value.len())
        .sum();
    if size > MAX_HEADER_FIELD_BYTES {
        return false;
    }
    let named = |wanted: &str| {
        fields
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(wanted))
    };
    if named("transfer-encoding") && named("content-length") {
        return false;
    }
    fields.iter().all(|(name, value)| {
        !VERDICT_FIELDS
            .iter()
            .any(|field| name.eq_ignore_ascii_case(field))
            || value
                .iter()
                .all(|b| matches!(b, b' ' | b'\t' | 0x21..=0x7E))
    })
}

/// Every value of the named field, joined, or None when it is absent. Only
/// called for verdict fields, whose bytes `readable_header_section` has
/// already held to visible ASCII.
pub(crate) fn field(fields: &[(String, Vec<u8>)], wanted: &str) -> Option<String> {
    let values: Vec<String> = fields
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(wanted))
        .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
        .collect();
    join_header_values(&values.iter().map(String::as_str).collect::<Vec<_>>())
}

fn declared_past_ceiling(fields: &[(String, Vec<u8>)]) -> bool {
    field(fields, "content-length")
        .and_then(|length| length.trim().parse::<u128>().ok())
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u128)
}

/// Whether a transport should read this response's body at all.
///
/// Not when the header section cannot be read alike, when the body is
/// content-coded, or when it declares more than the ceiling: each is decided
/// before a byte of the body is read, by both producers.
pub fn body_is_wanted(fields: &[(String, Vec<u8>)]) -> bool {
    readable_header_section(fields)
        && readable_content_coding(field(fields, "content-encoding").as_deref())
        && !declared_past_ceiling(fields)
}

/// Read one parsed answer to a batch.
///
/// `status` is None when nothing a parser would read arrived. `body` is None
/// when it was not read or ran past the ceiling.
pub fn read_answer(
    status: Option<u16>,
    fields: &[(String, Vec<u8>)],
    body: Option<&[u8]>,
    batch_events: usize,
) -> DeliveryVerdict {
    if status.is_none() || !readable_header_section(fields) {
        return read_batch_response(None, "", None, None, batch_events);
    }
    let body = if body_is_wanted(fields) { body } else { None };
    read_batch_response(
        status,
        &field(fields, "content-type").unwrap_or_default(),
        field(fields, "www-authenticate").as_deref(),
        body,
        batch_events,
    )
}

/// Whether a body under this `Content-Encoding` is read at all.
///
/// Only an absent or `identity` coding is. This payload requests no coding, so
/// a coded body is an intermediary's choice; this client decodes none, and a
/// coding the other producer's client would decode must not make one producer
/// read a body the other cannot.
pub fn readable_content_coding(content_encoding: Option<&str>) -> bool {
    match content_encoding {
        None => true,
        Some(value) => {
            let value = value.trim_matches(|c| matches!(c, ' ' | '\t'));
            value.is_empty() || value.eq_ignore_ascii_case("identity")
        }
    }
}

fn is_json_media_type(content_type: &str) -> bool {
    let base = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    base == "application/json" || base.ends_with("+json")
}

/// Whether more than `limit` containers are ever open at once.
///
/// Scanned over bytes outside strings before the parser runs, with the same
/// definition the Python producer uses: every open `[` or `{` counts, the
/// outermost included.
fn nesting_exceeds(body: &[u8], limit: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for &byte in body {
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == b'[' || byte == b'{' {
            depth += 1;
            if depth > limit {
                return true;
            }
        } else if byte == b']' || byte == b'}' {
            depth = depth.saturating_sub(1);
        }
    }
    false
}

/// Parse a body the way both producers must, or None when it is unreadable.
///
/// serde_json already refuses a byte-order mark, invalid UTF-8, NaN, Infinity,
/// an out-of-range number and an escaped lone surrogate; the Python producer
/// refuses the same set explicitly. The size and depth bounds are checked here
/// so neither producer depends on a library limit, and so is a repeated member
/// name, which serde_json would otherwise resolve by keeping the last.
pub(crate) fn parse_strict_json(body: &[u8]) -> Option<JsonValue> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BYTES {
        return None;
    }
    if nesting_exceeds(body, MAX_JSON_DEPTH) {
        return None;
    }
    serde_json::from_slice::<UniqueMembers>(body)
        .ok()
        .map(|parsed| parsed.0)
}

/// A JSON value in which no object names a member twice.
///
/// Which occurrence a parser keeps is the library's choice, not the contract's,
/// and a body reading `accepted_events` as 0 in one producer and 1 in another
/// is a disagreement about whether readings were stored.
struct UniqueMembers(JsonValue);

impl<'de> serde::Deserialize<'de> for UniqueMembers {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(UniqueMembersVisitor)
    }
}

struct UniqueMembersVisitor;

impl<'de> serde::de::Visitor<'de> for UniqueMembersVisitor {
    type Value = UniqueMembers;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value with unique member names")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueMembers(JsonValue::Null))
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueMembers(JsonValue::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueMembers(JsonValue::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueMembers(JsonValue::from(value)))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        serde_json::Number::from_f64(value)
            .map(|number| UniqueMembers(JsonValue::Number(number)))
            .ok_or_else(|| E::custom("number out of range"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueMembers(JsonValue::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueMembers(JsonValue::String(value)))
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut items = Vec::new();
        while let Some(UniqueMembers(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(UniqueMembers(JsonValue::Array(items)))
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut members = serde_json::Map::new();
        while let Some((name, UniqueMembers(value))) = map.next_entry::<String, UniqueMembers>()? {
            if members.contains_key(&name) {
                return Err(serde::de::Error::custom("repeated member name"));
            }
            members.insert(name, value);
        }
        Ok(UniqueMembers(JsonValue::Object(members)))
    }
}

/// A count member read strictly, or None when it is not a count.
///
/// An integer token between zero and the batch size. `as_u64` refuses a
/// negative number and a number written with a fraction or exponent. Holding
/// every term to the batch size is what keeps the sum below from wrapping in a
/// release build, panicking in a debug one, or truncating on a 32-bit phone.
pub(crate) fn count(body: &JsonValue, key: &str, batch_events: usize) -> Option<usize> {
    let value = body.get(key)?.as_u64()?;
    let value = usize::try_from(value).ok()?;
    (value <= batch_events).then_some(value)
}

/// Whether this is the endpoint refusing this credential for good.
///
/// Suspension stops export for the life of the credential, so it needs positive
/// evidence that the endpoint answered rather than merely that nothing
/// contradicted it. Any intermediary can return a bare 403 -- a proxy or WAF
/// does so without a challenge and with an HTML body -- and an absent header
/// proves nothing about origin. So every recorded property must hold.
pub(crate) fn is_terminal_refusal(
    status: u16,
    content_type: &str,
    www_authenticate: Option<&str>,
    body: Option<&JsonValue>,
) -> bool {
    if status != TERMINAL_REFUSAL_STATUS {
        return false;
    }
    if www_authenticate.is_some_and(|value| !value.is_empty()) {
        return false;
    }
    if !is_json_media_type(content_type) {
        return false;
    }
    match body.and_then(|value| value.get("detail")) {
        // Trimmed of ASCII space, tab, CR and LF only, as the Python producer
        // trims: `str::trim` and Python's `strip` disagree about which control
        // characters are whitespace.
        Some(JsonValue::String(detail)) => {
            detail.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'))
                == TERMINAL_REFUSAL_DETAIL
        }
        _ => false,
    }
}

/// Read one answer to a batch of `batch_events` events.
///
/// `status` is `None` when no answer arrived at all. Every path returns a
/// verdict: there is no answer this payload may treat as a reason to stop, and
/// no input to this function can end the process -- `Exporter::flush` promises
/// that and cannot keep the promise if this panics.
pub fn read_batch_response(
    status: Option<u16>,
    content_type: &str,
    www_authenticate: Option<&str>,
    body: Option<&[u8]>,
    batch_events: usize,
) -> DeliveryVerdict {
    // The contract forbids posting an empty batch and `take_pending` never
    // forms one, so this is a programming error rather than an answer. It is
    // reported and retained rather than asserted: a caller that promises not to
    // end the process must not be given a function that can.
    if batch_events == 0 {
        return DeliveryVerdict::retain("empty batch was not sent");
    }

    let Some(status) = status else {
        return DeliveryVerdict::retain("no response");
    };

    let decoded = body.and_then(parse_strict_json);

    if is_terminal_refusal(status, content_type, www_authenticate, decoded.as_ref()) {
        return DeliveryVerdict {
            outcome: DeliveryOutcome::Suspend,
            declined_events: 0,
            duplicate_events: 0,
            refused_events: batch_events,
            nonconformant_body: false,
            body_unreadable: false,
            receiver_answered: false,
            reason: format!("terminal refusal HTTP {status}"),
        };
    }

    if !(200..300).contains(&status) {
        return DeliveryVerdict::retain(format!("HTTP {status}"));
    }

    // A 2xx says nothing on its own. The body is what reports whether the
    // readings were stored, so a body that cannot be read is a transport
    // failure rather than an assumed delivery.
    let Some(JsonValue::Object(_)) = decoded else {
        return DeliveryVerdict::unreadable(format!("HTTP {status} with an unreadable body"));
    };
    let body = decoded.expect("matched as an object above");

    // A body counts toward abandoning the batch only when it is this contract's
    // answer: a JSON media type and a `status` the contract defines. Abandonment
    // discards readings, and a captive portal answering 200 with a JSON object
    // of its own is not the receiver declining to confirm them.
    let batch_status = match body.get("status") {
        Some(JsonValue::String(value)) if BATCH_STATUSES.contains(&value.as_str()) => value.clone(),
        _ => {
            return DeliveryVerdict::retain("response status is absent or not a defined value");
        }
    };
    let speaks = is_json_media_type(content_type);
    let unconfirmed = |reason: &str| DeliveryVerdict::unconfirmed(reason, speaks);

    let Some(accepted) = count(&body, "accepted_events", batch_events) else {
        return unconfirmed("accepted_events is absent or not a count");
    };

    // `rejected_events` and `duplicate_events` are required of a receiver and
    // tolerated when absent: an absent one is read as zero, the body is recorded
    // as non-conformant, and the invariant must still hold on that reading. The
    // answer an unmigrated receiver gives when it rejects a batch on `sequence`
    // -- `{"status": "duplicate", "accepted_events": 0}` -- therefore sums to
    // nothing and is not a delivery of readings it stored none of.
    let mut nonconformant = false;

    let declined = match body.get("rejected_events") {
        Some(JsonValue::Array(entries)) => {
            let mut named = std::collections::HashSet::new();
            for entry in entries {
                match entry.get("event_id") {
                    Some(JsonValue::String(event_id)) if !event_id.is_empty() => {
                        if !named.insert(event_id.as_str()) {
                            return unconfirmed("a rejected_events entry repeats an event");
                        }
                    }
                    _ => return unconfirmed("a rejected_events entry does not name an event"),
                }
            }
            entries.len()
        }
        Some(_) => return unconfirmed("rejected_events is not a list"),
        None => {
            nonconformant = true;
            0
        }
    };

    let duplicate = match body.get("duplicate_events") {
        Some(_) => match count(&body, "duplicate_events", batch_events) {
            Some(value) => value,
            None => {
                return unconfirmed("duplicate_events is present and not a count");
            }
        },
        None => {
            nonconformant = true;
            0
        }
    };

    // Every term is at most the batch size, so this cannot overflow; saturating
    // keeps that true if the bound is ever loosened.
    if accepted.saturating_add(duplicate).saturating_add(declined) != batch_events {
        return unconfirmed("response counts do not account for the batch");
    }

    DeliveryVerdict {
        outcome: DeliveryOutcome::Delivered,
        declined_events: declined,
        duplicate_events: duplicate,
        refused_events: 0,
        nonconformant_body: nonconformant,
        body_unreadable: false,
        receiver_answered: true,
        reason: batch_status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// The same decision table the Python producer reads. Compiled in, so a
    /// change to the vectors rebuilds this test rather than being missed.
    const VECTORS: &str =
        include_str!("../../../tests/vectors/telemetry_delivery/delivery_cases.json");

    fn outcome_from(name: &str) -> DeliveryOutcome {
        match name {
            "delivered" => DeliveryOutcome::Delivered,
            "retain" => DeliveryOutcome::Retain,
            "suspend" => DeliveryOutcome::Suspend,
            other => panic!("unknown outcome in the vector set: {other}"),
        }
    }

    #[test]
    fn a_header_section_is_readable_up_to_its_field_limit() {
        let padded = |total: usize| vec![("X-Pad".to_string(), vec![b'a'; total - "X-Pad".len()])];
        assert!(readable_header_section(&padded(MAX_HEADER_FIELD_BYTES)));
        assert!(!readable_header_section(&padded(
            MAX_HEADER_FIELD_BYTES + 1
        )));
    }

    #[test]
    fn every_delivery_vector_reaches_its_recorded_outcome() {
        let contract: JsonValue = serde_json::from_str(VECTORS).expect("vectors parse");
        let cases = contract["cases"].as_array().expect("cases is an array");
        assert!(!cases.is_empty(), "the vector set is empty");

        for case in cases {
            let name = case["name"].as_str().unwrap();
            let batch_events = case["batch_events"].as_u64().unwrap() as usize;
            let response = &case["response"];
            let expect = &case["expect"];

            let verdict = if response.get("transport_error").is_some() {
                read_batch_response(None, "", None, None, batch_events)
            } else if let Some(encoded) = response.get("raw_response_b64") {
                // Read by the payload's own HTTP client, as it reads the wire.
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(encoded.as_str().unwrap())
                    .expect("raw_response_b64 decodes");
                match crate::http::read_raw(&raw, 4096, MAX_RESPONSE_BYTES, |_, fields| {
                    body_is_wanted(fields)
                }) {
                    Ok(parsed) => {
                        let body = match &parsed.body {
                            crate::http::Body::Complete(bytes) => Some(bytes.as_slice()),
                            _ => None,
                        };
                        read_answer(Some(parsed.status), &parsed.fields, body, batch_events)
                    }
                    Err(_) => read_answer(None, &[], None, batch_events),
                }
            } else {
                let body_owned: Option<Vec<u8>> = if let Some(encoded) = response.get("body_b64") {
                    Some(
                        base64::engine::general_purpose::STANDARD
                            .decode(encoded.as_str().unwrap())
                            .expect("body_b64 decodes"),
                    )
                } else if let Some(raw) = response.get("body_raw") {
                    Some(raw.as_str().unwrap().as_bytes().to_vec())
                } else {
                    response
                        .get("body")
                        .map(|value| serde_json::to_vec(value).unwrap())
                };
                let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
                for (key, name) in [
                    ("content_type", "Content-Type"),
                    ("www_authenticate", "WWW-Authenticate"),
                    ("content_encoding", "Content-Encoding"),
                ] {
                    let values: Vec<&str> = match response.get(key) {
                        Some(JsonValue::String(value)) => vec![value.as_str()],
                        Some(JsonValue::Array(values)) => {
                            values.iter().map(|v| v.as_str().unwrap()).collect()
                        }
                        _ => Vec::new(),
                    };
                    for value in values {
                        // Latin-1, as the Python harness encodes it.
                        fields.push((
                            name.to_string(),
                            value.chars().map(|c| c as u32 as u8).collect(),
                        ));
                    }
                }
                read_answer(
                    Some(response["status"].as_u64().unwrap() as u16),
                    &fields,
                    body_owned.as_deref(),
                    batch_events,
                )
            };

            assert_eq!(
                verdict.outcome,
                outcome_from(expect["outcome"].as_str().unwrap()),
                "{name}: {}\ngot reason: {}",
                case["why"].as_str().unwrap_or(""),
                verdict.reason
            );
            assert_eq!(
                verdict.declined_events,
                expect["declined_events"].as_u64().unwrap() as usize,
                "{name}: declined_events"
            );
            assert_eq!(
                verdict.refused_events,
                expect["refused_events"].as_u64().unwrap() as usize,
                "{name}: refused_events"
            );
            assert_eq!(
                verdict.receiver_answered,
                expect["receiver_answered"].as_bool().unwrap(),
                "{name}: receiver_answered"
            );
            if let Some(expected) = expect.get("body_unreadable").and_then(|v| v.as_bool()) {
                assert_eq!(verdict.body_unreadable, expected, "{name}: body_unreadable");
            }
            if let Some(expected) = expect.get("duplicate_events").and_then(|v| v.as_u64()) {
                assert_eq!(
                    verdict.duplicate_events, expected as usize,
                    "{name}: duplicate_events"
                );
            }
            if let Some(expected) = expect.get("nonconformant_body").and_then(|v| v.as_bool()) {
                assert_eq!(
                    verdict.nonconformant_body, expected,
                    "{name}: nonconformant"
                );
            }
        }
    }

    #[test]
    fn the_vector_set_covers_all_three_outcomes() {
        // A table that exercised one branch would pass while two went unread.
        let contract: JsonValue = serde_json::from_str(VECTORS).unwrap();
        let mut seen = [false; 3];
        for case in contract["cases"].as_array().unwrap() {
            match outcome_from(case["expect"]["outcome"].as_str().unwrap()) {
                DeliveryOutcome::Delivered => seen[0] = true,
                DeliveryOutcome::Retain => seen[1] = true,
                DeliveryOutcome::Suspend => seen[2] = true,
            }
        }
        assert!(seen.iter().all(|reached| *reached));
    }

    #[test]
    fn suspension_needs_every_recorded_property_of_the_refusal() {
        // Written as the loss of one property at a time rather than as one
        // happy case, because a check that required only the status would pass
        // a test that supplied all four.
        let good = br#"{"detail":"device is suspended"}"#;
        assert_eq!(
            read_batch_response(Some(403), "application/json", None, Some(good), 1).outcome,
            DeliveryOutcome::Suspend
        );

        let weakened = [
            read_batch_response(Some(401), "application/json", None, Some(good), 1),
            read_batch_response(Some(403), "text/html", None, Some(good), 1),
            read_batch_response(
                Some(403),
                "application/json",
                Some("Bearer realm=\"api\""),
                Some(good),
                1,
            ),
            read_batch_response(
                Some(403),
                "application/json",
                None,
                Some(br#"{"detail":"access denied"}"#),
                1,
            ),
            read_batch_response(Some(403), "application/json", None, Some(b""), 1),
        ];
        for verdict in weakened {
            assert_ne!(
                verdict.outcome,
                DeliveryOutcome::Suspend,
                "{}",
                verdict.reason
            );
        }
    }

    #[test]
    fn no_answer_is_ever_a_reason_to_stop() {
        for status in [
            200u16, 201, 204, 301, 400, 401, 403, 404, 410, 415, 422, 429, 500, 503,
        ] {
            let verdict = read_batch_response(Some(status), "text/plain", None, Some(b"x"), 1);
            // Reaching here at all is the assertion: no status returns an error.
            assert!(matches!(
                verdict.outcome,
                DeliveryOutcome::Delivered | DeliveryOutcome::Retain | DeliveryOutcome::Suspend
            ));
        }
    }

    #[test]
    fn an_empty_batch_is_refused_without_ending_the_process() {
        // `Exporter::flush` promises no path through it ends the process, so
        // this must return a verdict rather than panic in a release build.
        let verdict = read_batch_response(Some(200), "application/json", None, None, 0);
        assert_eq!(verdict.outcome, DeliveryOutcome::Retain);
    }

    #[test]
    fn a_body_beyond_the_ceiling_is_unreadable_rather_than_parsed() {
        let mut body = br#"{"status":"accepted","accepted_events":1,"duplicate_events":0,"rejected_events":[],"pad":""#.to_vec();
        body.extend(std::iter::repeat_n(b'x', MAX_RESPONSE_BYTES));
        body.extend_from_slice(br#""}"#);
        let verdict = read_batch_response(Some(200), "application/json", None, Some(&body), 1);
        assert_eq!(verdict.outcome, DeliveryOutcome::Retain);
    }
}
