// Copyright 2026 Ori Nexus Systems LTD
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

mod delivery;
mod export;
mod http;
mod sensor_status;
use delivery::{
    body_is_wanted, read_answer, read_batch_response, DeliveryVerdict, MAX_RESPONSE_BYTES,
};
use export::Exporter;
use sensor_status::{
    read_status_answer, read_status_response, ReadFailure, StatusOutcome, StatusReason,
    StatusTracker,
};

const CONFIG_SIGNATURE_SCHEMA: &str = "ori.config_signature.v1";
const CONFIG_REQUIRE_SIGNED_ENV: &str = "ORI_CONFIG_REQUIRE_SIGNED";
const DEFAULT_CONFIG_TRUST_ANCHOR_ENV: &str = "ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64";
const TELEMETRY_SCHEMA_VERSION: &str = "runtime.telemetry.v1";
const JSON_SAFE_INT_MAX: u64 = 9_007_199_254_740_991;
const USER_AGENT: &str = "ori-runtime-mobile/0.1";
/// How often the export state is restated when nothing about it has changed,
/// so a reader can tell a quiet payload from a stopped one.
const REPORT_INTERVAL: Duration = Duration::from_secs(60);

type HmacSha256 = Hmac<Sha256>;

/// A configuration or start-up refusal, which is a different fact from a
/// runtime that stopped. The hosting application needs to tell an operator
/// which one it is, and a single exit code could not.
const EXIT_STARTUP_REFUSED: i32 = 2;

fn main() {
    if let Err(error) = run() {
        eprintln!("[ori-runtime-mobile] {error}");
        // Every error reaching here is from start-up: once the poll loop
        // begins, a telemetry fault is retained and retried rather than
        // returned, so the loop has no error path out.
        std::process::exit(EXIT_STARTUP_REFUSED);
    }
}

fn run() -> Result<(), String> {
    let args = Args::parse(env::args().skip(1).collect())?;
    let raw_config = fs::read_to_string(&args.config_path)
        .map_err(|error| format!("failed to read config: {error}"))?;
    let raw_yaml: YamlValue = serde_yaml::from_str(&raw_config)
        .map_err(|error| format!("failed to parse config YAML: {error}"))?;
    verify_config_signature(&raw_yaml)?;

    let config: RuntimeConfig = serde_yaml::from_str(&raw_config)
        .map_err(|error| format!("failed to decode runtime config: {error}"))?;
    config.validate_phone_authority()?;

    let api_key = env::var(&config.telemetry_export.api_key_env)
        .map_err(|_| "telemetry API key environment variable is not set".to_string())?;
    if api_key.trim().is_empty() {
        return Err("telemetry API key environment variable is empty".to_string());
    }

    let sensors = config.usb_socket_sensors()?;
    if sensors.is_empty() {
        return Err("no usb_serial socket:// sensors are configured".to_string());
    }

    let mut exporter = Exporter::new(
        config.telemetry_export.batch_size(),
        config.telemetry_export.max_queue_size(),
    );
    // Every declared sensor, not only the ones this payload reads: a snapshot
    // names each of them, and one this payload cannot read is reported so.
    let mut status = StatusTracker::new(
        config
            .sensors
            .iter()
            .map(|sensor| (sensor.id.as_str(), sensor.sensor_type.as_str())),
        config.telemetry_export.flush_interval(),
    );
    for declared in &config.sensors {
        if !sensors.iter().any(|read| read.id == declared.id) {
            status.mark_not_configured(&declared.id);
        }
    }
    let poll_interval = Duration::from_millis(config.min_poll_interval_ms());
    let mut last_reported = (exporter.counters().clone(), status.counters().clone());
    let mut last_held = (exporter.queued_events(), exporter.retained_events());
    let mut last_report_at = Instant::now();

    loop {
        for sensor in &sensors {
            match read_pzem_sensor(sensor) {
                Ok(reading) => {
                    status.record_success(&sensor.id, reading.timestamp);
                    exporter.enqueue(sensor_event(&config.device.id, reading));
                }
                Err(failure) => {
                    status.record_failure(&sensor.id, failure.reason);
                    eprintln!(
                        "[ori-runtime-mobile] sensor_id={} read failed: {failure}",
                        sensor.id
                    );
                }
            }
        }

        // Reading the meter is never gated on the network. A failed upload is
        // retained and retried on a backoff; it does not return out of here,
        // and it does not stop the next poll.
        let now = Instant::now();
        if exporter.has_pending() && exporter.attempt_due(now) {
            exporter.flush(now, |batch| send_batch(&config, &api_key, batch));
        }

        // After the readings, so a snapshot never delays one. A suspension on
        // either route covers both, so a suspended payload sends no status.
        // Timed from here rather than from before the flush, so a slow upload
        // does not bring the next interval snapshot forward.
        let status_now = Instant::now();
        if !exporter.is_suspended() && status.snapshot_due(status_now) {
            let snapshot = status.take_snapshot(&config.device.id, now_ms(), status_now);
            let outcome = send_status(&config, &api_key, &snapshot, status.declared_sensors());
            if outcome == StatusOutcome::Suspend {
                exporter.suspend(status_now, "sensor-status");
            }
            status.record_outcome(outcome);
        }

        // Reported whenever it changes rather than only on the way out, because
        // the hosting application stops this payload with a signal and would
        // otherwise never see a final line. What is dropped, queued, retained
        // or refused is a fact an operator needs while it is happening.
        //
        // The held counts are part of what "changes" here, not only the
        // counters: a payload retrying one batch against an endpoint that never
        // accepts moves no counter at all, and that is exactly the state worth
        // reporting. The interval then covers a steady state, which changes
        // nothing and still needs saying.
        let held = (exporter.queued_events(), exporter.retained_events());
        if exporter.counters() != &last_reported.0
            || status.counters() != &last_reported.1
            || held != last_held
            || now.duration_since(last_report_at) >= REPORT_INTERVAL
        {
            report_export_state(&exporter, &status, false);
            last_reported = (exporter.counters().clone(), status.counters().clone());
            last_held = held;
            last_report_at = now;
        }

        if args.once {
            break;
        }
        thread::sleep(poll_interval);
    }

    report_export_state(&exporter, &status, args.once);
    Ok(())
}

/// What the payload is holding and what it has lost, on one line.
///
/// Under `--once` an undelivered batch is not carried anywhere: the process is
/// about to end and nothing here is durable, so it is reported rather than
/// silently discarded.
fn report_export_state(exporter: &Exporter, status: &StatusTracker, once: bool) {
    let counters = exporter.counters();
    let status_counters = status.counters();
    eprintln!(
        "[ori-runtime-mobile] export state: delivered={} duplicate={} declined={} unconfirmed={} \
         dropped={} refused={} queued={} retained={} suspended={} \
         unreadable_responses={} nonconformant_responses={} \
         status_accepted={} status_discarded={} status_rejected_sensors={}",
        counters.delivered_events,
        counters.duplicate_events,
        counters.declined_events,
        counters.unconfirmed_events,
        counters.dropped_events,
        counters.refused_events,
        exporter.queued_events(),
        exporter.retained_events(),
        exporter.is_suspended(),
        counters.unreadable_responses,
        counters.nonconformant_responses,
        status_counters.accepted_snapshots,
        status_counters.discarded_snapshots,
        status_counters.rejected_sensor_entries,
    );
    if once && (exporter.queued_events() > 0 || exporter.retained_events() > 0) {
        eprintln!(
            "[ori-runtime-mobile] --once is ending with {} reading(s) undelivered; \
             nothing here is durable, so they are lost",
            exporter.queued_events() + exporter.retained_events()
        );
    }
}

/// Post one batch and read the answer. Returns None when the batch cannot be
/// sent at all, which is this payload's own loss rather than a refusal.
fn send_batch(
    config: &RuntimeConfig,
    api_key: &str,
    batch: &export::PendingBatch,
) -> Option<DeliveryVerdict> {
    let payload = json!({
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "device_id": config.device.id.as_str(),
        "sequence": batch.sequence,
        "sent_at_ms": now_ms(),
        "events": batch.events,
    });
    let body = match canonical_telemetry_json(&payload) {
        Ok(body) => body,
        Err(error) => {
            eprintln!(
                "[ori-runtime-mobile] batch sequence={} cannot be canonicalised: {error}",
                batch.sequence
            );
            return None;
        }
    };
    let timestamp_ms = now_ms().to_string();
    let signature = match telemetry_signature(api_key.as_bytes(), timestamp_ms.as_bytes(), &body) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!(
                "[ori-runtime-mobile] batch sequence={} cannot be signed: {error}",
                batch.sequence
            );
            return None;
        }
    };

    let batch_events = batch.events.len();
    let response = match signed_post(
        config,
        api_key,
        &config.telemetry_export.endpoint,
        &body,
        &timestamp_ms,
        &signature,
    ) {
        Ok(response) => response,
        Err(error) => {
            eprintln!(
                "[ori-runtime-mobile] telemetry POST for batch sequence={} got no answer: {error}",
                batch.sequence
            );
            return Some(read_batch_response(None, "", None, None, batch_events));
        }
    };
    let body = match &response.body {
        http::Body::Complete(bytes) => Some(bytes.as_slice()),
        http::Body::PastCeiling => {
            eprintln!(
                "[ori-runtime-mobile] response body exceeds the {MAX_RESPONSE_BYTES}-byte \
                 ceiling; batch sequence={} retained",
                batch.sequence
            );
            None
        }
        http::Body::NotRead => {
            if response.status != 101 {
                eprintln!(
                    "[ori-runtime-mobile] response body not read: its header section is not \
                     readable alike, it is content-coded, or it declares more than the \
                     {MAX_RESPONSE_BYTES}-byte ceiling; batch sequence={} retained",
                    batch.sequence
                );
            }
            None
        }
    };
    Some(read_answer(
        Some(response.status),
        &response.fields,
        body,
        batch_events,
    ))
}

/// Post one sensor-status snapshot and read the answer.
///
/// A snapshot that cannot be canonicalised or signed is discarded like any
/// other that is not accepted: it is state, and the next one supersedes it.
fn send_status(
    config: &RuntimeConfig,
    api_key: &str,
    snapshot: &JsonValue,
    sensors_sent: usize,
) -> StatusOutcome {
    let discarded = StatusOutcome::Discarded;
    let body = match canonical_telemetry_json(snapshot) {
        Ok(body) => body,
        Err(error) => {
            eprintln!("[ori-runtime-mobile] sensor status cannot be canonicalised: {error}");
            return discarded;
        }
    };
    let timestamp_ms = now_ms().to_string();
    let signature = match telemetry_signature(api_key.as_bytes(), timestamp_ms.as_bytes(), &body) {
        Ok(signature) => signature,
        Err(error) => {
            eprintln!("[ori-runtime-mobile] sensor status cannot be signed: {error}");
            return discarded;
        }
    };
    let url = status_route(&config.telemetry_export.endpoint);
    let outcome = match signed_post(config, api_key, &url, &body, &timestamp_ms, &signature) {
        Ok(response) => {
            let body = match &response.body {
                http::Body::Complete(bytes) => Some(bytes.as_slice()),
                _ => None,
            };
            read_status_answer(response.status, &response.fields, body, sensors_sent)
        }
        Err(error) => {
            eprintln!("[ori-runtime-mobile] sensor status POST got no answer: {error}");
            read_status_response(None, "", None, None, sensors_sent)
        }
    };
    if let StatusOutcome::Accepted { rejected_sensors } = outcome {
        if rejected_sensors > 0 {
            eprintln!(
                "[ori-runtime-mobile] receiver rejected {rejected_sensors} sensor status \
                 entr{}; not retried, the next snapshot supersedes them",
                if rejected_sensors == 1 { "y" } else { "ies" }
            );
        }
    }
    if outcome == StatusOutcome::Discarded {
        eprintln!(
            "[ori-runtime-mobile] sensor status snapshot was not accepted and is discarded; \
             the next snapshot supersedes it"
        );
    }
    outcome
}

/// The sensor-status route: the reading endpoint with the suffix appended, as
/// the contract states it. There is no second configuration key.
fn status_route(endpoint: &str) -> String {
    format!("{endpoint}{}", sensor_status::STATUS_ROUTE_SUFFIX)
}

/// Post signed bytes to `url` through the telemetry client.
///
/// Both routes use this, so the headers they send and the ceiling and parser
/// they read the answer with cannot differ.
fn signed_post(
    config: &RuntimeConfig,
    api_key: &str,
    url: &str,
    body: &[u8],
    timestamp_ms: &str,
    signature: &str,
) -> Result<http::Response, String> {
    let authorization = format!("Bearer {api_key}");
    let signature_header = format!("v1={signature}");
    let headers = [
        ("Authorization", authorization.as_str()),
        ("Content-Type", "application/json"),
        // No coding is accepted, so none is decoded: the size ceiling then
        // bounds the bytes that actually arrive.
        ("Accept-Encoding", "identity"),
        ("User-Agent", USER_AGENT),
        ("X-Ori-Device-Id", config.device.id.as_str()),
        ("X-Ori-Timestamp-Ms", timestamp_ms),
        ("X-Ori-Signature", signature_header.as_str()),
    ];
    http::post(
        url,
        &headers,
        body,
        Duration::from_millis(config.telemetry_export.timeout_ms.max(100)),
        MAX_RESPONSE_BYTES,
        |_, fields| body_is_wanted(fields),
    )
}

#[derive(Debug)]
struct Args {
    config_path: PathBuf,
    once: bool,
}

impl Args {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config_path: Option<PathBuf> = None;
        let mut once = false;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--config" => {
                    i += 1;
                    let value = args
                        .get(i)
                        .ok_or_else(|| "--config requires a path".to_string())?;
                    config_path = Some(PathBuf::from(value));
                }
                "--once" => once = true,
                "--help" | "-h" => {
                    println!("Usage: ori-runtime-mobile --config <ori.yaml> [--once]");
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument {other:?}")),
            }
            i += 1;
        }
        Ok(Self {
            config_path: config_path.ok_or_else(|| "--config is required".to_string())?,
            once,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RuntimeConfig {
    device: DeviceConfig,
    sensors: Vec<SensorConfig>,
    telemetry_export: TelemetryExportConfig,
}

impl RuntimeConfig {
    fn validate_phone_authority(&self) -> Result<(), String> {
        if self.device.deployment_type != "phone" {
            return Err("ori-runtime-mobile only accepts device.deployment_type=phone".to_string());
        }
        if !self.telemetry_export.enabled {
            return Err("telemetry_export.enabled must be true".to_string());
        }
        validate_https_or_loopback(&self.telemetry_export.endpoint)?;
        validate_env_name(&self.telemetry_export.api_key_env)?;
        // Refused rather than clamped, as the Python runtime refuses it. NaN is
        // outside the range too, and could not become a duration at all.
        let interval = self.telemetry_export.flush_interval_s;
        if !(1.0..=300.0).contains(&interval) {
            return Err(
                "telemetry_export.flush_interval_s must be between 1 and 300 seconds".to_string(),
            );
        }
        Ok(())
    }

    fn usb_socket_sensors(&self) -> Result<Vec<&SensorConfig>, String> {
        // A status snapshot names each declared sensor once. Two sharing an id
        // would report two states under one name, and a receiver would keep
        // whichever it read last.
        for (index, sensor) in self.sensors.iter().enumerate() {
            if self.sensors[..index]
                .iter()
                .any(|seen| seen.id == sensor.id)
            {
                return Err(format!(
                    "sensor_id={} is declared more than once",
                    sensor.id
                ));
            }
        }
        let mut sensors = Vec::new();
        for sensor in &self.sensors {
            if sensor.protocol != "usb_serial" {
                continue;
            }
            if !sensor.device_path.starts_with("socket://") {
                return Err(format!(
                    "sensor_id={} uses usb_serial but not socket://; Android USB permission must stay in the Java bridge",
                    sensor.id
                ));
            }
            socket_target(&sensor.device_path)
                .map_err(|error| format!("sensor_id={}: {error}", sensor.id))?;
            validate_supported_pzem_type(&sensor.sensor_type)?;
            sensors.push(sensor);
        }
        Ok(sensors)
    }

    fn min_poll_interval_ms(&self) -> u64 {
        self.sensors
            .iter()
            .map(|sensor| sensor.poll_interval_ms.max(100) as u64)
            .min()
            .unwrap_or(2000)
    }
}

#[derive(Debug, Deserialize)]
struct DeviceConfig {
    id: String,
    deployment_type: String,
}

#[derive(Debug, Deserialize)]
struct SensorConfig {
    id: String,
    #[serde(rename = "type")]
    sensor_type: String,
    protocol: String,
    device_path: String,
    #[serde(default = "default_poll_interval_ms")]
    poll_interval_ms: u32,
    #[serde(default = "default_slave_id")]
    slave_id: u8,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

#[derive(Debug, Deserialize)]
struct TelemetryExportConfig {
    enabled: bool,
    endpoint: String,
    api_key_env: String,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_batch_size")]
    batch_size: usize,
    #[serde(default = "default_max_queue_size")]
    max_queue_size: usize,
    #[serde(default = "default_flush_interval_s")]
    flush_interval_s: f64,
}

impl TelemetryExportConfig {
    fn batch_size(&self) -> usize {
        self.batch_size.clamp(1, 500)
    }

    /// The bound on telemetry held in memory, never below one batch: a payload
    /// that could not hold the batch it just formed would drop a reading it had
    /// no opportunity to send.
    fn max_queue_size(&self) -> usize {
        self.max_queue_size.max(self.batch_size())
    }

    /// The configured flush interval. This payload flushes readings on every
    /// poll, so here it bounds only how often an unchanged sensor-status
    /// snapshot is sent. Validated at start-up to the range the Python runtime
    /// accepts.
    fn flush_interval(&self) -> Duration {
        Duration::from_secs_f64(self.flush_interval_s)
    }
}

fn default_flush_interval_s() -> f64 {
    30.0
}

fn default_batch_size() -> usize {
    50
}

fn default_max_queue_size() -> usize {
    1000
}

fn default_poll_interval_ms() -> u32 {
    2000
}

fn default_slave_id() -> u8 {
    1
}

fn default_timeout_ms() -> u64 {
    3000
}

#[derive(Debug)]
struct SensorReading {
    sensor_id: String,
    sensor_type: String,
    value: f64,
    unit: &'static str,
    timestamp: u64,
    quality: f64,
    metadata: BTreeMap<String, JsonValue>,
}

fn read_pzem_sensor(sensor: &SensorConfig) -> Result<SensorReading, ReadFailure> {
    // Start-up checks the target's form and the type. Resolving the target is
    // left to each read, so a target that names nothing is a configuration the
    // payload cannot use, reported as one, rather than a fault it observed.
    let not_configured = |detail: String| ReadFailure::new(StatusReason::NotConfigured, detail);
    let target = socket_target(&sensor.device_path).map_err(not_configured)?;
    let address = target
        .to_socket_addrs()
        .map_err(|error| not_configured(format!("invalid socket target: {error}")))?
        .next()
        .ok_or_else(|| not_configured("socket target resolved to no addresses".to_string()))?;
    let metric = pzem_metric(&sensor.sensor_type).map_err(not_configured)?;

    let timeout = Duration::from_millis(sensor.timeout_ms.max(100));
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| ReadFailure::interface("failed to connect to USB bridge", &error))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| ReadFailure::interface("failed to set write timeout", &error))?;
    let raw = request_registers(&mut stream, sensor.slave_id, &metric, timeout)?;

    let mut metadata = BTreeMap::new();
    metadata.insert("source".to_string(), json!("ori_runtime_mobile"));
    metadata.insert("transport".to_string(), json!("android_usb_bridge"));
    metadata.insert(
        "device_path".to_string(),
        json!(sensor.device_path.as_str()),
    );
    metadata.insert("slave_id".to_string(), json!(sensor.slave_id));
    metadata.insert("register".to_string(), json!(metric.register));
    metadata.insert("raw".to_string(), json!(raw));

    Ok(SensorReading {
        sensor_id: sensor.id.clone(),
        sensor_type: sensor.sensor_type.clone(),
        value: ((raw as f64) * metric.scale * 10_000.0).round() / 10_000.0,
        unit: metric.unit,
        timestamp: now_ms(),
        quality: 1.0,
        metadata,
    })
}

struct PzemMetric {
    register: u16,
    register_count: u16,
    scale: f64,
    unit: &'static str,
}

fn pzem_metric(sensor_type: &str) -> Result<PzemMetric, String> {
    match sensor_type {
        "usb_voltage" => Ok(PzemMetric {
            register: 0x0000,
            register_count: 2,
            scale: 0.1,
            unit: "volt",
        }),
        "usb_current" => Ok(PzemMetric {
            register: 0x0008,
            register_count: 2,
            scale: 0.01,
            unit: "ampere",
        }),
        "usb_power" => Ok(PzemMetric {
            register: 0x0012,
            register_count: 2,
            scale: 0.1,
            unit: "watt",
        }),
        "usb_frequency" => Ok(PzemMetric {
            register: 0x0046,
            register_count: 1,
            scale: 0.1,
            unit: "hertz",
        }),
        "usb_energy" => Ok(PzemMetric {
            register: 0x0100,
            register_count: 2,
            scale: 0.01,
            unit: "kilowatt_hour",
        }),
        _ => Err(format!("unsupported PZEM sensor type {sensor_type:?}")),
    }
}

fn validate_supported_pzem_type(sensor_type: &str) -> Result<(), String> {
    pzem_metric(sensor_type).map(|_| ())
}

fn socket_target(device_path: &str) -> Result<String, String> {
    let rest = device_path
        .strip_prefix("socket://")
        .ok_or_else(|| "device_path must start with socket://".to_string())?;
    let has_port = rest.rsplit_once(':').is_some_and(|(host, port)| {
        !host.trim().is_empty() && port.parse::<u16>().is_ok_and(|port| port != 0)
    });
    if rest.contains('/') || !has_port {
        return Err("socket:// device_path must be host:port".to_string());
    }
    Ok(rest.to_string())
}

fn build_read_request(slave_id: u8, register: u16, count: u16) -> Vec<u8> {
    let mut frame = vec![
        slave_id,
        0x03,
        (register >> 8) as u8,
        (register & 0xff) as u8,
        (count >> 8) as u8,
        (count & 0xff) as u8,
    ];
    let crc = crc16(&frame);
    frame.push((crc & 0xff) as u8);
    frame.push((crc >> 8) as u8);
    frame
}

/// Somewhere an answer is read from, whose wait can be shortened.
///
/// Each read waits no longer than what remains of the exchange's timeout, so
/// the timeout bounds the whole answer and not each byte of it. A bridge that
/// trickles a byte just inside the timeout would otherwise hold this
/// single-threaded loop, and every upload behind it, for a frame's length of
/// timeouts, and be reported as a meter reading normally.
trait AnswerSource: Read {
    fn wait_at_most(&mut self, remaining: Duration) -> std::io::Result<()>;
}

impl AnswerSource for TcpStream {
    fn wait_at_most(&mut self, remaining: Duration) -> std::io::Result<()> {
        self.set_read_timeout(Some(remaining))
    }
}

/// Send one read request and read its answer within `timeout`.
fn request_registers<S: AnswerSource + Write>(
    stream: &mut S,
    slave_id: u8,
    metric: &PzemMetric,
    timeout: Duration,
) -> Result<u32, ReadFailure> {
    let request = build_read_request(slave_id, metric.register, metric.register_count);
    stream
        .write_all(&request)
        .map_err(|error| ReadFailure::interface("failed to write Modbus request", &error))?;
    let deadline = Instant::now() + timeout;
    read_register_frame(stream, slave_id, metric.register_count, deadline)
}

/// Read one holding-register answer, and classify it if it is not one.
///
/// The frame is read in stages rather than as a fixed length, so a meter's
/// Modbus exception -- five bytes, where a reading is seven or nine -- is read
/// as the answer it is instead of waiting out the timeout for bytes that will
/// never come and being reported as a meter that did not answer.
fn read_register_frame<R: AnswerSource>(
    stream: &mut R,
    slave_id: u8,
    register_count: u16,
    deadline: Instant,
) -> Result<u32, ReadFailure> {
    let mut frame: Vec<u8> = Vec::with_capacity(9);
    fill(stream, &mut frame, 2, deadline)?;
    let function = frame[1];

    if function == 0x83 {
        fill(stream, &mut frame, 5, deadline)?;
        check_crc(&frame)?;
        return Err(ReadFailure::new(
            StatusReason::MalformedResponse,
            format!("Modbus exception code 0x{:02X}", frame[2]),
        ));
    }
    if function != 0x03 {
        return Err(ReadFailure::new(
            StatusReason::MalformedResponse,
            format!("unexpected Modbus function 0x{function:02X}"),
        ));
    }

    fill(stream, &mut frame, 3, deadline)?;
    let expected_bytes = register_count as usize * 2;
    if frame[2] as usize != expected_bytes {
        return Err(ReadFailure::new(
            StatusReason::MalformedResponse,
            format!("Modbus byte count {}, expected {expected_bytes}", frame[2]),
        ));
    }
    fill(stream, &mut frame, 3 + expected_bytes + 2, deadline)?;
    check_crc(&frame)?;
    // After the CRC, so an intact frame from the wrong slave is told from a
    // corrupted one.
    if frame[0] != slave_id {
        return Err(ReadFailure::new(
            StatusReason::MalformedResponse,
            format!(
                "Modbus response from slave {}, expected {slave_id}",
                frame[0]
            ),
        ));
    }

    let data = &frame[3..3 + expected_bytes];
    if register_count == 1 {
        Ok(u16::from_be_bytes([data[0], data[1]]) as u32)
    } else {
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }
}

/// Read until `frame` holds `len` bytes by `deadline`, classifying a failure
/// by how much of the answer had arrived.
fn fill<R: AnswerSource>(
    stream: &mut R,
    frame: &mut Vec<u8>,
    len: usize,
    deadline: Instant,
) -> Result<(), ReadFailure> {
    let mut chunk = [0_u8; 16];
    while frame.len() < len {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let timed_out = std::io::Error::from(std::io::ErrorKind::TimedOut);
            return Err(ReadFailure::awaiting_answer(frame.len(), &timed_out));
        }
        stream
            .wait_at_most(remaining)
            .map_err(|error| ReadFailure::interface("failed to set read timeout", &error))?;
        let want = (len - frame.len()).min(chunk.len());
        match stream.read(&mut chunk[..want]) {
            Ok(0) => return Err(ReadFailure::closed_awaiting_answer(frame.len())),
            Ok(read) => frame.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(ReadFailure::awaiting_answer(frame.len(), &error)),
        }
    }
    Ok(())
}

fn check_crc(frame: &[u8]) -> Result<(), ReadFailure> {
    let payload_len = frame.len() - 2;
    let received = u16::from_le_bytes([frame[payload_len], frame[payload_len + 1]]);
    let computed = crc16(&frame[..payload_len]);
    if received != computed {
        return Err(ReadFailure::new(
            StatusReason::IntegrityFailed,
            format!("CRC mismatch: got 0x{received:04X}, computed 0x{computed:04X}"),
        ));
    }
    Ok(())
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0xffff_u16;
    for byte in data {
        crc ^= *byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xa001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

fn sensor_event(device_id: &str, reading: SensorReading) -> JsonValue {
    let fingerprint = compute_fingerprint(device_id, &reading);
    let sensor_id = reading.sensor_id.clone();
    let sensor_type = reading.sensor_type.clone();
    json!({
        "event_id": Uuid::new_v4().to_string(),
        "event_type": "sensor.reading",
        "device_id": device_id,
        "sensor_id": sensor_id.as_str(),
        "timestamp": reading.timestamp,
        "source": "ori_runtime_mobile",
        "fingerprint": fingerprint,
        "context": {},
        "reading": {
            "sensor_id": sensor_id.as_str(),
            "sensor_type": sensor_type.as_str(),
            "value": reading.value,
            "unit": reading.unit,
            "timestamp": reading.timestamp,
            "quality": reading.quality,
            "metadata": reading.metadata,
        }
    })
}

fn telemetry_signature(key: &[u8], timestamp_ms: &[u8], body: &[u8]) -> Result<String, String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|error| format!("failed to initialize HMAC: {error}"))?;
    mac.update(timestamp_ms);
    mac.update(b".");
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn canonical_telemetry_json(value: &JsonValue) -> Result<Vec<u8>, String> {
    validate_canonical_numbers(value, "$")?;
    serde_json::to_vec(value)
        .map_err(|error| format!("failed to serialize telemetry payload: {error}"))
}

fn validate_canonical_numbers(value: &JsonValue, path: &str) -> Result<(), String> {
    match value {
        JsonValue::Number(number) => {
            if let Some(integer) = number.as_i64() {
                if integer.unsigned_abs() > JSON_SAFE_INT_MAX {
                    return Err(format!("integer outside JSON-safe range at {path}"));
                }
            } else if let Some(integer) = number.as_u64() {
                if integer > JSON_SAFE_INT_MAX {
                    return Err(format!("integer outside JSON-safe range at {path}"));
                }
            } else if let Some(number) = number.as_f64() {
                let magnitude = number.abs();
                if !number.is_finite() || (magnitude != 0.0 && !(1e-4..1e16).contains(&magnitude)) {
                    return Err(format!(
                        "float outside cross-language canonical zone at {path}"
                    ));
                }
            } else {
                return Err(format!("unsupported JSON number at {path}"));
            }
        }
        JsonValue::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                validate_canonical_numbers(item, &format!("{path}[{index}]"))?;
            }
        }
        JsonValue::Object(items) => {
            for (key, item) in items {
                validate_canonical_numbers(item, &format!("{path}.{key}"))?;
            }
        }
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::String(_) => {}
    }
    Ok(())
}

fn compute_fingerprint(device_id: &str, reading: &SensorReading) -> String {
    let mut hasher = Sha256::new();
    hasher.update(device_id.as_bytes());
    hasher.update(reading.sensor_id.as_bytes());
    hasher.update(reading.sensor_type.as_bytes());
    hasher.update(format!("{:.1}", reading.value).as_bytes());
    hex::encode(hasher.finalize())
}

fn verify_config_signature(raw_yaml: &YamlValue) -> Result<(), String> {
    let required = env_truthy(CONFIG_REQUIRE_SIGNED_ENV);
    let root = raw_yaml
        .as_mapping()
        .ok_or_else(|| "runtime config must be a mapping".to_string())?;
    let signature_block = root
        .get(YamlValue::String("config_signature".to_string()))
        .ok_or_else(|| {
            if required {
                "missing config_signature block".to_string()
            } else {
                "ori-runtime-mobile requires a signed config".to_string()
            }
        })?;
    let signature_map = signature_block
        .as_mapping()
        .ok_or_else(|| "config_signature must be a mapping".to_string())?;

    let schema = yaml_string(signature_map, "schema")?;
    if schema != CONFIG_SIGNATURE_SCHEMA {
        return Err(format!(
            "config_signature.schema must be {CONFIG_SIGNATURE_SCHEMA}"
        ));
    }
    let signer_id = yaml_string(signature_map, "signer_id")?;
    if signer_id.trim().is_empty() {
        return Err("config_signature.signer_id is required".to_string());
    }
    let signed_at_ms = yaml_i64(signature_map, "signed_at_ms")?;
    if signed_at_ms <= 0 {
        return Err("config_signature.signed_at_ms must be > 0".to_string());
    }
    let signature = yaml_string(signature_map, "signature")?;
    let signature_b64 = signature
        .strip_prefix("ed25519:")
        .ok_or_else(|| "config_signature.signature must use ed25519:<base64>".to_string())?;

    let trust_anchor_env = config_trust_anchor_env(raw_yaml)?;
    validate_env_name(&trust_anchor_env)?;
    let public_key_b64 = env::var(&trust_anchor_env)
        .map_err(|_| "config signature trust anchor environment variable is not set".to_string())?;

    let signature_bytes = base64_decode(signature_b64, "config signature")?;
    let public_key_bytes = base64_decode(&public_key_b64, "config trust anchor")?;
    let verifying_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "config trust anchor must decode to 32 bytes".to_string())?,
    )
    .map_err(|error| format!("invalid Ed25519 trust anchor: {error}"))?;
    let ed25519_signature = Signature::from_slice(&signature_bytes)
        .map_err(|error| format!("invalid Ed25519 signature: {error}"))?;
    verifying_key
        .verify(
            &canonical_config_signature_payload(raw_yaml)?,
            &ed25519_signature,
        )
        .map_err(|error| format!("config signature verification failed: {error}"))?;
    Ok(())
}

fn canonical_config_signature_payload(raw_yaml: &YamlValue) -> Result<Vec<u8>, String> {
    let root = raw_yaml
        .as_mapping()
        .ok_or_else(|| "runtime config must be a mapping".to_string())?;
    let signature_block = root
        .get(YamlValue::String("config_signature".to_string()))
        .ok_or_else(|| "config_signature must be present".to_string())?;
    let signature_map = signature_block
        .as_mapping()
        .ok_or_else(|| "config_signature must be a mapping".to_string())?;

    let mut unsigned = serde_yaml::Mapping::new();
    for (key, value) in root {
        if key == &YamlValue::String("config_signature".to_string()) {
            continue;
        }
        unsigned.insert(key.clone(), value.clone());
    }
    let envelope = json!({
        "config": yaml_to_json(&YamlValue::Mapping(unsigned))?,
        "schema": yaml_string(signature_map, "schema")?,
        "signed_at_ms": yaml_i64(signature_map, "signed_at_ms")?,
        "signer_id": yaml_string(signature_map, "signer_id")?,
    });
    serde_json::to_vec(&envelope)
        .map_err(|error| format!("failed to serialize signature payload: {error}"))
}

fn config_trust_anchor_env(raw_yaml: &YamlValue) -> Result<String, String> {
    if let Ok(override_env) = env::var("ORI_CONFIG_TRUST_ANCHOR_ENV") {
        if !override_env.trim().is_empty() {
            return Ok(override_env);
        }
    }
    let Some(security) = raw_yaml
        .as_mapping()
        .and_then(|root| root.get(YamlValue::String("security".to_string())))
        .and_then(YamlValue::as_mapping)
    else {
        return Ok(DEFAULT_CONFIG_TRUST_ANCHOR_ENV.to_string());
    };
    let Some(config_signature) = security
        .get(YamlValue::String("config_signature".to_string()))
        .and_then(YamlValue::as_mapping)
    else {
        return Ok(DEFAULT_CONFIG_TRUST_ANCHOR_ENV.to_string());
    };
    match config_signature.get(YamlValue::String("trust_anchor_env".to_string())) {
        Some(value) => value.as_str().map(str::to_string).ok_or_else(|| {
            "security.config_signature.trust_anchor_env must be a string".to_string()
        }),
        None => Ok(DEFAULT_CONFIG_TRUST_ANCHOR_ENV.to_string()),
    }
}

fn yaml_to_json(value: &YamlValue) -> Result<JsonValue, String> {
    serde_json::to_value(value).map_err(|error| format!("failed to convert YAML: {error}"))
}

fn yaml_string(map: &serde_yaml::Mapping, key: &str) -> Result<String, String> {
    map.get(YamlValue::String(key.to_string()))
        .and_then(YamlValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("config_signature.{key} is required"))
}

fn yaml_i64(map: &serde_yaml::Mapping, key: &str) -> Result<i64, String> {
    map.get(YamlValue::String(key.to_string()))
        .and_then(YamlValue::as_i64)
        .ok_or_else(|| format!("config_signature.{key} must be an integer"))
}

fn base64_decode(value: &str, label: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|error| format!("{label} is not valid base64: {error}"))
}

fn validate_https_or_loopback(endpoint: &str) -> Result<(), String> {
    if endpoint.starts_with("https://") {
        return Ok(());
    }
    if endpoint.starts_with("http://127.0.0.1:")
        || endpoint.starts_with("http://localhost:")
        || endpoint.starts_with("http://[::1]:")
    {
        return Ok(());
    }
    Err("telemetry_export.endpoint must use https:// unless it targets loopback".to_string())
}

fn validate_env_name(value: &str) -> Result<(), String> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err("environment variable name is empty".to_string());
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(format!("invalid environment variable name {value:?}"));
    }
    if chars.any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric())) {
        return Err(format!("invalid environment variable name {value:?}"));
    }
    Ok(())
}

fn env_truthy(name: &str) -> bool {
    match env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_BODY: &str = concat!(
        "{\"device_id\":\"phone-gateway-ikeja-01\",\"events\":[{\"context\":{\"location\":\"Ìkẹjà\"},",
        "\"device_id\":\"phone-gateway-ikeja-01\",\"event_id\":\"00000000-0000-4000-8000-000000000001\",",
        "\"event_type\":\"sensor.reading\",\"fingerprint\":\"\",\"reading\":{\"metadata\":{\"label\":\"Mains – east\"},",
        "\"quality\":1.0,\"sensor_id\":\"phone-main-power\",\"sensor_type\":\"usb_power\",",
        "\"timestamp\":1719000000000,\"unit\":\"watt\",\"value\":1240.5},\"sensor_id\":\"phone-main-power\",",
        "\"source\":\"usb_serial\",\"timestamp\":1719000000000}],\"schema_version\":\"runtime.telemetry.v1\",",
        "\"sent_at_ms\":1719000000000,\"sequence\":1}"
    );

    #[test]
    fn runtime_telemetry_matches_specs_golden_fixture() {
        let payload: JsonValue = serde_json::from_str(GOLDEN_BODY).expect("valid fixture");
        let body = canonical_telemetry_json(&payload).expect("canonical fixture");
        assert_eq!(body, GOLDEN_BODY.as_bytes());
        assert_eq!(
            hex::encode(Sha256::digest(&body)),
            "51e7a268d28c96f7ba516593b7d4ca160848ff641888ce1b3b513f2bbf2370ea"
        );
        assert_eq!(
            telemetry_signature(b"test-runtime-telemetry-key", b"1719000000123", &body)
                .expect("HMAC"),
            "5ed66b6fc38a5d68e8c0c16bf18ade62968549432fb52baeb8b56625927dba79"
        );
    }

    #[test]
    fn runtime_telemetry_rejects_numbers_outside_agreement_zone() {
        assert!(canonical_telemetry_json(&json!({"value": 1e-5})).is_err());
        assert!(canonical_telemetry_json(&json!({"value": 9_007_199_254_740_992_u64})).is_err());
    }

    /// A valid PZEM frame for `slave`, function 0x03, carrying `data`.
    fn frame(slave: u8, data: &[u8]) -> Vec<u8> {
        let mut bytes = vec![slave, 0x03, data.len() as u8];
        bytes.extend_from_slice(data);
        let crc = crc16(&bytes);
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes
    }

    /// Yields its bytes, then fails with `then` instead of ending.
    struct Stalls {
        bytes: std::io::Cursor<Vec<u8>>,
        then: std::io::ErrorKind,
    }

    impl Read for Stalls {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.bytes.read(buf)? {
                0 => Err(std::io::Error::from(self.then)),
                read => Ok(read),
            }
        }
    }

    impl AnswerSource for Stalls {
        fn wait_at_most(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl AnswerSource for std::io::Cursor<Vec<u8>> {
        fn wait_at_most(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn classify(bytes: Vec<u8>, count: u16) -> Result<u32, StatusReason> {
        read_register_frame(&mut std::io::Cursor::new(bytes), 1, count, soon())
            .map_err(|f| f.reason)
    }

    fn stalled(bytes: Vec<u8>, then: std::io::ErrorKind) -> StatusReason {
        let mut reader = Stalls {
            bytes: std::io::Cursor::new(bytes),
            then,
        };
        read_register_frame(&mut reader, 1, 2, soon())
            .unwrap_err()
            .reason
    }

    /// Fails its first read with `Interrupted`, then yields its bytes.
    struct InterruptedOnce {
        bytes: std::io::Cursor<Vec<u8>>,
        interrupted: bool,
    }

    impl Read for InterruptedOnce {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(std::io::Error::from(std::io::ErrorKind::Interrupted));
            }
            self.bytes.read(buf)
        }
    }

    impl AnswerSource for InterruptedOnce {
        fn wait_at_most(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// A bridge whose socket refuses the request.
    struct RefusesWrites;

    impl Read for RefusesWrites {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            panic!("nothing is read after a failed write")
        }
    }

    impl Write for RefusesWrites {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl AnswerSource for RefusesWrites {
        fn wait_at_most(&mut self, _remaining: Duration) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn an_interrupted_read_is_retried() {
        let mut reader = InterruptedOnce {
            bytes: std::io::Cursor::new(frame(1, &[0, 0, 0x04, 0xD2])),
            interrupted: false,
        };
        assert_eq!(
            read_register_frame(&mut reader, 1, 2, soon()).map_err(|f| f.reason),
            Ok(1234)
        );
    }

    #[test]
    fn bytes_after_the_frame_are_not_read_into_it() {
        let mut bytes = frame(1, &[0, 0, 0x04, 0xD2]);
        bytes.extend_from_slice(&[0xAA; 20]);
        assert_eq!(classify(bytes, 2), Ok(1234));
    }

    #[test]
    fn a_byte_count_the_registers_do_not_explain_is_refused_before_reading_on() {
        // 255 bytes follow, so a reader that trusted the count would read them
        // all and report a CRC failure instead of the malformed frame it is.
        let mut bytes = vec![0x01, 0x03, 0xFF];
        bytes.extend_from_slice(&[0x00; 257]);
        assert_eq!(classify(bytes, 2), Err(StatusReason::MalformedResponse));
    }

    #[test]
    fn a_request_the_bridge_will_not_take_is_the_interface() {
        let metric = pzem_metric("usb_power").unwrap();
        let failure =
            request_registers(&mut RefusesWrites, 1, &metric, Duration::from_secs(1)).unwrap_err();
        assert_eq!(failure.reason, StatusReason::InterfaceAbsent);
    }

    #[test]
    fn a_target_that_resolves_to_nothing_is_not_configured() {
        let mut sensor = socket_sensor(9);
        sensor.device_path = "socket://[not-an-address:9".to_string();
        let failure = read_pzem_sensor(&sensor).unwrap_err();
        assert_eq!(failure.reason, StatusReason::NotConfigured);
    }

    /// A bridge that reads the request, sends `sent`, and then holds the
    /// connection without another byte.
    fn bridge_sending_then_silent(sent: Vec<u8>) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 8];
                if stream.read_exact(&mut request).is_ok() && stream.write_all(&sent).is_ok() {
                    thread::sleep(Duration::from_secs(5));
                }
            }
        });
        port
    }

    #[test]
    fn a_wait_after_part_of_an_answer_is_what_remains_of_the_timeout() {
        // Two bytes, then nothing. Each wait is shortened to what remains, so
        // the read ends at the timeout rather than a full timeout after the
        // last byte arrived.
        let mut sensor = socket_sensor(bridge_sending_then_silent(vec![0x01, 0x03]));
        sensor.timeout_ms = 250;
        let started = Instant::now();
        let failure = read_pzem_sensor(&sensor).unwrap_err();
        assert_eq!(failure.reason, StatusReason::MalformedResponse);
        assert!(
            started.elapsed() < Duration::from_millis(600),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_deadline_already_passed_is_no_response_not_the_interface() {
        // A zero wait is refused by the socket itself, which would otherwise be
        // reported as the interface failing.
        let port = bridge_sending_then_silent(Vec::new());
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        stream.write_all(&[0_u8; 8]).expect("request");
        let passed = Instant::now() - Duration::from_millis(1);
        let failure = read_register_frame(&mut stream, 1, 2, passed).unwrap_err();
        assert_eq!(failure.reason, StatusReason::NoResponse);
    }

    #[test]
    fn a_bridge_trickling_an_answer_is_bounded_by_the_timeout_in_total() {
        // One byte every 100 ms against a 250 ms timeout: each byte arrives in
        // time, the frame does not. Bounded per byte, this read took most of a
        // second and was a reading; bounded in total, it is part of an answer.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0_u8; 8];
                if stream.read_exact(&mut request).is_ok() {
                    for byte in frame(1, &[0, 0, 0x04, 0xD2]) {
                        thread::sleep(Duration::from_millis(100));
                        if stream.write_all(&[byte]).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let mut sensor = socket_sensor(port);
        sensor.timeout_ms = 250;
        let started = Instant::now();
        let failure = read_pzem_sensor(&sensor).unwrap_err();
        let took = started.elapsed();
        assert_eq!(failure.reason, StatusReason::MalformedResponse);
        assert!(took < Duration::from_millis(600), "took {took:?}");
    }

    #[test]
    fn a_valid_frame_is_read() {
        assert_eq!(classify(frame(1, &[0, 0, 0x04, 0xD2]), 2), Ok(1234));
        assert_eq!(classify(frame(1, &[0x01, 0xF4]), 1), Ok(500));
    }

    #[test]
    fn each_malformed_frame_is_classified_by_what_arrived() {
        let mut corrupt = frame(1, &[0, 0, 0x04, 0xD2]);
        corrupt[4] ^= 0xFF;
        assert_eq!(classify(corrupt, 2), Err(StatusReason::IntegrityFailed));

        let mut exception = vec![0x01, 0x83, 0x02];
        let crc = crc16(&exception);
        exception.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(
            classify(exception.clone(), 2),
            Err(StatusReason::MalformedResponse),
            "an exception is an answer, read without waiting for a full frame"
        );
        exception[4] ^= 0xFF;
        assert_eq!(classify(exception, 2), Err(StatusReason::IntegrityFailed));

        let mut wrong_function = frame(1, &[0, 0, 0, 1]);
        wrong_function[1] = 0x04;
        assert_eq!(
            classify(wrong_function, 2),
            Err(StatusReason::MalformedResponse)
        );

        assert_eq!(
            classify(frame(1, &[0x01, 0xF4]), 2),
            Err(StatusReason::MalformedResponse),
            "a byte count that does not match the registers asked for"
        );
        assert_eq!(
            classify(frame(7, &[0, 0, 0, 1]), 2),
            Err(StatusReason::MalformedResponse),
            "an intact frame from another slave"
        );
    }

    #[test]
    fn an_answer_that_stops_is_told_from_one_that_never_started() {
        use std::io::ErrorKind;
        assert_eq!(
            stalled(vec![], ErrorKind::WouldBlock),
            StatusReason::NoResponse
        );
        assert_eq!(
            stalled(vec![], ErrorKind::TimedOut),
            StatusReason::NoResponse
        );
        assert_eq!(
            stalled(vec![0x01, 0x03, 0x04], ErrorKind::WouldBlock),
            StatusReason::MalformedResponse
        );
        assert_eq!(
            stalled(vec![], ErrorKind::ConnectionReset),
            StatusReason::InterfaceAbsent
        );
        assert_eq!(classify(vec![], 2), Err(StatusReason::InterfaceAbsent));
        assert_eq!(
            classify(vec![0x01, 0x03, 0x04, 0x00], 2),
            Err(StatusReason::MalformedResponse)
        );
    }

    fn socket_sensor(port: u16) -> SensorConfig {
        SensorConfig {
            id: "phone-main-power".to_string(),
            sensor_type: "usb_power".to_string(),
            protocol: "usb_serial".to_string(),
            device_path: format!("socket://127.0.0.1:{port}"),
            poll_interval_ms: 200,
            slave_id: 1,
            timeout_ms: 150,
        }
    }

    /// A bridge that accepts, reads each request, and answers with `answer`.
    /// `None` holds the connection open and never answers.
    fn fake_bridge(answer: Option<Vec<u8>>) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let answer = answer.clone();
                thread::spawn(move || {
                    let mut request = [0_u8; 8];
                    while stream.read_exact(&mut request).is_ok() {
                        match &answer {
                            Some(bytes) => {
                                let _ = stream.write_all(bytes);
                            }
                            None => {
                                // Silent for longer than any test's timeout,
                                // then gone. A read that waited past its
                                // timeout sees the close and fails its test
                                // instead of hanging the suite.
                                thread::sleep(Duration::from_secs(2));
                                return;
                            }
                        }
                    }
                });
            }
        });
        port
    }

    fn refusing_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().unwrap().port()
    }

    /// Five polls through the real read path into a tracker. One snapshot is
    /// owed, carrying `expected`, and the four failures after it owe nothing.
    fn one_status_for(port: u16, expected: StatusReason) {
        let sensor = socket_sensor(port);
        let start = Instant::now();
        let mut status = StatusTracker::new(
            [(sensor.id.as_str(), sensor.sensor_type.as_str())],
            Duration::from_secs(30),
        );
        let mut sent = Vec::new();
        for poll in 0..5 {
            match read_pzem_sensor(&sensor) {
                Ok(_) => panic!("a faulty bridge produced a reading"),
                Err(failure) => status.record_failure(&sensor.id, failure.reason),
            }
            let now = start + Duration::from_secs(poll);
            if status.snapshot_due(now) {
                sent.push(status.take_snapshot("d", 1, now));
            }
        }
        assert_eq!(
            sent.len(),
            1,
            "repeated failures of one class owe one status"
        );
        let entry = &sent[0]["sensors"][0];
        assert_eq!(entry["reason"], expected.as_str());
        assert_eq!(entry["state"], "never_read");
        assert_eq!(entry["consecutive_failures"], 1);
    }

    #[test]
    fn a_bridge_that_refuses_is_the_interface_absent() {
        one_status_for(refusing_port(), StatusReason::InterfaceAbsent);
    }

    #[test]
    fn a_bridge_that_accepts_and_never_answers_is_a_meter_not_responding() {
        one_status_for(fake_bridge(None), StatusReason::NoResponse);
    }

    #[test]
    fn a_bridge_answering_with_a_bad_crc_is_an_integrity_failure() {
        let mut corrupt = frame(1, &[0, 0, 0x04, 0xD2]);
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        one_status_for(fake_bridge(Some(corrupt)), StatusReason::IntegrityFailed);
    }

    #[test]
    fn a_bridge_answering_correctly_produces_a_reading_through_the_same_path() {
        let port = fake_bridge(Some(frame(1, &[0, 0, 0x04, 0xD2])));
        let reading = read_pzem_sensor(&socket_sensor(port)).expect("a reading");
        assert_eq!(reading.value, 123.4);
    }

    fn phone_config(export_extra: &str, sensors: &str) -> RuntimeConfig {
        let yaml = format!(
            "device: {{id: phone-01, deployment_type: phone}}\n\
             sensors: [{sensors}]\n\
             telemetry_export: {{enabled: true, endpoint: 'https://product.example.invalid/runtime/telemetry', \
             api_key_env: ORI_DEVICE_API_KEY{export_extra}}}\n"
        );
        serde_yaml::from_str(&yaml).expect("config decodes")
    }

    const SENSOR: &str =
        "{id: meter, type: usb_power, protocol: usb_serial, device_path: 'socket://127.0.0.1:9'}";

    #[test]
    fn the_flush_interval_is_refused_outside_the_range_the_python_runtime_accepts() {
        for accepted in [
            "",
            ", flush_interval_s: 1",
            ", flush_interval_s: 30",
            ", flush_interval_s: 300",
            ", flush_interval_s: 2.5",
        ] {
            assert!(
                phone_config(accepted, SENSOR)
                    .validate_phone_authority()
                    .is_ok(),
                "{accepted:?}"
            );
        }
        for refused in [
            ", flush_interval_s: 0.5",
            ", flush_interval_s: 300.5",
            ", flush_interval_s: .nan",
            ", flush_interval_s: .inf",
            ", flush_interval_s: -30",
        ] {
            assert!(
                phone_config(refused, SENSOR)
                    .validate_phone_authority()
                    .is_err(),
                "{refused:?}"
            );
        }
        assert_eq!(
            phone_config("", SENSOR).telemetry_export.flush_interval(),
            Duration::from_secs(30)
        );
    }

    #[test]
    fn a_sensor_id_declared_twice_is_refused() {
        let twice = format!("{SENSOR}, {SENSOR}");
        assert!(phone_config("", &twice).usb_socket_sensors().is_err());
        let other =
            "{id: meter, type: battery_percent, protocol: android_battery, device_path: ''}";
        assert!(
            phone_config("", &format!("{SENSOR}, {other}"))
                .usb_socket_sensors()
                .is_err(),
            "an id is unique across every declared sensor, not only the ones read here"
        );
        assert_eq!(
            phone_config("", SENSOR).usb_socket_sensors().unwrap().len(),
            1
        );
    }

    #[test]
    fn a_socket_target_without_a_port_is_refused_at_start_up() {
        let no_port =
            "{id: meter, type: usb_power, protocol: usb_serial, device_path: 'socket://127.0.0.1'}";
        assert!(phone_config("", no_port).usb_socket_sensors().is_err());
        for refused in [
            "socket://127.0.0.1:",
            "socket://:7000",
            "socket://127.0.0.1:0",
            "socket://127.0.0.1:70000",
        ] {
            assert!(socket_target(refused).is_err(), "{refused}");
        }
        for accepted in [
            "socket://127.0.0.1:7000",
            "socket://[::1]:7000",
            "socket://localhost:7000",
        ] {
            assert!(socket_target(accepted).is_ok(), "{accepted}");
        }
    }

    #[test]
    fn the_status_route_is_the_endpoint_with_the_suffix() {
        assert_eq!(
            status_route("https://product.example.invalid/runtime/telemetry"),
            "https://product.example.invalid/runtime/telemetry/sensor-status"
        );
    }
}
