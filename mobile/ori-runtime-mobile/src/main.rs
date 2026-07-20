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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const CONFIG_SIGNATURE_SCHEMA: &str = "ori.config_signature.v1";
const CONFIG_REQUIRE_SIGNED_ENV: &str = "ORI_CONFIG_REQUIRE_SIGNED";
const DEFAULT_CONFIG_TRUST_ANCHOR_ENV: &str = "ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64";
const TELEMETRY_SCHEMA_VERSION: &str = "runtime.telemetry.v1";
const JSON_SAFE_INT_MAX: u64 = 9_007_199_254_740_991;
const USER_AGENT: &str = "ori-runtime-mobile/0.1";

type HmacSha256 = Hmac<Sha256>;

fn main() {
    if let Err(error) = run() {
        eprintln!("[ori-runtime-mobile] {error}");
        std::process::exit(1);
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

    let mut sequence = 0_u64;
    loop {
        let mut events = Vec::new();
        for sensor in &sensors {
            match read_pzem_sensor(sensor) {
                Ok(reading) => events.push(sensor_event(&config.device.id, reading)),
                Err(error) => eprintln!(
                    "[ori-runtime-mobile] sensor_id={} read failed: {error}",
                    sensor.id
                ),
            }
        }

        if !events.is_empty() {
            sequence += 1;
            post_telemetry_batch(&config, &api_key, sequence, events)?;
        }

        if args.once {
            break;
        }
        thread::sleep(Duration::from_millis(config.min_poll_interval_ms()));
    }
    Ok(())
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
        Ok(())
    }

    fn usb_socket_sensors(&self) -> Result<Vec<&SensorConfig>, String> {
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

fn read_pzem_sensor(sensor: &SensorConfig) -> Result<SensorReading, String> {
    let target = socket_target(&sensor.device_path)?;
    let address = target
        .to_socket_addrs()
        .map_err(|error| format!("invalid socket target {target}: {error}"))?
        .next()
        .ok_or_else(|| format!("socket target {target} resolved to no addresses"))?;
    let timeout = Duration::from_millis(sensor.timeout_ms.max(100));
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| format!("failed to connect to USB bridge: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| format!("failed to set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| format!("failed to set write timeout: {error}"))?;

    let metric = pzem_metric(&sensor.sensor_type)?;
    let request = build_read_request(sensor.slave_id, metric.register, metric.register_count);
    stream
        .write_all(&request)
        .map_err(|error| format!("failed to write Modbus request: {error}"))?;

    let expected_len = 5 + (metric.register_count as usize * 2);
    let mut response = vec![0_u8; expected_len];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("failed to read Modbus response: {error}"))?;
    let raw = parse_response(&response, metric.register_count)?;

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
    if rest.trim().is_empty() || rest.contains('/') {
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

fn parse_response(response: &[u8], expected_count: u16) -> Result<u32, String> {
    let expected_len = 5 + (expected_count as usize * 2);
    if response.len() < expected_len {
        return Err(format!(
            "short Modbus response: {} bytes, expected at least {expected_len}",
            response.len()
        ));
    }
    let payload_len = response.len() - 2;
    let received_crc = u16::from_le_bytes([response[payload_len], response[payload_len + 1]]);
    let computed_crc = crc16(&response[..payload_len]);
    if received_crc != computed_crc {
        return Err(format!(
            "CRC mismatch: got 0x{received_crc:04X}, computed 0x{computed_crc:04X}"
        ));
    }
    let data = &response[3..payload_len];
    if expected_count == 1 {
        Ok(u16::from_be_bytes([data[0], data[1]]) as u32)
    } else {
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }
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

fn post_telemetry_batch(
    config: &RuntimeConfig,
    api_key: &str,
    sequence: u64,
    events: Vec<JsonValue>,
) -> Result<(), String> {
    let payload = json!({
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "device_id": config.device.id.as_str(),
        "sequence": sequence,
        "sent_at_ms": now_ms(),
        "events": events,
    });
    let body = canonical_telemetry_json(&payload)?;
    let timestamp_ms = now_ms().to_string();
    let signature = telemetry_signature(api_key.as_bytes(), timestamp_ms.as_bytes(), &body)?;
    let response = ureq::post(&config.telemetry_export.endpoint)
        .set("Authorization", &format!("Bearer {api_key}"))
        .set("Content-Type", "application/json")
        .set("User-Agent", USER_AGENT)
        .set("X-Ori-Device-Id", &config.device.id)
        .set("X-Ori-Timestamp-Ms", &timestamp_ms)
        .set("X-Ori-Signature", &format!("v1={signature}"))
        .timeout(Duration::from_millis(
            config.telemetry_export.timeout_ms.max(100),
        ))
        .send_bytes(&body);
    match response {
        Ok(resp) if (200..300).contains(&resp.status()) => Ok(()),
        Ok(resp) => Err(format!("telemetry POST returned HTTP {}", resp.status())),
        Err(error) => Err(format!("telemetry POST failed: {error}")),
    }
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
        .get(&YamlValue::String("config_signature".to_string()))
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
        .get(&YamlValue::String("config_signature".to_string()))
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
        .and_then(|root| root.get(&YamlValue::String("security".to_string())))
        .and_then(YamlValue::as_mapping)
    else {
        return Ok(DEFAULT_CONFIG_TRUST_ANCHOR_ENV.to_string());
    };
    let Some(config_signature) = security
        .get(&YamlValue::String("config_signature".to_string()))
        .and_then(YamlValue::as_mapping)
    else {
        return Ok(DEFAULT_CONFIG_TRUST_ANCHOR_ENV.to_string());
    };
    match config_signature.get(&YamlValue::String("trust_anchor_env".to_string())) {
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
    map.get(&YamlValue::String(key.to_string()))
        .and_then(YamlValue::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("config_signature.{key} is required"))
}

fn yaml_i64(map: &serde_yaml::Mapping, key: &str) -> Result<i64, String> {
    map.get(&YamlValue::String(key.to_string()))
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
}
