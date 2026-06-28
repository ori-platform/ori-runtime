# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import base64
import importlib.util
import json
import struct
from pathlib import Path

import yaml

from ori import phone_doctor
from ori.security.config_signatures import (
    CONFIG_SIGNATURE_SCHEMA,
    canonical_config_signature_payload,
)

_PZEM_SIM_PATH = Path("scripts/pzem_socket_sim.py")


def _load_pzem_sim():
    spec = importlib.util.spec_from_file_location("pzem_socket_sim", _PZEM_SIM_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_phone_config(
    tmp_path,
    *,
    deployment_type: str = "phone",
    sensor_block: str | None = None,
    security_block: str | None = None,
    relay_enabled: bool = False,
    telemetry_enabled: bool = False,
    operator_contact: str = "+2348012345678",
) -> str:
    path = tmp_path / "ori.yaml"
    sensors = (
        sensor_block
        or """
  - id: phone-main-power
    type: usb_power
    protocol: usb_serial
    device_path: /dev/ttyUSB0
    poll_interval_ms: 2000
""".rstrip()
    )
    security = security_block or ""
    path.write_text(
        f"""
device:
  id: phone-gateway-ikeja-01
  name: Ikeja Office Phone Gateway
  location: Lagos, Nigeria
  timezone: Africa/Lagos
  deployment_type: {deployment_type}

sensors:
{sensors}

skills:
  - name: energy-anomaly-detector
    version: "0.1.0"

reasoning:
  default_tier: local
  local_model: qwen2.5-0.5b-instruct-q4_k_m
  model_path: /data/data/com.termux/files/home/models/

gateway:
  enabled: false
  broker_url: ""

telemetry_export:
  enabled: {str(telemetry_enabled).lower()}
  endpoint: "https://api.ori.energy/runtime/telemetry"
  api_key_env: ORI_ENERGY_DEVICE_API_KEY

health_socket:
  enabled: true
  path: /data/data/com.termux/files/home/.ori/health.sock
  mode: 0o660

{security}

actions:
  primary_alert_channel: sms
  operator_contact: "{operator_contact}"
  whatsapp:
    enabled: false
  sms:
    enabled: false
  relay:
    enabled: {str(relay_enabled).lower()}
    gpio_pin: 26

hal:
  circuit_breaker:
    failure_threshold: 5
    recovery_timeout_s: 300
    success_threshold: 2

logging:
  level: INFO
  file: ori.log
""".strip()
    )
    return str(path)


def _ed25519_keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    return private_key, public_key_b64


def _sign_config_file(config_path: str, private_key) -> None:
    path = Path(config_path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    raw["config_signature"] = {
        "schema": CONFIG_SIGNATURE_SCHEMA,
        "signer_id": "ori-energy-test",
        "signed_at_ms": 1_800_000_000_000,
        "signature": "ed25519:",
    }
    signature = private_key.sign(canonical_config_signature_payload(raw))
    raw["config_signature"]["signature"] = "ed25519:" + base64.b64encode(
        signature
    ).decode("ascii")
    path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")


def _status_by_name(checks):
    return {check.name: check.status for check in checks}


def _message_by_name(checks):
    return {check.name: check.message for check in checks}


def _dependency_finder(available):
    def find_spec(name):
        if name in available:
            return object()
        return None

    return find_spec


def test_phone_doctor_accepts_valid_phone_config_with_warnings(tmp_path, monkeypatch):
    config_path = _write_phone_config(tmp_path)
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(config_path)

    statuses = _status_by_name(checks)
    assert statuses["config.load"] == "pass"
    assert statuses["config.deployment_type"] == "pass"
    assert statuses["config.relay"] == "pass"
    assert statuses["config.gateway"] == "pass"
    assert statuses["config.sensor_profile"] == "pass"
    assert statuses["config.profile_dependencies"] == "pass"
    assert statuses["config.config_signature"] == "warn"
    assert statuses["config.telemetry_export"] == "warn"
    assert statuses["config.health_socket"] == "pass"
    assert phone_doctor.has_failures(checks) is False


def test_phone_doctor_accepts_verified_signed_phone_config(tmp_path, monkeypatch):
    private_key, public_key_b64 = _ed25519_keypair()
    monkeypatch.setenv("ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64", public_key_b64)
    config_path = _write_phone_config(
        tmp_path,
        security_block="""
security:
  config_signature:
    require_signed: true
    trust_anchor_env: ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64
  skills:
    require_signed: false
""".rstrip(),
    )
    _sign_config_file(config_path, private_key)
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(config_path)

    statuses = _status_by_name(checks)
    signature_check = next(
        check for check in checks if check.name == "config.config_signature"
    )
    assert statuses["config.load"] == "pass"
    assert statuses["config.config_signature"] == "pass"
    assert signature_check.details == {
        "verified": True,
        "required": True,
        "trust_anchor_env": "ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64",
        "signer_id": "ori-energy-test",
        "signed_at_ms": 1_800_000_000_000,
    }
    assert phone_doctor.has_failures(checks) is False


def test_phone_doctor_fails_required_unsigned_config(tmp_path, monkeypatch):
    config_path = _write_phone_config(
        tmp_path,
        security_block="""
security:
  config_signature:
    require_signed: true
  skills:
    require_signed: false
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(config_path)

    statuses = _status_by_name(checks)
    assert statuses["config.load"] == "fail"
    assert "missing config_signature" in _message_by_name(checks)["config.load"]
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_fails_tampered_signed_config(tmp_path, monkeypatch):
    private_key, public_key_b64 = _ed25519_keypair()
    monkeypatch.setenv("ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64", public_key_b64)
    config_path = _write_phone_config(
        tmp_path,
        security_block="""
security:
  config_signature:
    require_signed: true
  skills:
    require_signed: false
""".rstrip(),
    )
    _sign_config_file(config_path, private_key)
    path = Path(config_path)
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "location: Lagos, Nigeria",
            "location: Tampered",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(config_path)

    statuses = _status_by_name(checks)
    assert statuses["config.load"] == "fail"
    assert "signature verification failed" in _message_by_name(checks)["config.load"]
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_fails_when_deployment_type_is_not_phone(tmp_path, monkeypatch):
    config_path = _write_phone_config(tmp_path, deployment_type="pi")
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.deployment_type"] == "fail"
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_fails_when_phone_relay_is_enabled(tmp_path, monkeypatch):
    config_path = _write_phone_config(tmp_path, relay_enabled=True)
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.relay"] == "fail"
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_requires_api_key_when_telemetry_enabled(tmp_path, monkeypatch):
    config_path = _write_phone_config(tmp_path, telemetry_enabled=True)
    monkeypatch.delenv("ORI_ENERGY_DEVICE_API_KEY", raising=False)
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.telemetry_export"] == "fail"
    assert (
        "ORI_ENERGY_DEVICE_API_KEY"
        in _message_by_name(checks)["config.telemetry_export"]
    )


def test_phone_doctor_accepts_api_key_when_telemetry_enabled(tmp_path, monkeypatch):
    config_path = _write_phone_config(tmp_path, telemetry_enabled=True)
    monkeypatch.setenv("ORI_ENERGY_DEVICE_API_KEY", "test-key")
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.telemetry_export"] == "pass"
    assert phone_doctor.has_failures(checks) is False


def test_phone_doctor_accepts_growatt_phone_profile(tmp_path, monkeypatch):
    config_path = _write_phone_config(
        tmp_path,
        sensor_block="""
  - id: growatt-pv-power
    type: growatt_pv_power
    protocol: growatt
    host: "192.168.1.20"
    serial: "1234567890"
    port: 8899
    poll_interval_ms: 5000
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor.importlib.util,
        "find_spec",
        _dependency_finder({"pysolarmanv5"}),
    )

    checks = phone_doctor.run_phone_doctor(config_path)

    statuses = _status_by_name(checks)
    assert statuses["config.sensor_profile"] == "pass"
    assert statuses["config.profile_dependencies"] == "pass"
    assert phone_doctor.has_failures(checks) is False


def test_phone_doctor_fails_growatt_profile_without_host_or_serial(
    tmp_path, monkeypatch
):
    config_path = _write_phone_config(
        tmp_path,
        sensor_block="""
  - id: growatt-pv-power
    type: growatt_pv_power
    protocol: growatt
    poll_interval_ms: 5000
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor.importlib.util,
        "find_spec",
        _dependency_finder({"pysolarmanv5"}),
    )

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.sensor_profile"] == "fail"
    message = _message_by_name(checks)["config.sensor_profile"]
    assert "host" in message
    assert "serial" in message
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_fails_growatt_profile_without_dependency(tmp_path, monkeypatch):
    config_path = _write_phone_config(
        tmp_path,
        sensor_block="""
  - id: growatt-pv-power
    type: growatt_pv_power
    protocol: growatt
    host: "192.168.1.20"
    serial: "1234567890"
    poll_interval_ms: 5000
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor.importlib.util,
        "find_spec",
        _dependency_finder(set()),
    )

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.profile_dependencies"] == "fail"
    assert "pysolarmanv5" in _message_by_name(checks)["config.profile_dependencies"]
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_accepts_solarman_modbus_phone_profile(tmp_path, monkeypatch):
    config_path = _write_phone_config(
        tmp_path,
        sensor_block="""
  - id: deye-grid-power
    type: deye_grid_power
    protocol: solarman_modbus
    profile: deye_hybrid
    host: "192.168.1.20"
    serial: "1234567890"
    port: 8899
    poll_interval_ms: 5000
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor.importlib.util,
        "find_spec",
        _dependency_finder({"pysolarmanv5"}),
    )

    checks = phone_doctor.run_phone_doctor(config_path)

    statuses = _status_by_name(checks)
    assert statuses["config.sensor_profile"] == "pass"
    assert statuses["config.profile_dependencies"] == "pass"
    assert phone_doctor.has_failures(checks) is False


def test_phone_doctor_fails_solarman_modbus_profile_without_fields(
    tmp_path, monkeypatch
):
    config_path = _write_phone_config(
        tmp_path,
        sensor_block="""
  - id: deye-grid-power
    type: deye_grid_power
    protocol: solarman_modbus
    poll_interval_ms: 5000
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor.importlib.util,
        "find_spec",
        _dependency_finder({"pysolarmanv5"}),
    )

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.sensor_profile"] == "fail"
    message = _message_by_name(checks)["config.sensor_profile"]
    assert "profile" in message
    assert "host" in message
    assert "serial" in message
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_fails_solarman_modbus_profile_without_dependency(
    tmp_path, monkeypatch
):
    config_path = _write_phone_config(
        tmp_path,
        sensor_block="""
  - id: deye-grid-power
    type: deye_grid_power
    protocol: solarman_modbus
    profile: deye_hybrid
    host: "192.168.1.20"
    serial: "1234567890"
    poll_interval_ms: 5000
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor.importlib.util,
        "find_spec",
        _dependency_finder(set()),
    )

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.profile_dependencies"] == "fail"
    assert "pysolarmanv5" in _message_by_name(checks)["config.profile_dependencies"]
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_accepts_victron_phone_profile(tmp_path, monkeypatch):
    config_path = _write_phone_config(
        tmp_path,
        sensor_block="""
  - id: victron-pv-power
    type: victron_pv_power
    protocol: victron
    broker_host: "192.168.1.50"
    portal_id: "site-portal"
    port: 1883
    poll_interval_ms: 5000
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor.importlib.util,
        "find_spec",
        _dependency_finder({"aiomqtt"}),
    )

    checks = phone_doctor.run_phone_doctor(config_path)

    statuses = _status_by_name(checks)
    assert statuses["config.sensor_profile"] == "pass"
    assert statuses["config.profile_dependencies"] == "pass"
    assert phone_doctor.has_failures(checks) is False


def test_phone_doctor_fails_victron_profile_without_broker_or_portal(
    tmp_path, monkeypatch
):
    config_path = _write_phone_config(
        tmp_path,
        sensor_block="""
  - id: victron-pv-power
    type: victron_pv_power
    protocol: victron
    poll_interval_ms: 5000
""".rstrip(),
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor.importlib.util,
        "find_spec",
        _dependency_finder({"aiomqtt"}),
    )

    checks = phone_doctor.run_phone_doctor(config_path)

    assert _status_by_name(checks)["config.sensor_profile"] == "fail"
    message = _message_by_name(checks)["config.sensor_profile"]
    assert "broker_host" in message
    assert "portal_id" in message
    assert phone_doctor.has_failures(checks) is True


def test_phone_doctor_rejects_linux_health_socket_path_for_phone(tmp_path, monkeypatch):
    config_path = Path(_write_phone_config(tmp_path))
    text = config_path.read_text(encoding="utf-8")
    config_path.write_text(
        text.replace(
            "/data/data/com.termux/files/home/.ori/health.sock",
            "/run/ori/health.sock",
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    checks = phone_doctor.run_phone_doctor(str(config_path))

    assert _status_by_name(checks)["config.health_socket"] == "fail"
    assert "/run" in _message_by_name(checks)["config.health_socket"]
    assert phone_doctor.has_failures(checks) is True


def test_usb_readiness_prefers_direct_serial_device(monkeypatch):
    monkeypatch.setattr(
        phone_doctor,
        "_find_direct_serial_devices",
        lambda: ["/dev/ttyUSB0"],
    )

    check = phone_doctor._check_usb_readiness()

    assert check.status == "pass"
    assert check.details == {"serial_devices": ["/dev/ttyUSB0"]}


def test_usb_readiness_warns_for_raw_termux_usb_without_serial(monkeypatch):
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(
        phone_doctor,
        "_list_termux_usb_devices",
        lambda: ["/dev/bus/usb/001/002"],
    )

    check = phone_doctor._check_usb_readiness()

    assert check.status == "warn"
    assert "no /dev/ttyUSB" in check.message


def test_parse_termux_usb_json_output():
    assert phone_doctor._parse_termux_usb_output(
        '["/dev/bus/usb/001/002", "/dev/bus/usb/001/003"]'
    ) == ["/dev/bus/usb/001/002", "/dev/bus/usb/001/003"]


def test_main_emits_json_and_returns_failure(tmp_path, monkeypatch, capsys):
    config_path = _write_phone_config(tmp_path, relay_enabled=True)
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    exit_code = phone_doctor.main(["--config", config_path, "--json"])

    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert any(
        item["name"] == "config.relay" and item["status"] == "fail" for item in payload
    )


def test_main_no_fail_returns_zero_for_failures(tmp_path, monkeypatch):
    config_path = _write_phone_config(tmp_path, relay_enabled=True)
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    assert phone_doctor.main(["--config", config_path, "--no-fail"]) == 0


def test_format_text_uses_pretty_ansi_report(tmp_path, monkeypatch):
    config_path = _write_phone_config(tmp_path)
    monkeypatch.setattr(phone_doctor, "_find_direct_serial_devices", lambda: [])
    monkeypatch.setattr(phone_doctor, "_list_termux_usb_devices", lambda: [])

    output = phone_doctor._format_text(phone_doctor.run_phone_doctor(config_path))

    assert "\033[" in output
    assert "ORI  PHONE DOCTOR" in output
    assert "ANDROID / TERMUX" in output
    assert "ORI CONFIG" in output
    assert "Result: PASS" in output


def test_pzem_socket_sim_builds_usb_power_response():
    sim = _load_pzem_sim()
    payload = struct.pack(">BBHH", 1, 0x03, 0x0012, 2)
    request = payload + struct.pack("<H", sim.crc16(payload))

    response = sim.build_response(request, {"power": 850.0})

    assert response[:3] == b"\x01\x03\x04"
    assert struct.unpack(">I", response[3:-2])[0] == 8500
    assert struct.unpack("<H", response[-2:])[0] == sim.crc16(response[:-2])
