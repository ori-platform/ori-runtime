# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.config import ConfigValidationError, _parse_firmware_mqtt_provisioning
from ori.runtime import _read_private_key_file, _read_public_pem_file


def _enabled_config() -> dict:
    return {
        "enabled": True,
        "socket_path": "/run/ori/firmware-mqtt.sock",
        "socket_mode": "0o600",
        "allowed_uids": [0, 1000, 1000],
        "provisioner_key_env": "ORI_FW_PROVISIONER_KEY",
        "client_ca_certfile": "/etc/ori/client-ca.crt",
        "client_ca_keyfile": "/etc/ori/client-ca.key",
        "broker_ca_certfile": "/etc/ori/broker-ca.crt",
        "broker_uri": "mqtts://broker.example.com:8883",
        "time_server": "time.example.com",
        "certificate_validity_days": 90,
    }


def test_firmware_mqtt_operator_defaults_disabled() -> None:
    config = _parse_firmware_mqtt_provisioning(None)
    assert config["enabled"] is False
    assert config["socket_mode"] == 0o600
    assert config["allowed_uids"] == []


def test_firmware_mqtt_operator_accepts_fail_closed_configuration() -> None:
    config = _parse_firmware_mqtt_provisioning(_enabled_config())
    assert config["enabled"] is True
    assert config["allowed_uids"] == [0, 1000]
    assert config["socket_path"].startswith("/run/ori/")


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("enabled", "true", "must be a boolean"),
        ("socket_mode", "0o606", "world access"),
        ("socket_mode", True, "valid integer"),
        ("socket_mode", "0o400", "owner or group write"),
        ("socket_path", "relative.sock", "must be absolute"),
        ("client_ca_keyfile", "relative.key", "must be absolute"),
        ("provisioner_key_env", "not-an-env", "is invalid"),
        ("broker_uri", [], "must be text"),
        ("allowed_uids", [True], "invalid uid"),
        ("certificate_validity_days", 0, "within 1..397"),
    ],
)
def test_firmware_mqtt_operator_rejects_unsafe_configuration(
    field: str,
    value: object,
    match: str,
) -> None:
    config = _enabled_config()
    config[field] = value
    with pytest.raises(ConfigValidationError, match=match):
        _parse_firmware_mqtt_provisioning(config)


def test_firmware_mqtt_operator_requires_all_runtime_owned_material() -> None:
    config = _enabled_config()
    config["client_ca_keyfile"] = ""
    with pytest.raises(ConfigValidationError, match="client_ca_keyfile"):
        _parse_firmware_mqtt_provisioning(config)


def test_private_ca_key_file_must_not_be_group_or_world_accessible(tmp_path) -> None:
    key_file = tmp_path / "client-ca.key"
    key_file.write_bytes(b"private-key-test-material")
    key_file.chmod(0o640)
    with pytest.raises(RuntimeError, match="0o600 or stricter"):
        _read_private_key_file(str(key_file))

    key_file.chmod(0o600)
    assert _read_private_key_file(str(key_file)) == b"private-key-test-material"


def test_ca_material_readers_refuse_symlinks_and_private_public_input(tmp_path) -> None:
    target = tmp_path / "target.pem"
    target.write_bytes(b"-----BEGIN CERTIFICATE-----\npublic\n")
    target.chmod(0o600)
    link = tmp_path / "link.pem"
    link.symlink_to(target)
    with pytest.raises(RuntimeError, match="cannot open"):
        _read_private_key_file(str(link))

    public_with_key = tmp_path / "public.pem"
    public_with_key.write_bytes(b"-----BEGIN PRIVATE KEY-----\nsecret\n")
    with pytest.raises(RuntimeError, match="invalid"):
        _read_public_pem_file(str(public_with_key))
