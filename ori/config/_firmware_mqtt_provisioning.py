# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The ``firmware_mqtt_provisioning`` section."""

from pathlib import Path
from typing import Any

from ori.config._env import ENV_NAME_RE
from ori.config._fields import ConfigValidationError


def parse_firmware_mqtt_provisioning(data: Any) -> dict:
    """Parse the fail-closed firmware MQTT operator-service configuration."""
    defaults = {
        "enabled": False,
        "socket_path": "/run/ori/firmware-mqtt-provisioning.sock",
        "socket_mode": 0o600,
        "allowed_uids": [],
        "provisioner_key_env": "ORI_FW_PROVISIONER_KEY",
        "client_ca_certfile": "",
        "client_ca_keyfile": "",
        "client_ca_key_password_env": "",
        "broker_ca_certfile": "",
        "broker_uri": "",
        "time_server": "",
        "certificate_validity_days": 90,
    }
    if data is None:
        return defaults
    if not isinstance(data, dict):
        raise ConfigValidationError("firmware_mqtt_provisioning must be a mapping.")

    out = dict(defaults)
    raw_enabled = data.get("enabled", False)
    if type(raw_enabled) is not bool:
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.enabled must be a boolean."
        )
    out["enabled"] = raw_enabled
    for field_name in (
        "socket_path",
        "provisioner_key_env",
        "client_ca_certfile",
        "client_ca_keyfile",
        "client_ca_key_password_env",
        "broker_ca_certfile",
        "broker_uri",
        "time_server",
    ):
        raw_value = data.get(field_name, defaults[field_name])
        if not isinstance(raw_value, str):
            raise ConfigValidationError(
                f"firmware_mqtt_provisioning.{field_name} must be text."
            )
        value = raw_value.strip()
        if "\x00" in value:
            raise ConfigValidationError(
                f"firmware_mqtt_provisioning.{field_name} contains invalid null bytes."
            )
        out[field_name] = value

    raw_mode = data.get("socket_mode", defaults["socket_mode"])
    if isinstance(raw_mode, bool):
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.socket_mode must be a valid integer."
        )
    try:
        mode = int(raw_mode, 0) if isinstance(raw_mode, str) else int(raw_mode)
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.socket_mode must be a valid integer."
        ) from exc
    if mode < 0 or mode > 0o777 or mode & 0o007:
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.socket_mode must not grant world access."
        )
    if mode & 0o220 == 0:
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.socket_mode must grant owner or group write."
        )
    out["socket_mode"] = mode

    raw_uids = data.get("allowed_uids", [])
    if not isinstance(raw_uids, list):
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.allowed_uids must be a list."
        )
    allowed_uids: list[int] = []
    for raw_uid in raw_uids:
        if isinstance(raw_uid, bool):
            raise ConfigValidationError(
                "firmware_mqtt_provisioning.allowed_uids contains an invalid uid."
            )
        try:
            uid = int(raw_uid)
        except (TypeError, ValueError) as exc:
            raise ConfigValidationError(
                "firmware_mqtt_provisioning.allowed_uids contains an invalid uid."
            ) from exc
        if uid < 0:
            raise ConfigValidationError(
                "firmware_mqtt_provisioning.allowed_uids contains an invalid uid."
            )
        if uid not in allowed_uids:
            allowed_uids.append(uid)
    out["allowed_uids"] = allowed_uids

    raw_validity = data.get(
        "certificate_validity_days",
        defaults["certificate_validity_days"],
    )
    if isinstance(raw_validity, bool):
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.certificate_validity_days must be within 1..397."
        )
    try:
        validity_days = int(raw_validity)
    except (TypeError, ValueError) as exc:
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.certificate_validity_days must be within 1..397."
        ) from exc
    if not 1 <= validity_days <= 397:
        raise ConfigValidationError(
            "firmware_mqtt_provisioning.certificate_validity_days must be within 1..397."
        )
    out["certificate_validity_days"] = validity_days

    if out["enabled"]:
        required = (
            "socket_path",
            "provisioner_key_env",
            "client_ca_certfile",
            "client_ca_keyfile",
            "broker_ca_certfile",
            "broker_uri",
            "time_server",
        )
        missing = [field_name for field_name in required if not out[field_name]]
        if missing:
            raise ConfigValidationError(
                "firmware_mqtt_provisioning requires: " + ", ".join(missing)
            )
        if not Path(str(out["socket_path"])).is_absolute():
            raise ConfigValidationError(
                "firmware_mqtt_provisioning.socket_path must be absolute."
            )
        for path_field in (
            "client_ca_certfile",
            "client_ca_keyfile",
            "broker_ca_certfile",
        ):
            if not Path(str(out[path_field])).is_absolute():
                raise ConfigValidationError(
                    f"firmware_mqtt_provisioning.{path_field} must be absolute."
                )
        for env_field in (
            "provisioner_key_env",
            "client_ca_key_password_env",
        ):
            env_name = str(out[env_field])
            if env_name and ENV_NAME_RE.fullmatch(env_name) is None:
                raise ConfigValidationError(
                    f"firmware_mqtt_provisioning.{env_field} is invalid."
                )
        if not str(out["broker_uri"]).startswith("mqtts://"):
            raise ConfigValidationError(
                "firmware_mqtt_provisioning.broker_uri must use mqtts://."
            )
    return out
