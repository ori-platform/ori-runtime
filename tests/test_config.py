# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import os
import textwrap

import pytest

from ori.config import (
    Config,
    ConfigValidationError,
)

EXAMPLE_YAML = os.path.join(os.path.dirname(__file__), "..", "ori.yaml.example")


@pytest.fixture
def _mock_env_vars_for_examples(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "mock_sid")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "mock_token")
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", "mock_from")
    monkeypatch.setenv("OWNER_WHATSAPP_NUMBER", "mock_owner")
    monkeypatch.setenv("AT_API_KEY", "mock_key")
    monkeypatch.setenv("AT_USERNAME", "mock_user")
    monkeypatch.setenv("OWNER_PHONE_NUMBER", "mock_phone")


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _write_yaml(tmp_path, content: str) -> str:
    p = tmp_path / "ori.yaml"
    p.write_text(textwrap.dedent(content))
    return str(p)


# ─── Loading ori.yaml.example ─────────────────────────────────────────────────


class TestLoadExample:
    @pytest.fixture(autouse=True)
    def use_mock_env(self, _mock_env_vars_for_examples):
        pass

    def test_loads_without_error(self):
        cfg = Config.load(EXAMPLE_YAML)
        assert isinstance(cfg, Config)

    def test_device_fields(self):
        cfg = Config.load(EXAMPLE_YAML)
        assert cfg.device.id == "energy-monitor-ikeja-01"
        assert cfg.device.name == "Ikeja Office Energy Monitor"
        assert cfg.device.location == "Lagos, Nigeria"
        assert cfg.device.rated_capacity_amps == 10.0

    def test_sensors_count_and_types(self):
        cfg = Config.load(EXAMPLE_YAML)
        # example has 3 uncommented sensors
        assert len(cfg.sensors) == 3
        types = {s.type for s in cfg.sensors}
        assert "current_clamp" in types
        assert "voltage" in types
        assert "battery_state" in types

    def test_sensor_poll_intervals(self):
        cfg = Config.load(EXAMPLE_YAML)
        for sensor in cfg.sensors:
            assert 100 <= sensor.poll_interval_ms <= 60_000

    def test_calibration_parsed(self):
        cfg = Config.load(EXAMPLE_YAML)
        load_current = next(s for s in cfg.sensors if s.id == "load-current")
        assert load_current.calibration == {"sensitivity": 0.1}

    def test_sensor_metadata_contains_extra_fields(self):
        cfg = Config.load(EXAMPLE_YAML)
        # address and channel are not first-class SensorConfig fields → metadata
        load_current = next(s for s in cfg.sensors if s.id == "load-current")
        assert "address" in load_current.metadata
        assert "channel" in load_current.metadata

    def test_skill_parsed(self):
        cfg = Config.load(EXAMPLE_YAML)
        assert len(cfg.skills) == 1
        skill = cfg.skills[0]
        assert skill.name == "energy-anomaly-detector"
        assert skill.version == "0.2.1"

    def test_skill_config_fields(self):
        cfg = Config.load(EXAMPLE_YAML)
        skill_cfg = cfg.skills[0].config
        assert skill_cfg["requires_approval_for_soft_actions"] is False
        assert skill_cfg["approval_timeout_seconds"] == 300
        assert skill_cfg["safe_default_action"] == "log_to_dashboard"

    def test_reasoning_fields(self):
        cfg = Config.load(EXAMPLE_YAML)
        r = cfg.reasoning
        assert r.default_tier == "local"
        assert r.local_model == "qwen2.5-0.5b-instruct-q4_k_m"
        assert r.offline_fallback == "rule"
        assert r.escalation_threshold == pytest.approx(0.70)

    def test_gateway_disabled(self):
        cfg = Config.load(EXAMPLE_YAML)
        assert cfg.gateway.enabled is False
        assert "192.168.1.10" in cfg.gateway.broker_url

    def test_actions_primary_channel(self):
        cfg = Config.load(EXAMPLE_YAML)
        assert cfg.actions.primary_alert_channel == "sms"

    def test_actions_relay(self):
        cfg = Config.load(EXAMPLE_YAML)
        relay = cfg.actions.relay
        assert relay["enabled"] is False
        assert relay["gpio_pin"] == 26

    def test_raw_preserved(self):
        cfg = Config.load(EXAMPLE_YAML)
        assert "device" in cfg.raw
        assert "sensors" in cfg.raw

    def test_hal_external_watchdog_defaults(self):
        cfg = Config.load(EXAMPLE_YAML)
        ext = cfg.hal.external_watchdog
        assert ext["enabled"] is False
        assert ext["gpio_pin"] == 17
        assert ext["ping_interval_s"] == 30


# ─── DeviceConfig validation ──────────────────────────────────────────────────


class TestDeviceValidation:
    def test_rejects_id_with_space(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: "bad id"
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        with pytest.raises(ConfigValidationError, match="spaces"):
            Config.load(yaml_path)

    def test_rejects_missing_device_id(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        with pytest.raises(ConfigValidationError, match="device.id"):
            Config.load(yaml_path)

    def test_rated_capacity_default(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        cfg = Config.load(yaml_path)
        assert cfg.device.rated_capacity_amps == 10.0

    def test_phone_deployment_type(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: phone-01
              name: Phone Gateway
              location: Lagos
              deployment_type: phone
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
              relay:
                enabled: false
                gpio_pin: 26
            """,
        )
        cfg = Config.load(yaml_path)
        assert cfg.device.deployment_type == "phone"

    def test_rejects_invalid_deployment_type(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
              deployment_type: edge-phone
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        with pytest.raises(ConfigValidationError, match="deployment_type"):
            Config.load(yaml_path)


# ─── SensorConfig validation ──────────────────────────────────────────────────


class TestSensorValidation:
    def _base_yaml(self, sensors_block: str) -> str:
        return f"""
device:
  id: dev-01
  name: Test
  location: Lagos
sensors:
{sensors_block}
skills: []
reasoning:
  default_tier: local
  local_model: x
  model_path: /tmp
  offline_fallback: rule
gateway:
  enabled: false
  broker_url: mqtt://localhost
actions:
  primary_alert_channel: sms
"""

    def test_rejects_poll_interval_too_low(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: s1\n    type: current_clamp\n    protocol: i2c\n    poll_interval_ms: 50"
            ),
        )
        with pytest.raises(ConfigValidationError, match="poll_interval_ms"):
            Config.load(yaml_path)

    def test_rejects_poll_interval_too_high(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: s1\n    type: voltage\n    protocol: i2c\n    poll_interval_ms: 999999"
            ),
        )
        with pytest.raises(ConfigValidationError, match="poll_interval_ms"):
            Config.load(yaml_path)

    def test_accepts_boundary_poll_intervals(self, tmp_path):
        for ms in (100, 60_000):
            yaml_path = _write_yaml(
                tmp_path,
                self._base_yaml(
                    f"  - id: s1\n    type: voltage\n    protocol: i2c\n    poll_interval_ms: {ms}"
                ),
            )
            cfg = Config.load(yaml_path)
            assert cfg.sensors[0].poll_interval_ms == ms

    def test_extra_fields_go_to_metadata(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: s1\n    type: current_clamp\n    protocol: i2c\n"
                "    poll_interval_ms: 1000\n    address: 0x48\n    channel: 0"
            ),
        )
        cfg = Config.load(yaml_path)
        # YAML parses hex literals like 0x48 as integers (72)
        assert cfg.sensors[0].metadata == {"address": 0x48, "channel": 0}

    def test_missing_type_raises(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: s1\n    protocol: i2c\n    poll_interval_ms: 1000"
            ),
        )
        with pytest.raises(ConfigValidationError, match="type"):
            Config.load(yaml_path)

    def test_rejects_unknown_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: s1\n    type: voltage\n    protocol: unknown_proto\n    poll_interval_ms: 1000"
            ),
        )
        with pytest.raises(ConfigValidationError, match="unknown protocol"):
            Config.load(yaml_path)

    def test_accepts_growatt_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: inverter-battery\n    type: growatt_battery_soc\n    protocol: growatt\n    poll_interval_ms: 5000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "growatt"

    def test_accepts_usb_serial_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: mains-power\n    type: usb_power\n    protocol: usb_serial\n    poll_interval_ms: 2000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "usb_serial"

    def test_accepts_http_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: outdoor-temp\n    type: temperature\n    protocol: http\n    poll_interval_ms: 10000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "http"

    def test_accepts_victron_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: victron-battery\n    type: victron_battery_soc\n    protocol: victron\n    poll_interval_ms: 5000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "victron"

    def test_accepts_opcua_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: plc-temperature\n    type: temperature\n    protocol: opcua\n    poll_interval_ms: 1000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "opcua"


# ─── SkillConfig / action_tier validation ─────────────────────────────────────


class TestSkillValidation:
    def _base_yaml(self, skills_block: str) -> str:
        return f"""
device:
  id: dev-01
  name: Test
  location: Lagos
sensors: []
skills:
{skills_block}
reasoning:
  default_tier: local
  local_model: x
  model_path: /tmp
  offline_fallback: rule
gateway:
  enabled: false
  broker_url: mqtt://localhost
actions:
  primary_alert_channel: sms
"""

    def test_valid_action_tiers_accepted(self, tmp_path):
        for tier in ("A", "B", "C", "D"):
            yaml_path = _write_yaml(
                tmp_path,
                self._base_yaml(
                    f"  - name: skill-x\n    version: '1.0'\n"
                    f"    config:\n      action_tier: {tier}"
                ),
            )
            cfg = Config.load(yaml_path)
            assert cfg.skills[0].config["action_tier"] == tier

    def test_invalid_action_tier_rejected(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - name: skill-x\n    version: '1.0'\n"
                "    config:\n      action_tier: Z"
            ),
        )
        with pytest.raises(ConfigValidationError, match="action_tier"):
            Config.load(yaml_path)

    def test_nested_action_tier_validated(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - name: skill-x\n    version: '1.0'\n"
                "    config:\n      triggers:\n        - action_tier: X"
            ),
        )
        with pytest.raises(ConfigValidationError, match="action_tier"):
            Config.load(yaml_path)

    def test_skill_config_known_keys(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - name: skill-x\n    version: '1.0'\n"
                "    config:\n"
                "      requires_approval_for_soft_actions: true\n"
                "      approval_timeout_seconds: 120\n"
                "      safe_default_action: log_to_dashboard\n"
                "      secondary_contact_number: '+234800000000'"
            ),
        )
        cfg = Config.load(yaml_path)
        sc = cfg.skills[0].config
        assert sc["requires_approval_for_soft_actions"] is True
        assert sc["approval_timeout_seconds"] == 120
        assert sc["safe_default_action"] == "log_to_dashboard"
        assert sc["secondary_contact_number"] == "+234800000000"


# ─── ReasoningConfig ──────────────────────────────────────────────────────────


class TestReasoningConfig:
    def test_escalation_threshold_default(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        cfg = Config.load(yaml_path)
        assert cfg.reasoning.escalation_threshold == pytest.approx(0.70)

    def test_escalation_threshold_custom(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
              escalation_threshold: 0.85
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        cfg = Config.load(yaml_path)
        assert cfg.reasoning.escalation_threshold == pytest.approx(0.85)

    def test_energy_aware_reasoning_parsed(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
              energy_aware_reasoning:
                enabled: true
                throttle_threshold_percent: 20
                critical_threshold_percent: 10
                battery_sensor_id: inverter-battery
                alert_on_throttle: true
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        cfg = Config.load(yaml_path)
        ear = cfg.reasoning.energy_aware_reasoning
        assert ear["enabled"] is True
        assert ear["battery_sensor_id"] == "inverter-battery"

    def test_causal_memory_parsed(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
              causal_memory:
                rejection_expiry_days: 30
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        cfg = Config.load(yaml_path)
        cm = cfg.reasoning.causal_memory
        assert cm["rejection_expiry_days"] == 30


# ─── ActionChannelConfig validation ───────────────────────────────────────────


class TestActionsValidation:
    def test_rejects_invalid_primary_channel(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: telegram
            """,
        )
        with pytest.raises(ConfigValidationError, match="primary_alert_channel"):
            Config.load(yaml_path)

    def test_gpio_pin_coerced_to_int(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
              relay:
                enabled: false
                gpio_pin: 26
            """,
        )
        cfg = Config.load(yaml_path)
        assert isinstance(cfg.actions.relay["gpio_pin"], int)
        assert cfg.actions.relay["gpio_pin"] == 26

    def test_gpio_pin_out_of_bcm_range_raises(self, tmp_path):
        """gpio_pin=45 is outside BCM 2-27 — must raise at config load time."""
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
              relay:
                enabled: true
                gpio_pin: 45
            """,
        )
        with pytest.raises(ConfigValidationError, match="gpio_pin=45"):
            Config.load(yaml_path)


# ─── HAL / Circuit Breaker validation ─────────────────────────────────────────


class TestHalCircuitBreakerValidation:
    def _base_yaml(self, hal_block: str) -> str:
        return f"""
device:
  id: dev-01
  name: Test
  location: Lagos
sensors: []
skills: []
reasoning:
  default_tier: local
  local_model: x
  model_path: /tmp
  offline_fallback: rule
gateway:
  enabled: false
  broker_url: mqtt://localhost
actions:
  primary_alert_channel: sms
hal:
{hal_block}
"""

    def test_failure_threshold_must_be_positive(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  circuit_breaker:\n"
                "    failure_threshold: 0\n"
                "    recovery_timeout_s: 300\n"
                "    success_threshold: 2"
            ),
        )
        with pytest.raises(ConfigValidationError, match="failure_threshold"):
            Config.load(yaml_path)

    def test_recovery_timeout_must_be_positive(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  circuit_breaker:\n"
                "    failure_threshold: 5\n"
                "    recovery_timeout_s: 0\n"
                "    success_threshold: 2"
            ),
        )
        with pytest.raises(ConfigValidationError, match="recovery_timeout_s"):
            Config.load(yaml_path)

    def test_success_threshold_must_be_positive(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  circuit_breaker:\n"
                "    failure_threshold: 5\n"
                "    recovery_timeout_s: 300\n"
                "    success_threshold: 0"
            ),
        )
        with pytest.raises(ConfigValidationError, match="success_threshold"):
            Config.load(yaml_path)

    def test_external_watchdog_gpio_must_be_valid_bcm(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  external_watchdog:\n"
                "    enabled: true\n"
                "    gpio_pin: 45\n"
                "    ping_interval_s: 30"
            ),
        )
        with pytest.raises(
            ConfigValidationError, match="hal.external_watchdog.gpio_pin=45"
        ):
            Config.load(yaml_path)

    def test_external_watchdog_ping_interval_must_be_positive(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  external_watchdog:\n"
                "    enabled: true\n"
                "    gpio_pin: 17\n"
                "    ping_interval_s: 0"
            ),
        )
        with pytest.raises(
            ConfigValidationError,
            match="hal.external_watchdog.ping_interval_s",
        ):
            Config.load(yaml_path)


# ─── Environment variable expansion ───────────────────────────────────────────


class TestEnvExpansion:
    def test_env_var_substituted(self, tmp_path, monkeypatch):
        monkeypatch.setenv("OWNER_PHONE_NUMBER", "+2348012345678")
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
                AT_API_KEY: "mock_key"
                AT_USERNAME: "mock_user"
                OWNER_PHONE_NUMBER: "${OWNER_PHONE_NUMBER}"
            """,
        )
        cfg = Config.load(yaml_path)
        assert cfg.actions.sms["OWNER_PHONE_NUMBER"] == "+2348012345678"

    def test_unset_env_var_preserved_as_literal(self, tmp_path, monkeypatch):
        monkeypatch.delenv("UNSET_VAR", raising=False)
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning:
              default_tier: local
              local_model: x
              model_path: /tmp
              offline_fallback: rule
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
                AT_API_KEY: "mock_key"
                AT_USERNAME: "mock_user"
                OWNER_PHONE_NUMBER: "${UNSET_VAR}"
            """,
        )
        cfg = Config.load(yaml_path)
        assert cfg.actions.sms["OWNER_PHONE_NUMBER"] == "${UNSET_VAR}"


# ─── File not found ───────────────────────────────────────────────────────────


class TestFileErrors:
    def test_missing_file_raises(self):
        with pytest.raises(ConfigValidationError, match="Cannot read"):
            Config.load("/nonexistent/path/ori.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text("device: [\nunclosed bracket")
        with pytest.raises(ConfigValidationError, match="YAML parse error"):
            Config.load(str(p))


class TestActionEnvValidation:
    def _yaml(self, actions_block: str) -> str:
        return f"""
device:
  id: dev-01
  name: Test
  location: Lagos
sensors: []
skills: []
reasoning:
  default_tier: local
  local_model: x
  model_path: /tmp
  offline_fallback: rule
gateway:
  enabled: false
  broker_url: mqtt://localhost
actions:
{actions_block}
"""

    def test_whatsapp_missing_critical_var_raises(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: whatsapp\n"
                "  whatsapp:\n"
                "    enabled: true\n"
                "    TWILIO_ACCOUNT_SID: '${TWILIO_ACCOUNT_SID}'\n"
                "    TWILIO_AUTH_TOKEN: 'token'\n"
                "    TWILIO_WHATSAPP_FROM: 'from'\n"
                "    OWNER_WHATSAPP_NUMBER: 'to'"
            ),
        )
        with pytest.raises(ConfigValidationError, match="TWILIO_ACCOUNT_SID"):
            Config.load(yaml_path)

    def test_sms_missing_critical_var_raises(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: true\n"
                "    AT_API_KEY: 'key'\n"
                "    AT_USERNAME: '${AT_USERNAME}'"
            ),
        )
        with pytest.raises(ConfigValidationError, match="AT_USERNAME"):
            Config.load(yaml_path)

    def test_operator_contact_missing_warns(self, tmp_path, caplog):
        import logging

        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: whatsapp\n"
                "  operator_contact: '${OWNER_PHONE_NUMBER}'\n"
            ),
        )
        with caplog.at_level(logging.WARNING):
            Config.load(yaml_path)
            assert "actions.operator_contact is missing" in caplog.text

    def test_sms_incoming_webhook_missing_token_raises(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: true\n"
                "    AT_API_KEY: 'key'\n"
                "    AT_USERNAME: 'user'\n"
                "    incoming_webhook:\n"
                "      enabled: true\n"
                "      token: '${ORI_SMS_WEBHOOK_TOKEN}'\n"
            ),
        )
        with pytest.raises(ConfigValidationError, match="ORI_SMS_WEBHOOK_TOKEN"):
            Config.load(yaml_path)

    def test_sms_incoming_webhook_token_set_is_valid(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: true\n"
                "    AT_API_KEY: 'key'\n"
                "    AT_USERNAME: 'user'\n"
                "    incoming_webhook:\n"
                "      enabled: true\n"
                "      token: 'super-secret-token'\n"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.actions.sms["incoming_webhook"]["token"] == "super-secret-token"
