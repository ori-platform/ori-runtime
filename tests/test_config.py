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
    monkeypatch.setenv("TWILIO_WHATSAPP_FROM", "whatsapp:+14155238886")
    monkeypatch.setenv("OWNER_WHATSAPP_NUMBER", "whatsapp:+2340000000000")
    monkeypatch.setenv("AT_API_KEY", "mock_key")
    monkeypatch.setenv("AT_USERNAME", "mock_user")
    monkeypatch.setenv("OWNER_PHONE_NUMBER", "+2340000000000")


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
        assert cfg.device.site_type == "office"
        assert cfg.device.rated_capacity_amps == 10.0
        assert cfg.device.country_code == "NG"

    def test_sensors_count_and_types(self):
        cfg = Config.load(EXAMPLE_YAML)
        # example has 3 uncommented sensors
        assert len(cfg.sensors) == 3
        types = {s.type for s in cfg.sensors}
        assert "ads1115_current" in types
        assert "ads1115_voltage" in types
        assert "active_power" in types

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
        assert cfg.gateway.reasoning["enabled"] is True
        assert cfg.gateway.reasoning["timeout_ms"] == 10_000
        assert cfg.gateway.auth["enabled"] is False
        assert cfg.gateway.auth["shared_secret_env"] == "GATEWAY_SHARED_SECRET"
        assert cfg.gateway.auth["max_clock_skew_ms"] == 300_000
        assert cfg.gateway.auth["replay_ttl_ms"] == 300_000
        assert cfg.gateway.tls["enabled"] is False
        assert cfg.gateway.tls["ca_certfile"] == ""
        assert cfg.gateway.tls["certfile"] == ""
        assert cfg.gateway.tls["keyfile"] == ""
        assert cfg.gateway.tls["keyfile_password_env"] == ""

    def test_gateway_tls_keyfile_requires_certfile(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway:
              enabled: true
              broker_url: mqtts://broker.local
              tls:
                enabled: true
                keyfile: /etc/ori/certs/runtime.key
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            """,
        )

        with pytest.raises(ConfigValidationError, match="gateway.tls.certfile"):
            Config.load(yaml_path)

    def test_gateway_tls_key_password_requires_keyfile(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway:
              enabled: true
              broker_url: mqtts://broker.local
              tls:
                enabled: true
                certfile: /etc/ori/certs/runtime.crt
                keyfile_password_env: MQTT_KEY_PASSWORD
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            """,
        )

        with pytest.raises(ConfigValidationError, match="gateway.tls.keyfile"):
            Config.load(yaml_path)

    def test_gateway_tls_rejects_insecure_skip_verify(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway:
              enabled: true
              broker_url: mqtts://broker.local
              tls:
                enabled: true
                insecure_skip_verify: true
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            """,
        )

        with pytest.raises(ConfigValidationError, match="insecure_skip_verify"):
            Config.load(yaml_path)

    def test_gateway_auth_requires_secret_env_when_enabled(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway:
              enabled: true
              broker_url: mqtt://broker.local
              auth:
                enabled: true
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            """,
        )

        with pytest.raises(
            ConfigValidationError, match="gateway.auth.shared_secret_env"
        ):
            Config.load(yaml_path)

    def test_gateway_auth_bounds_must_be_positive(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway:
              enabled: true
              broker_url: mqtt://broker.local
              auth:
                enabled: true
                shared_secret_env: GATEWAY_SHARED_SECRET
                max_clock_skew_ms: 999
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            """,
        )

        with pytest.raises(ConfigValidationError, match="max_clock_skew_ms"):
            Config.load(yaml_path)

    def test_gateway_reasoning_timeout_must_be_at_least_100ms(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway:
              enabled: true
              broker_url: mqtt://broker.local
              reasoning:
                enabled: true
                timeout_ms: 50
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            """,
        )

        with pytest.raises(ConfigValidationError, match="gateway.reasoning.timeout_ms"):
            Config.load(yaml_path)

    def test_gateway_reasoning_timeout_must_be_integer(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway:
              enabled: true
              broker_url: mqtt://broker.local
              reasoning:
                enabled: true
                timeout_ms: not-a-number
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            """,
        )

        with pytest.raises(ConfigValidationError, match="gateway.reasoning.timeout_ms"):
            Config.load(yaml_path)

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
        status = cfg.hal.status_signaling
        assert status["enabled"] is False
        assert status["power_led_pin"] == 17
        assert status["relay_led_pin"] == 27
        assert status["network_led_pin"] == 22
        assert status["health_led_pin"] == 23
        assert status["buzzer_pin"] == 24
        assert status["tick_ms"] == 100

    def test_health_socket_defaults(self):
        cfg = Config.load(EXAMPLE_YAML)
        assert cfg.health_socket["enabled"] is True
        assert cfg.health_socket["path"] == "/run/ori/health.sock"
        assert cfg.health_socket["mode"] == 0o660

    def test_security_remote_commands_defaults(self):
        cfg = Config.load(EXAMPLE_YAML)
        remote = cfg.security["remote_commands"]
        assert remote["enabled"] is False
        assert remote["hmac_secret_env"] == "ORI_REMOTE_COMMAND_HMAC_SECRET"
        assert remote["max_skew_seconds"] == 300
        assert remote["allow_unlisted_senders"] is False
        assert remote["allowed_senders"] == {
            "sms": ["+2340000000000"],
            "whatsapp": ["whatsapp:+2340000000000"],
        }
        lockout = remote["lockout"]
        assert lockout["risk_window_ms"] == 3_600_000
        assert lockout["state_stale_after_ms"] == 3_600_000
        assert lockout["incident_sender_limit"] == 50
        assert lockout["elevated_incident_threshold"] == 1
        assert lockout["critical_incident_threshold"] == 3
        assert lockout["elevated_rejection_threshold"] == 5
        assert lockout["critical_rejection_threshold"] == 15
        assert lockout["enforcement_enabled"] is False

    def test_gateway_message_secret_separate_from_remote_command_secret(self):
        cfg = Config.load(EXAMPLE_YAML)

        assert cfg.gateway.auth["shared_secret_env"] == "GATEWAY_SHARED_SECRET"
        assert (
            cfg.gateway.auth["shared_secret_env"]
            != cfg.security["remote_commands"]["hmac_secret_env"]
        )

    def test_security_remote_command_lockout_overrides(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway: {}
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            security:
              remote_commands:
                enabled: false
                lockout:
                  risk_window_ms: 120000
                  state_stale_after_ms: 240000
                  incident_sender_limit: 7
                  elevated_incident_threshold: 2
                  critical_incident_threshold: 4
                  elevated_rejection_threshold: 8
                  critical_rejection_threshold: 20
                  enforcement_enabled: true
            """,
        )

        cfg = Config.load(yaml_path)

        lockout = cfg.security["remote_commands"]["lockout"]
        assert lockout["risk_window_ms"] == 120_000
        assert lockout["state_stale_after_ms"] == 240_000
        assert lockout["incident_sender_limit"] == 7
        assert lockout["elevated_incident_threshold"] == 2
        assert lockout["critical_incident_threshold"] == 4
        assert lockout["elevated_rejection_threshold"] == 8
        assert lockout["critical_rejection_threshold"] == 20
        assert lockout["enforcement_enabled"] is False

    def test_security_remote_command_allowed_senders_are_normalized(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway: {}
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            security:
              remote_commands:
                enabled: true
                hmac_secret_env: ORI_REMOTE_COMMAND_HMAC_SECRET
                allow_unlisted_senders: true
                allowed_senders:
                  sms:
                    - " +234 801 234 5678 "
                    - "+2348012345678"
                  whatsapp:
                    - " WhatsApp:+2348012345678 "
            """,
        )

        cfg = Config.load(yaml_path)

        remote = cfg.security["remote_commands"]
        assert remote["allow_unlisted_senders"] is True
        assert remote["allowed_senders"] == {
            "sms": ["+2348012345678"],
            "whatsapp": ["whatsapp:+2348012345678"],
        }

    def test_os_sandbox_defaults(self):
        cfg = Config.load(EXAMPLE_YAML)
        assert cfg.os_sandbox["enabled"] is True
        assert cfg.os_sandbox["require_for_community"] is False
        assert cfg.os_sandbox["exec_timeout_ms"] == 2000
        assert cfg.os_sandbox["max_output_bytes"] == 65536


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

    def test_invalid_device_timezone_falls_back_to_host_tz_env(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("TZ", "Europe/London")
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
              timezone: Invalid/Timezone
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
        assert cfg.device.timezone == "Europe/London"

    def test_missing_device_timezone_falls_back_to_host_tz_env(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("TZ", "America/New_York")
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
        assert cfg.device.timezone == "America/New_York"

    def test_timezone_falls_back_to_utc_when_config_and_host_unavailable(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr("ori.config._detect_host_timezone", lambda: None)
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
              timezone: Invalid/Timezone
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
        assert cfg.device.timezone == "UTC"

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

    def test_accepts_valid_country_code(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Nairobi
              country_code: ke
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
        assert cfg.device.country_code == "KE"

    def test_rejects_invalid_country_code(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Test
              country_code: NGR
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
        with pytest.raises(ConfigValidationError, match="country_code"):
            Config.load(yaml_path)


# ─── Security validation ──────────────────────────────────────────────────────


class TestSecurityValidation:
    def test_rejects_non_mapping_security(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway: {}
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            security: []
            """,
        )

        with pytest.raises(ConfigValidationError, match="security"):
            Config.load(yaml_path)

    def test_rejects_invalid_remote_command_skew(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway: {}
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            security:
              remote_commands:
                enabled: true
                hmac_secret_env: ORI_REMOTE_COMMAND_HMAC_SECRET
                max_skew_seconds: -1
            """,
        )

        with pytest.raises(ConfigValidationError, match="max_skew_seconds"):
            Config.load(yaml_path)

    def test_rejects_invalid_remote_command_lockout_value(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway: {}
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            security:
              remote_commands:
                lockout:
                  risk_window_ms: -1
            """,
        )

        with pytest.raises(ConfigValidationError, match="risk_window_ms"):
            Config.load(yaml_path)

    def test_rejects_invalid_remote_command_allowed_senders(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway: {}
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            security:
              remote_commands:
                allowed_senders:
                  sms: "+2348012345678"
            """,
        )

        with pytest.raises(ConfigValidationError, match="allowed_senders.sms"):
            Config.load(yaml_path)

    def test_rejects_remote_command_lockout_critical_below_elevated(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
            device:
              id: dev-01
              name: Test
              location: Lagos
            sensors: []
            skills: []
            reasoning: {}
            gateway: {}
            actions:
              primary_alert_channel: sms
              sms:
                enabled: false
            security:
              remote_commands:
                lockout:
                  elevated_rejection_threshold: 10
                  critical_rejection_threshold: 5
            """,
        )

        with pytest.raises(ConfigValidationError, match="critical_rejection_threshold"):
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

    def test_accepts_zigbee_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: living-room-temp\n    type: temperature\n    protocol: zigbee\n    poll_interval_ms: 1000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "zigbee"

    def test_accepts_lorawan_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: field-temp\n    type: lorawan_temperature\n    protocol: lorawan\n    poll_interval_ms: 5000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "lorawan"

    def test_accepts_mqtt_perception_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: ppe-hardhat-cam-01\n    type: ppe_hardhat_violation_score\n    protocol: mqtt_perception\n    poll_interval_ms: 1000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "mqtt_perception"

    def test_accepts_mqtt_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: chiller-supply\n    type: temperature\n    protocol: mqtt\n    poll_interval_ms: 1000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "mqtt"

    def test_accepts_opcua_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: plc-temperature\n    type: temperature\n    protocol: opcua\n    poll_interval_ms: 1000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "opcua"

    def test_accepts_smart_protocol(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  - id: drive-health\n    type: drive_temp_celsius\n    protocol: smart\n    poll_interval_ms: 60000"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "smart"

    def test_accepts_coap_protocol_with_required_fields(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
device:
  id: dev-01
  name: Test
  location: Lagos
sensors:
  - id: coap-temp-01
    type: temperature
    protocol: coap
    poll_interval_ms: 1000
    uri: coap://192.168.1.70/telemetry/temp
    method: GET
    json_path: metrics.temp_c
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
  coap:
    enabled: false
    allowed_hosts: ["192.168.1.70"]
""",
        )
        cfg = Config.load(yaml_path)
        assert cfg.sensors[0].protocol == "coap"
        assert cfg.sensors[0].metadata["uri"].startswith("coap://")

    def test_rejects_coap_sensor_without_uri(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
device:
  id: dev-01
  name: Test
  location: Lagos
sensors:
  - id: coap-temp-01
    type: temperature
    protocol: coap
    poll_interval_ms: 1000
    json_path: metrics.temp_c
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
  coap:
    enabled: false
    allowed_hosts: ["192.168.1.70"]
""",
        )
        with pytest.raises(ConfigValidationError, match="require 'uri'"):
            Config.load(yaml_path)

    def test_rejects_coap_sensor_when_host_not_in_global_allowlist(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            """
device:
  id: dev-01
  name: Test
  location: Lagos
sensors:
  - id: coap-temp-01
    type: temperature
    protocol: coap
    poll_interval_ms: 1000
    uri: coap://10.0.0.9/telemetry/temp
    method: GET
    json_path: metrics.temp_c
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
  coap:
    enabled: false
    allowed_hosts: ["192.168.1.70"]
""",
        )
        with pytest.raises(ConfigValidationError, match="allowed_hosts"):
            Config.load(yaml_path)

    def test_accepts_coap_action_config(self, tmp_path):
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
  coap:
    enabled: true
    allowed_hosts: ["192.168.1.70"]
    commands:
      open_bypass_valve:
        uri: coap://192.168.1.70/actuators/bypass
        method: POST
        payload: '{"state":"open"}'
""",
        )
        cfg = Config.load(yaml_path)
        assert cfg.actions.coap["enabled"] is True
        assert "open_bypass_valve" in cfg.actions.coap["commands"]

    def test_rejects_coap_enabled_without_allowlist(self, tmp_path):
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
  coap:
    enabled: true
    commands:
      open_bypass_valve:
        uri: coap://192.168.1.70/actuators/bypass
        method: POST
""",
        )
        with pytest.raises(ConfigValidationError, match="allowed_hosts"):
            Config.load(yaml_path)


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

    def test_capability_posture_defaults(self, tmp_path):
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
        cp = cfg.reasoning.capability_posture
        assert cp["enabled"] is True
        assert cp["probe_interval_seconds"] == 30
        assert cp["gateway_heartbeat_ttl_seconds"] == 30

    def test_capability_posture_custom_values(self, tmp_path):
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
              capability_posture:
                enabled: true
                probe_interval_seconds: 20
                gateway_heartbeat_ttl_seconds: 25
                internet_probe_timeout_ms: 1500
                internet_probe_port: 443
                internet_probe_host: one.one.one.one
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        cfg = Config.load(yaml_path)
        cp = cfg.reasoning.capability_posture
        assert cp["probe_interval_seconds"] == 20
        assert cp["gateway_heartbeat_ttl_seconds"] == 25
        assert cp["internet_probe_timeout_ms"] == 1500
        assert cp["internet_probe_port"] == 443
        assert cp["internet_probe_host"] == "one.one.one.one"

    def test_capability_posture_rejects_probe_interval_over_30(self, tmp_path):
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
              capability_posture:
                probe_interval_seconds: 31
            gateway:
              enabled: false
              broker_url: mqtt://localhost
            actions:
              primary_alert_channel: sms
            """,
        )
        with pytest.raises(
            ConfigValidationError,
            match="probe_interval_seconds must be between 1 and 30",
        ):
            Config.load(yaml_path)


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

    def test_relay_gpio_conflicts_status_signaling_relay_led_pin(self, tmp_path):
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
                gpio_pin: 26
            hal:
              status_signaling:
                enabled: true
                power_led_pin: 17
                relay_led_pin: 26
                network_led_pin: 22
                health_led_pin: 23
                buzzer_pin: 24
                tick_ms: 100
            """,
        )
        with pytest.raises(
            ConfigValidationError,
            match="hal.status_signaling.relay_led_pin conflicts with actions.relay.gpio_pin",
        ):
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

    def test_status_signaling_pin_must_be_valid_bcm(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  status_signaling:\n"
                "    enabled: true\n"
                "    power_led_pin: 45\n"
                "    relay_led_pin: 27\n"
                "    network_led_pin: 22\n"
                "    health_led_pin: 23\n"
                "    buzzer_pin: 24\n"
                "    tick_ms: 100"
            ),
        )
        with pytest.raises(
            ConfigValidationError, match="hal.status_signaling.power_led_pin=45"
        ):
            Config.load(yaml_path)

    def test_status_signaling_pins_must_be_unique(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  status_signaling:\n"
                "    enabled: true\n"
                "    power_led_pin: 17\n"
                "    relay_led_pin: 17\n"
                "    network_led_pin: 22\n"
                "    health_led_pin: 23\n"
                "    buzzer_pin: 24\n"
                "    tick_ms: 100"
            ),
        )
        with pytest.raises(ConfigValidationError, match="pins must be unique"):
            Config.load(yaml_path)

    def test_status_signaling_tick_must_be_min_50(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  status_signaling:\n"
                "    enabled: true\n"
                "    power_led_pin: 17\n"
                "    relay_led_pin: 27\n"
                "    network_led_pin: 22\n"
                "    health_led_pin: 23\n"
                "    buzzer_pin: 24\n"
                "    tick_ms: 40"
            ),
        )
        with pytest.raises(ConfigValidationError, match="tick_ms must be >= 50"):
            Config.load(yaml_path)

    def test_status_signaling_power_pin_conflicts_external_watchdog(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._base_yaml(
                "  external_watchdog:\n"
                "    enabled: true\n"
                "    gpio_pin: 17\n"
                "    ping_interval_s: 30\n"
                "  status_signaling:\n"
                "    enabled: true\n"
                "    power_led_pin: 17\n"
                "    relay_led_pin: 27\n"
                "    network_led_pin: 22\n"
                "    health_led_pin: 23\n"
                "    buzzer_pin: 24\n"
                "    tick_ms: 100"
            ),
        )
        with pytest.raises(
            ConfigValidationError,
            match="power_led_pin conflicts with hal.external_watchdog.gpio_pin",
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

    def test_whatsapp_from_must_use_whatsapp_prefix(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TWILIO_ACCOUNT_SID", "sid")
        monkeypatch.setenv("TWILIO_AUTH_TOKEN", "token")
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: whatsapp\n"
                "  whatsapp:\n"
                "    enabled: true\n"
                "    TWILIO_ACCOUNT_SID: '${TWILIO_ACCOUNT_SID}'\n"
                "    TWILIO_AUTH_TOKEN: '${TWILIO_AUTH_TOKEN}'\n"
                "    TWILIO_WHATSAPP_FROM: '+14155238886'\n"
            ),
        )
        with pytest.raises(
            ConfigValidationError, match="must start with 'whatsapp:\\+'"
        ):
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

    def test_sms_invalid_transport_raises(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: true\n"
                "    transport: satellite\n"
                "    AT_API_KEY: 'key'\n"
                "    AT_USERNAME: 'user'\n"
            ),
        )
        with pytest.raises(ConfigValidationError, match="actions.sms.transport"):
            Config.load(yaml_path)

    def test_sms_gsm_transport_does_not_require_at_credentials(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: true\n"
                "    transport: gsm\n"
                "    gsm:\n"
                "      enabled: true\n"
                "      port: '/dev/ttyUSB0'\n"
                "      baud: 115200\n"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.actions.sms["transport"] == "gsm"

    def test_sms_gsm_transport_requires_port(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: true\n"
                "    transport: gsm\n"
                "    gsm:\n"
                "      enabled: true\n"
                "      baud: 115200\n"
            ),
        )
        with pytest.raises(ConfigValidationError, match="actions.sms.gsm.port"):
            Config.load(yaml_path)

    def test_sms_hybrid_transport_accepts_gsm_without_ip_credentials(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: true\n"
                "    transport: hybrid\n"
                "    gsm:\n"
                "      enabled: true\n"
                "      port: '/dev/ttyUSB0'\n"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.actions.sms["transport"] == "hybrid"

    def test_sms_hybrid_transport_requires_at_least_one_path(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: true\n"
                "    transport: hybrid\n"
            ),
        )
        with pytest.raises(ConfigValidationError, match="at least one configured"):
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

    def test_local_console_defaults(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml("  primary_alert_channel: sms\n  sms:\n    enabled: false\n"),
        )
        cfg = Config.load(yaml_path)
        assert cfg.actions.local_console["enabled"] is False
        assert cfg.actions.local_console["poll_interval_ms"] == 1000
        assert cfg.actions.local_console["approval_channel_id"] == "local_console"
        assert cfg.actions.offline_tokens["enabled"] is False
        assert cfg.actions.offline_tokens["max_clock_skew_s"] == 300

    def test_local_console_poll_interval_minimum(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  local_console:\n"
                "    enabled: true\n"
                "    poll_interval_ms: 10\n"
            ),
        )
        with pytest.raises(
            ConfigValidationError,
            match="actions.local_console.poll_interval_ms must be >= 100",
        ):
            Config.load(yaml_path)

    def test_offline_tokens_enabled_requires_public_key(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: false\n"
                "  offline_tokens:\n"
                "    enabled: true\n"
            ),
        )
        with pytest.raises(
            ConfigValidationError,
            match="actions.offline_tokens.enabled=true requires",
        ):
            Config.load(yaml_path)

    def test_offline_tokens_enabled_with_public_key_is_valid(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "  primary_alert_channel: sms\n"
                "  sms:\n"
                "    enabled: false\n"
                "  offline_tokens:\n"
                "    enabled: true\n"
                "    public_key_b64: 'dGVzdA=='\n"
                "    max_clock_skew_s: 10\n"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.actions.offline_tokens["enabled"] is True
        assert cfg.actions.offline_tokens["max_clock_skew_s"] == 10


class TestDevicePolicyConfig:
    def _yaml(self, extra_block: str = "") -> str:
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
{extra_block}
"""

    def test_defaults_when_block_missing(self, tmp_path):
        yaml_path = _write_yaml(tmp_path, self._yaml())
        cfg = Config.load(yaml_path)
        assert cfg.device_policy["enabled"] is False
        assert cfg.device_policy["url"] == ""
        assert cfg.device_policy["auth_token"] == ""
        assert cfg.device_policy["public_key_b64"] == ""
        assert cfg.device_policy["request_timeout_ms"] == 3000
        assert cfg.device_policy["max_clock_skew_s"] == 300
        assert cfg.device_policy["refresh_enabled"] is False
        assert cfg.device_policy["refresh_interval_s"] == 21600

    def test_enabled_requires_https_url(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "device_policy:\n"
                "  enabled: true\n"
                "  url: http://localhost/policy\n"
                "  auth_token: token\n"
                "  public_key_b64: key\n"
            ),
        )
        with pytest.raises(ConfigValidationError, match="must start with https://"):
            Config.load(yaml_path)

    def test_enabled_requires_auth_token(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "device_policy:\n"
                "  enabled: true\n"
                "  url: https://example.com/policy\n"
                "  auth_token: ''\n"
                "  public_key_b64: key\n"
            ),
        )
        with pytest.raises(ConfigValidationError, match="auth_token"):
            Config.load(yaml_path)

    def test_enabled_requires_public_key(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "device_policy:\n"
                "  enabled: true\n"
                "  url: https://example.com/policy\n"
                "  auth_token: token\n"
                "  public_key_b64: ''\n"
            ),
        )
        with pytest.raises(ConfigValidationError, match="public_key_b64"):
            Config.load(yaml_path)

    def test_enabled_valid_configuration(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "device_policy:\n"
                "  enabled: true\n"
                "  url: https://example.com/policy\n"
                "  auth_token: token\n"
                "  public_key_b64: dGVzdA==\n"
                "  request_timeout_ms: 5000\n"
                "  max_clock_skew_s: 120\n"
                "  refresh_enabled: true\n"
                "  refresh_interval_s: 3600\n"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.device_policy["enabled"] is True
        assert cfg.device_policy["url"] == "https://example.com/policy"
        assert cfg.device_policy["request_timeout_ms"] == 5000
        assert cfg.device_policy["max_clock_skew_s"] == 120
        assert cfg.device_policy["refresh_enabled"] is True
        assert cfg.device_policy["refresh_interval_s"] == 3600

    def test_refresh_interval_minimum_enforced(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "device_policy:\n"
                "  enabled: false\n"
                "  refresh_enabled: true\n"
                "  refresh_interval_s: 59\n"
            ),
        )
        with pytest.raises(
            ConfigValidationError,
            match="refresh_interval_s must be >= 60",
        ):
            Config.load(yaml_path)


class TestHealthSocketConfig:
    def _yaml(self, extra_block: str = "") -> str:
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
{extra_block}
"""

    def test_defaults_when_block_missing(self, tmp_path):
        yaml_path = _write_yaml(tmp_path, self._yaml())
        cfg = Config.load(yaml_path)
        assert cfg.health_socket["enabled"] is True
        assert cfg.health_socket["path"] == "/run/ori/health.sock"
        assert cfg.health_socket["mode"] == 0o660

    def test_rejects_empty_path(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml("health_socket:\n  enabled: true\n  path: ''\n"),
        )
        with pytest.raises(ConfigValidationError, match="health_socket.path"):
            Config.load(yaml_path)

    def test_rejects_invalid_mode(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml("health_socket:\n  enabled: true\n  mode: invalid\n"),
        )
        with pytest.raises(ConfigValidationError, match="health_socket.mode"):
            Config.load(yaml_path)

    def test_accepts_mode_string(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml(
                "health_socket:\n"
                "  enabled: true\n"
                "  path: /tmp/ori-health.sock\n"
                "  mode: '0o666'\n"
            ),
        )
        cfg = Config.load(yaml_path)
        assert cfg.health_socket["mode"] == 0o666


class TestOSSandboxConfig:
    def _yaml(self, extra_block: str = "") -> str:
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
{extra_block}
"""

    def test_defaults_when_block_missing(self, tmp_path):
        cfg = Config.load(_write_yaml(tmp_path, self._yaml()))
        assert cfg.os_sandbox["enabled"] is True
        assert cfg.os_sandbox["require_for_community"] is False
        assert cfg.os_sandbox["exec_timeout_ms"] == 2000
        assert cfg.os_sandbox["max_output_bytes"] == 65536

    def test_rejects_invalid_numeric_fields(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml("os_sandbox:\n  exec_timeout_ms: abc\n"),
        )
        with pytest.raises(ConfigValidationError, match="os_sandbox.exec_timeout_ms"):
            Config.load(yaml_path)

    def test_rejects_too_small_limits(self, tmp_path):
        yaml_path = _write_yaml(
            tmp_path,
            self._yaml("os_sandbox:\n  exec_timeout_ms: 10\n  max_output_bytes: 100\n"),
        )
        with pytest.raises(ConfigValidationError, match="exec_timeout_ms"):
            Config.load(yaml_path)


class TestReasoningDefaultTierValidation:
    def _yaml(self, tier: str) -> str:
        return f"""
device:
  id: dev-01
  name: Test
  location: Lagos
sensors: []
skills: []
reasoning:
  default_tier: {tier}
  local_model: x
  model_path: /tmp
  offline_fallback: rule
gateway:
  enabled: false
  broker_url: mqtt://localhost
actions:
  primary_alert_channel: sms
"""

    def test_rejects_gateway_default_tier_pre_v1(self, tmp_path):
        yaml_path = _write_yaml(tmp_path, self._yaml("gateway"))
        with pytest.raises(ConfigValidationError, match="reasoning.default_tier"):
            Config.load(yaml_path)

    def test_rejects_cloud_default_tier_pre_v1(self, tmp_path):
        yaml_path = _write_yaml(tmp_path, self._yaml("cloud"))
        with pytest.raises(ConfigValidationError, match="reasoning.default_tier"):
            Config.load(yaml_path)
