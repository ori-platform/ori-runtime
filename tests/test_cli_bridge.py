# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import base64
import json
import textwrap
from pathlib import Path

import yaml

from ori import cli_bridge
from ori.network.events import ActionResult, OriEvent, SensorReading
from ori.security.config_signatures import (
    CONFIG_SIGNATURE_SCHEMA,
    canonical_config_signature_payload,
)
from ori.state.store import StateStore


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


def _sign_config_yaml(content: str, private_key) -> str:
    raw = yaml.safe_load(textwrap.dedent(content))
    raw["config_signature"] = {
        "schema": CONFIG_SIGNATURE_SCHEMA,
        "signer_id": "product-provisioning-test",
        "signed_at_ms": 1_800_000_000_000,
        "signature": "ed25519:",
    }
    signature = private_key.sign(canonical_config_signature_payload(raw))
    raw["config_signature"]["signature"] = "ed25519:" + base64.b64encode(
        signature
    ).decode("ascii")
    return yaml.safe_dump(raw, sort_keys=False)


def _base_config(*, deployment_type: str = "phone") -> str:
    return f"""
    device:
      id: {deployment_type}-01
      name: Test Device
      location: Lagos
      deployment_type: {deployment_type}
      deployment_profile: development
    sensors:
      - id: pzem-power
        type: usb_power
        protocol: usb_serial
        poll_interval_ms: 1000
        device_path: socket://127.0.0.1:17891
    skills: []
    reasoning: {{}}
    gateway:
      enabled: false
    telemetry_export:
      enabled: true
      endpoint: http://127.0.0.1:8010/runtime/telemetry
      api_key_env: ORI_DEVICE_API_KEY
      flush_interval_s: 30
      batch_size: 50
      timeout_ms: 3000
      max_queue_size: 1000
    device_policy:
      enabled: false
    actions:
      primary_alert_channel: sms
      operator_contact: "+2348012345678"
      sms:
        enabled: false
      relay:
        enabled: false
    security:
      config_signature:
        require_signed: false
      skills:
        require_signed: false
    """


def _write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "ori.yaml"
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


def _read_stdout_json(capsys) -> dict:
    captured = capsys.readouterr()
    assert captured.err == ""
    return json.loads(captured.out)


async def _seed_state_store(path: Path) -> None:
    store = StateStore(str(path))
    await store.open()
    try:
        await store.append_history(
            OriEvent.from_reading(
                SensorReading(
                    sensor_id="pir_01",
                    sensor_type="motion",
                    value=1.0,
                    unit="binary",
                    timestamp=1_800_000_000_000,
                    quality=0.95,
                    metadata={"source": "test"},
                ),
                device_id="dev-01",
            )
        )
        await store.log_action_for_event(
            ActionResult(
                action_name="trip_relay",
                tier="D",
                executed=True,
                approved=None,
                action_taken="open_relay",
                timestamp=1_800_000_000_100,
            ),
            trigger_name="dangerous_overcurrent",
            device_id="dev-01",
            sensor_id="pir_01",
            sensor_type="motion",
        )
    finally:
        await store.close()


def test_cli_bridge_config_validate_reports_signed_phone_posture(
    tmp_path, monkeypatch, capsys
):
    private_key, public_key_b64 = _ed25519_keypair()
    monkeypatch.setenv("ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64", public_key_b64)
    config_path = _write_config(
        tmp_path,
        _sign_config_yaml(
            _base_config().replace("require_signed: false", "require_signed: true"),
            private_key,
        ),
    )

    rc = cli_bridge.main(["config-validate", "--path", str(config_path)])

    payload = _read_stdout_json(capsys)
    assert rc == 0
    assert payload["ok"] is True
    result = payload["result"]["config"]
    assert result["device"]["deployment_type"] == "phone"
    assert result["config_signature"] == {
        "required": True,
        "verified": True,
        "signer_id": "product-provisioning-test",
        "signed_at_ms": 1_800_000_000_000,
        "trust_anchor_env": "ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64",
    }
    assert result["telemetry_export"]["api_key_env"] == "ORI_DEVICE_API_KEY"
    assert result["telemetry_export"]["endpoint_host"] == "127.0.0.1"
    assert result["phone_runtime_mobile"]["applies"] is True
    assert result["phone_runtime_mobile"]["socket_bridge_sensor_ids"] == ["pzem-power"]
    assert result["phone_runtime_mobile"]["tier_c_physical_authority"] is False
    assert public_key_b64 not in json.dumps(payload)


def test_cli_bridge_config_validate_accepts_public_noun_verb_command(tmp_path, capsys):
    config_path = _write_config(tmp_path, _base_config())

    rc = cli_bridge.main(["config", "validate", "--path", str(config_path)])

    payload = _read_stdout_json(capsys)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["command"] == "config validate"
    assert payload["result"]["valid"] is True


def test_cli_bridge_config_show_preserves_edge_node_deployment_type(tmp_path, capsys):
    config_path = _write_config(tmp_path, _base_config(deployment_type="edge_node"))

    rc = cli_bridge.main(["config", "show", "--path", str(config_path)])

    payload = _read_stdout_json(capsys)
    assert rc == 0
    result = payload["result"]["config"]
    assert result["device"]["deployment_type"] == "edge_node"
    assert result["phone_runtime_mobile"]["applies"] is False
    assert result["phone_runtime_mobile"]["tier_c_physical_authority"] is None


def test_cli_bridge_config_show_accepts_legacy_alias_during_cli_migration(
    tmp_path, capsys
):
    config_path = _write_config(tmp_path, _base_config(deployment_type="edge_node"))

    rc = cli_bridge.main(["config-show", "--path", str(config_path)])

    payload = _read_stdout_json(capsys)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["command"] == "config show"


def test_cli_bridge_invalid_config_returns_structured_json(tmp_path, capsys):
    config_path = _write_config(
        tmp_path,
        _base_config(deployment_type="edge-phone"),
    )

    rc = cli_bridge.main(["config-validate", "--path", str(config_path)])

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "config_validation_error"
    assert "deployment_type" in payload["error"]["detail"]


def test_cli_bridge_health_snapshot_preserves_device_policy_caps(monkeypatch, capsys):
    async def _fake_health_snapshot(socket_path: str, timeout_ms: int):
        assert socket_path == "/tmp/ori-health.sock"
        assert timeout_ms == 500
        return {
            "schema_version": 1,
            "ok": True,
            "health": {
                "device_id": "phone-01",
                "device_policy": {
                    "available": True,
                    "alert_sms_monthly_cap": 10,
                    "alert_whatsapp_monthly_cap": 20,
                },
            },
        }

    monkeypatch.setattr(cli_bridge, "_read_health_snapshot", _fake_health_snapshot)

    rc = cli_bridge.main(
        [
            "health",
            "snapshot",
            "--socket",
            "/tmp/ori-health.sock",
            "--timeout-ms",
            "500",
        ]
    )

    payload = _read_stdout_json(capsys)
    assert rc == 0
    assert payload["result"]["health"]["device_policy"]["alert_sms_monthly_cap"] == 10
    assert (
        payload["result"]["health"]["device_policy"]["alert_whatsapp_monthly_cap"] == 20
    )


def test_cli_bridge_state_action_log_reads_runtime_store(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    asyncio.run(_seed_state_store(tmp_path / "ori_state.db"))

    rc = cli_bridge.main(["state", "action-log", "limit=5"])

    payload = _read_stdout_json(capsys)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["command"] == "state action-log"
    assert payload["result"][0]["action_name"] == "trip_relay"
    assert payload["result"][0]["tier"] == "D"
    assert payload["result"][0]["executed"] is True
    assert payload["result"][0]["sensor_id"] == "pir_01"


def test_cli_bridge_state_history_requires_sensor_id(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    asyncio.run(_seed_state_store(tmp_path / "ori_state.db"))

    rc = cli_bridge.main(["state", "history", "limit=5"])

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["command"] == "state history"
    assert payload["error"]["code"] == "invalid_arguments"
    assert "sensor_id" in payload["error"]["detail"]


def test_cli_bridge_state_history_reads_bounded_sensor_history(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    asyncio.run(_seed_state_store(tmp_path / "ori_state.db"))

    rc = cli_bridge.main(["state", "history", "sensor_id=pir_01", "limit=5"])

    payload = _read_stdout_json(capsys)
    assert rc == 0
    assert payload["ok"] is True
    assert payload["command"] == "state history"
    assert payload["result"] == [
        {
            "sensor_id": "pir_01",
            "sensor_type": "motion",
            "value": 1.0,
            "unit": "binary",
            "timestamp": 1_800_000_000_000,
            "quality": 0.95,
            "metadata": {"source": "test"},
        }
    ]


def test_cli_bridge_state_rejects_unknown_filter(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    asyncio.run(_seed_state_store(tmp_path / "ori_state.db"))

    rc = cli_bridge.main(["state", "action-log", "table=sensor_history"])

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "invalid_arguments"
    assert "unsupported filter" in payload["error"]["detail"]


def test_cli_bridge_state_rejects_missing_database(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    rc = cli_bridge.main(["state", "action-log"])

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "state_store_unavailable"
    assert not (tmp_path / "ori_state.db").exists()


def test_cli_bridge_skills_validate_reports_invalid_skill(tmp_path, capsys):
    skill_dir = tmp_path / "skills" / "bad-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent(
            """
            name: bad-skill
            version: 0.1.0
            author: test
            signature: bundled
            sensors_required:
              - type: usb_power
            triggers:
              - name: missing_tier
                condition: value > 1
            actions:
              available:
                - name: log_to_dashboard
                  tier: A
              defaults:
                missing_tier: [log_to_dashboard]
            """
        ),
        encoding="utf-8",
    )

    rc = cli_bridge.main(
        ["skills", "validate", "--skills-dir", str(tmp_path / "skills")]
    )

    payload = _read_stdout_json(capsys)
    assert rc == 0
    assert payload["result"]["valid"] is False
    assert payload["result"]["skill_count"] == 0
    assert payload["result"]["errors"][0]["code"] == "skill_validation_error"
    assert "action_tier" in payload["result"]["errors"][0]["detail"]


def test_cli_bridge_unknown_command_returns_json_error(capsys):
    rc = cli_bridge.main(["unknown"])

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "unknown_command"


def test_cli_bridge_public_group_requires_supported_subcommand(capsys):
    rc = cli_bridge.main(["config", "reload"])

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "unknown_command"
    assert "expected one of: show, validate" in payload["error"]["detail"]
