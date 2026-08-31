# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import base64
import json
import textwrap
from pathlib import Path

import pytest
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
    assert monkeypatch is not None, "a hardened config needs monkeypatch for its anchor"
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
    # A skill that never parsed is not activatable either. Reporting it as
    # activatable would describe a malformed skill as runnable.
    assert payload["result"]["activatable"] is False
    assert payload["result"]["skill_count"] == 0
    assert payload["result"]["errors"][0]["code"] == "skill_validation_error"
    assert "action_tier" in payload["result"]["errors"][0]["detail"]


_ACTIVATABLE_SKILL = """
name: community-skill
version: 0.1.0
author: test
signature: bundled
sensors_required:
  - type: usb_power
triggers:
  - name: warm
    condition: value > 1
    action_tier: A
actions:
  available:
    - name: log_to_dashboard
      tier: A
  defaults:
    warm: [log_to_dashboard]
"""


def _write_community_skill_with_hooks(tmp_path: Path) -> Path:
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "community-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent(_ACTIVATABLE_SKILL), encoding="utf-8"
    )
    (skill_dir / "hooks.py").write_text("MARKER = 1\n", encoding="utf-8")
    return skills_dir


def test_cli_bridge_skills_list_does_not_report_valid_for_unactivatable_skill(
    tmp_path, capsys, monkeypatch
):
    """`valid` must not be true for a skill the runtime refuses to activate.

    The aggregate is what automation branches on. Reporting `valid: true` while
    burying `activation.ok: false` inside the per-skill entry would put the
    safe-looking answer in the field consumers read and the disqualifying
    detail in one they do not.
    """
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._verify_community_signature",
        lambda self, raw, skill_dir: None,
    )
    skills_dir = _write_community_skill_with_hooks(tmp_path)

    rc = cli_bridge.main(["skills", "list", "--skills-dir", str(skills_dir)])

    payload = _read_stdout_json(capsys)
    result = payload["result"]
    assert rc == 0
    # Listing still describes the skill — that is what listing is for.
    assert result["skill_count"] == 1
    assert result["skills"][0]["name"] == "community-skill"
    assert result["skills"][0]["activation"]["ok"] is False
    assert result["skills"][0]["activation"]["code"] == "hooks_not_activatable"
    # But it is not reported as usable.
    assert result["valid"] is False
    assert result["activatable"] is False
    assert result["unactivatable_count"] == 1


def test_cli_bridge_skills_validate_rejects_unactivatable_skill(
    tmp_path, capsys, monkeypatch
):
    """Validation fails for anything the runtime would refuse to activate."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._verify_community_signature",
        lambda self, raw, skill_dir: None,
    )
    skills_dir = _write_community_skill_with_hooks(tmp_path)

    rc = cli_bridge.main(["skills", "validate", "--skills-dir", str(skills_dir)])

    payload = _read_stdout_json(capsys)
    result = payload["result"]
    assert rc == 0
    assert result["valid"] is False
    assert result["activatable"] is False
    assert result["skill_count"] == 0
    assert result["errors"][0]["code"] == "skill_security_error"
    assert "not first-party" in result["errors"][0]["detail"]


def test_cli_bridge_skills_commands_report_valid_for_an_activatable_skill(
    tmp_path, capsys, monkeypatch
):
    """The aggregate is not simply always false — a clean skill still passes."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._verify_community_signature",
        lambda self, raw, skill_dir: None,
    )
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "community-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent(_ACTIVATABLE_SKILL), encoding="utf-8"
    )

    for command in ("list", "validate"):
        rc = cli_bridge.main(["skills", command, "--skills-dir", str(skills_dir)])
        result = _read_stdout_json(capsys)["result"]
        assert rc == 0, command
        assert result["valid"] is True, command
        assert result["activatable"] is True, command
        assert result["skill_count"] == 1, command


def test_cli_bridge_skills_commands_never_execute_hooks(tmp_path, capsys, monkeypatch):
    """Neither command runs hook code, for any skill it reports on."""
    monkeypatch.setattr(
        "ori.skills.loader.SkillLoader._verify_community_signature",
        lambda self, raw, skill_dir: None,
    )
    sentinel = tmp_path / "executed.marker"
    skills_dir = tmp_path / "skills"
    skill_dir = skills_dir / "community-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent(_ACTIVATABLE_SKILL), encoding="utf-8"
    )
    (skill_dir / "hooks.py").write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('executed')\n",
        encoding="utf-8",
    )

    for command in ("list", "validate"):
        cli_bridge.main(["skills", command, "--skills-dir", str(skills_dir)])
        _read_stdout_json(capsys)
        assert not sentinel.exists(), f"skills {command} executed hooks.py"


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


# ─── Gateway posture in `config show` ─────────────────────────────────────────


_GATEWAY_CONFIG_BASE = """\
device:
  id: gw-device-01
  name: Gateway Device
  location: Lagos
sensors:
  - id: cpu
    type: cpu_percent
    protocol: psutil
    poll_interval_ms: 1000
skills: []
reasoning:
  default_tier: rule
gateway:
"""


def _config_with_gateway(tmp_path: Path, gateway: str) -> Path:
    """Write a config whose ``gateway:`` block is *gateway*.

    Composed rather than interpolated into a ``textwrap.dedent`` block: dedent
    runs after substitution, so an injected block's own indentation becomes the
    common prefix and silently mangles the surrounding YAML.
    """
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(_GATEWAY_CONFIG_BASE + gateway + "\n", encoding="utf-8")
    return cfg


def _gateway_from_show(capsys, cfg: Path) -> dict:
    rc = cli_bridge.main(["config", "show", "--path", str(cfg)])
    payload = _read_stdout_json(capsys)
    assert rc == 0
    return payload["result"]["config"]["gateway"]


def test_config_show_reports_disabled_gateway(tmp_path, capsys):
    cfg = _config_with_gateway(tmp_path, "  enabled: false\n  broker_url: ''")
    gateway = _gateway_from_show(capsys, cfg)

    assert gateway["enabled"] is False
    assert gateway["broker_configured"] is False


@pytest.mark.parametrize(
    ("broker_url", "host", "port", "scheme"),
    [
        ("mqtt://localhost", "localhost", 1883, "mqtt"),
        ("localhost", "localhost", 1883, "mqtt"),
        ("mqtts://localhost", "localhost", 8883, "mqtts"),
        ("mqtt://127.0.0.1:1884", "127.0.0.1", 1884, "mqtt"),
    ],
    ids=["default_port", "bare_host", "mqtts_default_port", "explicit_port"],
)
def test_config_show_normalises_broker_url_like_the_runtime(
    tmp_path, capsys, broker_url, host, port, scheme
):
    """Diagnostics must agree with the transport about defaults and bare hosts.

    A raw `urlparse()` reported no port for `mqtt://localhost` and no host for a
    bare `localhost`, so doctor warned about a broker the runtime would have
    reached. Both now use `parse_gateway_broker_endpoint`.
    """
    cfg = _config_with_gateway(tmp_path, f"  enabled: true\n  broker_url: {broker_url}")
    gateway = _gateway_from_show(capsys, cfg)

    assert gateway["broker_host"] == host
    assert gateway["broker_port"] == port
    assert gateway["broker_scheme"] == scheme
    assert "broker_error" not in gateway


@pytest.mark.parametrize(
    ("broker_url", "expected"),
    [
        ("mqtt://localhost:notaport", "invalid port"),
        ("mqtt://", "must include a broker host"),
        ("http://localhost", "must use mqtt://"),
        ("''", "is required when gateway.enabled is true"),
    ],
    ids=["bad_port", "no_host", "bad_scheme", "empty"],
)
def test_enabled_gateway_with_unusable_broker_url_fails_validation(
    tmp_path, capsys, broker_url, expected
):
    """An unusable endpoint is invalid configuration, not broker unavailability.

    Returning success with a `broker_error` field would make a config the
    transport cannot act on look merely degraded. It fails validation instead,
    so doctor's mandatory `config.valid` check catches it.
    """
    cfg = _config_with_gateway(tmp_path, f"  enabled: true\n  broker_url: {broker_url}")

    rc = cli_bridge.main(["config", "show", "--path", str(cfg)])

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "config_validation_error"
    assert expected in payload["error"]["detail"]


def test_disabled_gateway_tolerates_an_unusable_broker_url(tmp_path, capsys):
    """A disabled gateway never connects, so its stale URL is not an error."""
    cfg = _config_with_gateway(
        tmp_path, "  enabled: false\n  broker_url: mqtt://localhost:notaport"
    )
    gateway = _gateway_from_show(capsys, cfg)

    assert gateway["enabled"] is False
    assert "invalid port" in gateway["broker_error"]


def test_config_show_names_the_secret_variable_but_never_its_value(
    tmp_path, capsys, monkeypatch
):
    """The variable name is useful; the value is not this command's to emit.

    Presence is not reported at all — the service reads the secret from its own
    environment file, which this process does not inherit.
    """
    monkeypatch.setenv("GATEWAY_SHARED_SECRET", "super-secret-value")
    cfg = _config_with_gateway(
        tmp_path,
        "  enabled: true\n  broker_url: mqtt://127.0.0.1:1883\n"
        "  auth:\n    enabled: true\n    shared_secret_env: GATEWAY_SHARED_SECRET",
    )
    rc = cli_bridge.main(["config", "show", "--path", str(cfg)])
    raw = capsys.readouterr().out
    gateway = json.loads(raw)["result"]["config"]["gateway"]

    assert rc == 0
    assert gateway["shared_secret_env"] == "GATEWAY_SHARED_SECRET"
    assert "shared_secret_env_set" not in gateway
    assert "super-secret-value" not in raw


# --------------------------------------------------------------------------
# Commissioned safety binding ceremony
# --------------------------------------------------------------------------
#
# The bridge exists here because CLI-7 stops the CLI reading `ori.yaml` and
# CLI-9 stops it driving a contactor. What it must not do is form a second
# opinion: `deliver` runs the runtime's own verifier over the context the
# loader builds at startup, so a document accepted here is the one accepted
# then.


def _commissioning_config(
    tmp_path: Path,
    *,
    hardened: bool = False,
    monkeypatch: pytest.MonkeyPatch | None = None,
) -> Path:
    """A config the runtime would load, in the posture the test needs.

    Hardened posture is reached the way a deployment reaches it, not by
    mutating a loaded object: the whole chain the loader enforces has to be
    satisfied, config signature included, because the config the bridge reads
    is the config the runtime reads.
    """
    body = textwrap.dedent(f"""\
        device:
          id: bench-01
          name: Bench
          location: Test Lab
          deployment_profile: development
        sensors:
          - id: load-current
            type: cpu_percent
            protocol: psutil
            poll_interval_ms: 1000
        skills: []
        reasoning:
          default_tier: rule
        actions:
          relay:
            enabled: false
            gpio_pin: 26
        database:
          path: {tmp_path / "ori_state.db"}
        logging:
          level: INFO
          file: {tmp_path / "ori.log"}
        """)
    config_path = tmp_path / "ori.yaml"
    if not hardened:
        config_path.write_text(body, encoding="utf-8")
        return config_path

    assert monkeypatch is not None, "a hardened config needs monkeypatch for its anchor"
    private_key, public_key_b64 = _ed25519_keypair()
    monkeypatch.setenv("ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64", public_key_b64)
    body += textwrap.dedent(f"""\
        security:
          enforce_production_posture: true
          skills:
            require_signed: true
          config_signature:
            require_signed: true
            trust_anchor_env: ORI_CONFIG_TRUST_ANCHOR_PUBLIC_KEY_B64
        state:
          encryption:
            mode: filesystem_required
            encrypted_path_prefixes: ["{tmp_path}"]
        """)
    config_path.write_text(_sign_config_yaml(body, private_key), encoding="utf-8")
    return config_path


def _bench_envelope(**overrides):
    """A binding with both proof legs unless a test overrides one."""
    from tests.commissioning.signing import local_gpio_binding, sign_envelope

    overrides.setdefault("proof_method", "actuate_and_observe")
    overrides.setdefault("control_proof_method", "commanded_and_observed")
    binding = local_gpio_binding(
        device_id="bench-01",
        sensor_id="load-current",
        gpio_pin=26,
        active_high=False,
        **overrides,
    )
    return sign_envelope(binding, "7" * 64)


def _anchor(monkeypatch, seed: str = "7" * 64) -> None:
    from ori.security.commissioning.anchors import COMMISSIONING_ANCHOR_ENV
    from tests.commissioning.signing import public_key_b64

    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64(seed))


def test_cli_bridge_commissioning_inventory_reports_the_candidate_set(tmp_path, capsys):
    config_path = _commissioning_config(tmp_path)

    rc = cli_bridge.main(["commissioning", "inventory", "--path", str(config_path)])

    payload = _read_stdout_json(capsys)
    assert rc == 0
    result = payload["result"]
    assert result["device_id"] == "bench-01"
    assert result["sensor_ids"] == ["load-current"]
    assert result["actuators"] == [{"kind": "local_gpio", "identity": {"gpio_pin": 26}}]
    assert result["deployment_posture"] == "development"
    assert result["accepted_binding_seq"] == 0
    assert result["accepted_binding_hash"] is None


def test_cli_bridge_commissioning_inventory_omits_polarity(tmp_path, capsys):
    """Polarity is the question the ceremony asks, not one the device answers."""
    config_path = _commissioning_config(tmp_path)

    cli_bridge.main(["commissioning", "inventory", "--path", str(config_path)])

    result = _read_stdout_json(capsys)["result"]
    identity = result["actuators"][0]["identity"]
    assert identity == {"gpio_pin": 26}
    assert "active_high" not in identity
    # Nor a generation the runtime does not have to compare against.
    assert "inventory_generation" not in result


def test_cli_bridge_commissioning_inventory_reports_hardened_posture(
    tmp_path, monkeypatch, capsys
):
    config_path = _commissioning_config(
        tmp_path, hardened=True, monkeypatch=monkeypatch
    )

    cli_bridge.main(["commissioning", "inventory", "--path", str(config_path)])

    assert _read_stdout_json(capsys)["result"]["deployment_posture"] == "production"


def test_cli_bridge_commissioning_deliver_stages_an_accepted_binding(
    tmp_path, monkeypatch, capsys
):
    from ori.security.commissioning.loader import BINDING_RELATIVE_PATH

    config_path = _commissioning_config(tmp_path)
    _anchor(monkeypatch)
    source = tmp_path / "binding.json"
    source.write_text(json.dumps(_bench_envelope()), encoding="utf-8")

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )

    payload = _read_stdout_json(capsys)
    assert rc == 0
    result = payload["result"]
    assert result["accepted"] is True
    assert result["installed"] is True
    assert result["binding_seq"] == 1
    # Staged, not live: the runtime reads it when it next starts.
    assert "next starts" in result["message"]
    assert result["state"] == "in_force" and result["unproven_zones"] == []
    staged = tmp_path / BINDING_RELATIVE_PATH
    assert json.loads(staged.read_text()) == json.loads(source.read_text())


def test_cli_bridge_commissioning_deliver_refuses_by_stage_and_writes_nothing(
    tmp_path, monkeypatch, capsys
):
    from ori.security.commissioning.loader import BINDING_RELATIVE_PATH

    config_path = _commissioning_config(tmp_path)
    # The anchor configured is not the key that signed the document.
    _anchor(monkeypatch, seed="6" * 64)
    source = tmp_path / "binding.json"
    source.write_text(json.dumps(_bench_envelope()), encoding="utf-8")

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )

    payload = _read_stdout_json(capsys)
    # A refused document is answered the way `config validate` answers an
    # invalid one: ok false, exit 2, and the verdict typed in the error.
    assert rc == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "unknown_signer"
    assert payload["error"]["stage"] == "key_selection"
    assert not (tmp_path / BINDING_RELATIVE_PATH).exists()


def test_cli_bridge_commissioning_deliver_refuses_an_undemonstrated_zone_when_hardened(
    tmp_path, monkeypatch, capsys
):
    """The posture `inventory` reported is the posture `deliver` applies."""
    from ori.security.commissioning.loader import BINDING_RELATIVE_PATH

    config_path = _commissioning_config(
        tmp_path, hardened=True, monkeypatch=monkeypatch
    )
    _anchor(monkeypatch)
    source = tmp_path / "binding.json"
    source.write_text(
        json.dumps(_bench_envelope(proof_method="undemonstrated")), encoding="utf-8"
    )

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )

    assert rc == 2
    error = _read_stdout_json(capsys)["error"]
    assert error["code"] == "undemonstrated_binding"
    assert error["stage"] == "activation_posture"
    assert not (tmp_path / BINDING_RELATIVE_PATH).exists()


@pytest.mark.parametrize(
    "overrides",
    [
        {"control_proof_method": None},
        {"control_proof_method": "undemonstrated"},
    ],
    ids=["control_leg_absent", "control_leg_undemonstrated"],
)
def test_cli_bridge_commissioning_deliver_names_a_provisional_document(
    tmp_path, monkeypatch, capsys, overrides
):
    """Verification is not authority, and the installer is told which they got."""
    from ori.security.commissioning.loader import BINDING_RELATIVE_PATH

    config_path = _commissioning_config(tmp_path)
    _anchor(monkeypatch)
    source = tmp_path / "binding.json"
    source.write_text(json.dumps(_bench_envelope(**overrides)), encoding="utf-8")

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )

    result = _read_stdout_json(capsys)["result"]
    assert rc == 0
    assert result["accepted"] is True and result["installed"] is True
    assert result["state"] == "provisional"
    assert result["unproven_zones"] == ["bench"]
    assert "will not connect the actuator" in result["message"]
    assert (tmp_path / BINDING_RELATIVE_PATH).exists()


def test_cli_bridge_commissioning_deliver_refuses_a_repeated_key_from_the_wire(
    tmp_path, monkeypatch, capsys
):
    """The bytes are read through the runtime's parser, not a lenient one."""
    config_path = _commissioning_config(tmp_path)
    _anchor(monkeypatch)
    source = tmp_path / "binding.json"
    text = json.dumps(_bench_envelope(), indent=1)
    assert '"binding_seq": 1' in text
    source.write_text(
        text.replace('"binding_seq": 1', '"binding_seq": 5, "binding_seq": 1', 1),
        encoding="utf-8",
    )

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )

    assert rc == 2
    error = _read_stdout_json(capsys)["error"]
    assert (error["code"], error["stage"]) == ("malformed", "parses")


def test_cli_bridge_commissioning_deliver_will_not_replace_a_staged_document(
    tmp_path, monkeypatch, capsys
):
    """One installer does not silently discard another's staged binding."""
    from ori.security.commissioning.loader import BINDING_RELATIVE_PATH

    config_path = _commissioning_config(tmp_path)
    _anchor(monkeypatch)
    staged = tmp_path / BINDING_RELATIVE_PATH
    staged.parent.mkdir(parents=True, exist_ok=True)
    staged.write_text(json.dumps(_bench_envelope(binding_seq=9)), encoding="utf-8")
    before = staged.read_bytes()
    source = tmp_path / "binding.json"
    source.write_text(json.dumps(_bench_envelope()), encoding="utf-8")

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert payload["ok"] is False
    assert payload["error"]["code"] == "binding_already_staged"
    assert staged.read_bytes() == before

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
            "--force",
        ]
    )
    assert rc == 0
    assert staged.read_bytes() != before


async def _retain_foreign_binding(config_path: Path) -> None:
    """Put a binding for a different device into this device's store."""
    from ori.config import Config

    config = Config.load(str(config_path))
    store = cli_bridge._commissioning_store(config)
    await store.open()
    try:
        await store.retain_commissioned_binding(
            binding_seq=7,
            canonical_hash="sha256:" + "a" * 64,
            device_id="some-other-device",
            inventory_generation=1,
            signer_id="commissioning-test",
            supersedes=None,
            canonical_json="{}",
            signature="ed25519:" + base64.b64encode(b"\x00" * 64).decode(),
            zones_json=json.dumps(
                [
                    {
                        "kind": "local_gpio",
                        "proof_method": "actuate_and_observe",
                        "control_proof_method": "commanded_and_observed",
                    }
                ]
            ),
        )
    finally:
        await store.close()


def _legacy_zone() -> dict:
    """The retained shape before the control leg existed: no leg fields at all."""
    return {
        "zone_id": "bench",
        "sensor_id": "load-current",
        "quantity": "current",
        "unit": "ampere",
        "direction": "positive_is_load_draw",
        "range_min": 0.0,
        "range_max": 100.0,
        "noise_floor": 0.05,
        "calibration_ref": "bench",
        "rated_capacity_parameter": "rated_capacity_amps",
        "rated_capacity_value": 10.0,
        "kind": "local_gpio",
        "identity": {"gpio_pin": 26, "active_high": False},
        "mapping": {
            "open_protected_circuit": "de_energised",
            "close_protected_circuit": "energised",
            "de_energised_terminal_state": "open",
        },
        "proof_method": "actuate_and_observe",
        "proof_performed_at_ms": 1800000000000,
    }


async def _retain_legacy_binding(config_path: Path) -> None:
    """A row written before the control leg existed, bypassing the store's guard."""
    from ori.config import Config

    config = Config.load(str(config_path))
    store = cli_bridge._commissioning_store(config)
    await store.open()
    try:
        await store._run_write(
            lambda: (
                store._conn.execute(
                    "INSERT INTO commissioned_binding (binding_seq, canonical_hash, "
                    "device_id, inventory_generation, signer_id, supersedes, "
                    "canonical_json, signature, zones_json, accepted_at_ms, "
                    "retired_at_ms) VALUES (5, ?, ?, 1, 's', NULL, '{}', "
                    "'ed25519:x', ?, 1000, NULL)",
                    (
                        "sha256:" + "d" * 64,
                        "bench-01",
                        json.dumps([_legacy_zone()]),
                    ),
                ),
                store._conn.commit(),
            )
        )
    finally:
        await store.close()


def test_cli_bridge_commissioning_reads_no_binding_whose_control_leg_is_unproven(
    tmp_path, capsys
):
    """A row the store's guard predates is still not a baseline to chain onto.

    The bridge reads the store before the runtime's next start, so it can see a
    row the loader has not yet retired, and reporting it would let a producer
    chain a revision onto a document that licenses nothing.
    """
    config_path = _commissioning_config(tmp_path)
    asyncio.run(_retain_legacy_binding(config_path))

    cli_bridge.main(["commissioning", "inventory", "--path", str(config_path)])
    result = _read_stdout_json(capsys)["result"]
    assert result["accepted_binding_seq"] == 0
    assert result["accepted_binding_hash"] is None


def test_cli_bridge_commissioning_reads_no_binding_held_for_another_device(
    tmp_path, monkeypatch, capsys
):
    """A retained binding for another device is not this device's baseline.

    Reporting its sequence would let a producer chain a revision onto a
    document this device never accepted, and `deliver` would then judge
    freshness against a hash it does not hold. The loader reads it the same
    way, which is why the two agree at startup.
    """
    config_path = _commissioning_config(tmp_path)
    asyncio.run(_retain_foreign_binding(config_path))

    cli_bridge.main(["commissioning", "inventory", "--path", str(config_path)])
    result = _read_stdout_json(capsys)["result"]
    assert result["accepted_binding_seq"] == 0
    assert result["accepted_binding_hash"] is None

    # And the first binding for this device is accepted against that baseline,
    # rather than refused as stale behind the foreign sequence of 7.
    _anchor(monkeypatch)
    source = tmp_path / "binding.json"
    source.write_text(json.dumps(_bench_envelope()), encoding="utf-8")
    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )
    delivered = _read_stdout_json(capsys)["result"]
    assert rc == 0
    assert delivered["accepted"] is True
    assert delivered["binding_seq"] == 1


def test_cli_bridge_commissioning_deliver_agrees_with_the_loader_at_startup(
    tmp_path, monkeypatch, capsys
):
    """The verdict `deliver` gives is the verdict the runtime will give.

    This is the whole claim the command makes. It is checked by staging a
    document through the bridge and then running the loader over the same
    installation, which is what the runtime does at its next start: the
    binding that comes into force must be the one that was delivered.
    """
    from ori.config import Config
    from ori.security.commissioning.anchors import load_commissioning_anchors
    from ori.security.commissioning.loader import (
        DeclaredInventory,
        load_commissioning_state,
    )
    from ori.security.commissioning.profiles import load_shipped_profile_set

    config_path = _commissioning_config(tmp_path)
    _anchor(monkeypatch)
    source = tmp_path / "binding.json"
    source.write_text(json.dumps(_bench_envelope()), encoding="utf-8")

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )
    delivered = _read_stdout_json(capsys)["result"]
    assert rc == 0 and delivered["accepted"] is True

    async def _load():
        config = Config.load(str(config_path))
        store = cli_bridge._commissioning_store(config)
        await store.open()
        try:
            return await load_commissioning_state(
                data_path=config_path.resolve().parent,
                device_id=str(config.device.id),
                anchors=load_commissioning_anchors(),
                provisioning_anchor=None,
                inventory=DeclaredInventory.from_config(["load-current"], 26),
                posture="development",
                profiles=load_shipped_profile_set(),
                store=store,
            )
        finally:
            await store.close()

    state = asyncio.run(_load())
    assert state.in_force is not None
    assert state.in_force.binding_seq == delivered["binding_seq"]
    assert state.in_force.canonical_hash == delivered["binding_hash"]
    assert state.actuation_licensed is True
    # Narrowed rather than assumed: a `None` verdict here would otherwise fail
    # as an AttributeError deep in the assertion instead of saying that the
    # loader recorded nothing for the document the bridge staged.
    assert state.last_verdict is not None
    assert (state.last_verdict.stage, state.last_verdict.reason) == (
        "accepted",
        "accepted",
    )


def test_cli_bridge_commissioning_reads_create_no_state_database(tmp_path, capsys):
    """Asking a device a question must not build its durable state.

    Opening the store applies the DDL, so a read that opened it would leave a
    fully-formed database owned by whoever ran the query. On a system install
    that is the installer, not the service account, and the runtime would then
    be unable to open its own store — with nothing to connect the failure back
    to an inventory command run days earlier.
    """
    config_path = _commissioning_config(tmp_path)
    db_path = tmp_path / "ori_state.db"
    assert not db_path.exists()

    rc = cli_bridge.main(["commissioning", "inventory", "--path", str(config_path)])

    result = _read_stdout_json(capsys)["result"]
    assert rc == 0
    assert result["accepted_binding_seq"] == 0
    assert result["accepted_binding_hash"] is None
    assert not db_path.exists(), "the read created the state database"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ori.yaml"]


def test_cli_bridge_commissioning_deliver_works_before_the_first_start(
    tmp_path, monkeypatch, capsys
):
    """The first commissioning happens before the runtime has ever run."""
    from ori.security.commissioning.loader import BINDING_RELATIVE_PATH

    config_path = _commissioning_config(tmp_path)
    _anchor(monkeypatch)
    source = tmp_path / "binding.json"
    source.write_text(json.dumps(_bench_envelope()), encoding="utf-8")

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )

    result = _read_stdout_json(capsys)["result"]
    assert rc == 0 and result["accepted"] is True
    assert (tmp_path / BINDING_RELATIVE_PATH).is_file()
    assert not (tmp_path / "ori_state.db").exists()


def test_cli_bridge_commissioning_deliver_reports_a_non_utf8_file_as_malformed(
    tmp_path, monkeypatch, capsys
):
    """A document that is not UTF-8 is malformed by the grammar, not a tool fault.

    Reading it through the generic error path would report the same class of
    defect as every other malformed document under a different name, and an
    operator could not tell a bad file from a broken tool.
    """
    config_path = _commissioning_config(tmp_path)
    _anchor(monkeypatch)
    source = tmp_path / "binding.json"
    source.write_bytes(b'{"binding":"\xff","signature":"x"}')

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(source),
        ]
    )

    payload = _read_stdout_json(capsys)
    assert rc == 2
    assert (payload["error"]["code"], payload["error"]["stage"]) == (
        "malformed",
        "parses",
    )


def test_cli_bridge_errors_without_a_verdict_carry_no_stage(tmp_path, capsys):
    """Only a verdict has a stage; an unreadable file is not one."""
    config_path = _commissioning_config(tmp_path)

    rc = cli_bridge.main(
        [
            "commissioning",
            "deliver",
            "--path",
            str(config_path),
            "--binding",
            str(tmp_path / "absent.json"),
        ]
    )

    error = _read_stdout_json(capsys)["error"]
    assert rc == 2
    assert error["code"] == "binding_unreadable"
    assert "stage" not in error
