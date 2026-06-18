# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path

import pytest

import ori
from ori.integration.rule_evaluation import (
    RuleEvaluationRequest,
    RuleEvaluationSession,
    bundled_skill_path,
    evaluate_sensor_reading,
)


def _request(
    value: float,
    *,
    sensor_type: str = "current_clamp",
    unit: str = "ampere",
    **kwargs: object,
) -> RuleEvaluationRequest:
    return RuleEvaluationRequest(
        sensor_id="main-circuit-current",
        sensor_type=sensor_type,
        value=value,
        unit=unit,
        timestamp_ms=1_710_000_000_123,
        quality=1.0,
        device_id="demo-site-a",
        metadata={"source": "demo-api"},
        **kwargs,
    )


def _write_skill(
    root: Path,
    *,
    name: str,
    condition: str,
    cooldown_seconds: int = 0,
    config: str = "",
    hooks: str | None = None,
) -> None:
    skill_dir = root / name
    skill_dir.mkdir()
    skill_dir.joinpath("skill.yaml").write_text(
        f"""
name: {name}
version: 0.1.0
author: test
signature: bundled
sensors_required:
  - type: current_clamp
triggers:
  - name: demo_trigger
    condition: "{condition}"
    action_tier: A
    cooldown_seconds: {cooldown_seconds}
prompts:
  demo_trigger: Demo.
actions:
  available:
    - name: alert_whatsapp
      tier: A
  defaults:
    demo_trigger: [alert_whatsapp]
config:
{config or "  threshold: 10.0"}
""",
        encoding="utf-8",
    )
    if hooks is not None:
        skill_dir.joinpath("hooks.py").write_text(hooks, encoding="utf-8")


@pytest.mark.asyncio
async def test_dangerous_overcurrent_returns_tier_d_with_proof_fields() -> None:
    result = await evaluate_sensor_reading(_request(52.0))

    assert result.matched is True
    assert result.action_tier == "D"
    assert result.trigger_name == "dangerous_overcurrent"
    assert result.bypass_llm is True
    assert (
        result.proof_rule_condition
        == "(sensor_type == 'current_clamp' or sensor_type == 'ads1115_current' or sensor_type == 'current' or sensor_type == 'usb_current') and value > dangerous_overcurrent_threshold"
    )
    assert result.proof_threshold_name == "dangerous_overcurrent_threshold"
    assert result.proof_threshold == pytest.approx(20.0)
    assert result.proof_sensor_value == pytest.approx(52.0)
    assert result.proof_tier_selected == "D"
    assert result.proposed_action == "alert_whatsapp"
    assert result.default_actions == ("alert_whatsapp", "log_to_dashboard")
    assert result.latency_ms >= 0


@pytest.mark.asyncio
async def test_usb_current_can_return_tier_d_with_proof_fields() -> None:
    result = await evaluate_sensor_reading(
        _request(52.0, sensor_type="usb_current", unit="ampere")
    )

    assert result.matched is True
    assert result.action_tier == "D"
    assert result.trigger_name == "dangerous_overcurrent"
    assert result.proof_threshold_name == "dangerous_overcurrent_threshold"
    assert result.proof_threshold == pytest.approx(20.0)
    assert result.proof_sensor_value == pytest.approx(52.0)
    assert result.proof_tier_selected == "D"


@pytest.mark.asyncio
async def test_below_dangerous_overcurrent_threshold_does_not_match_tier_d() -> None:
    result = await evaluate_sensor_reading(_request(12.0))

    assert result.matched is False
    assert result.action_tier == "A"
    assert result.trigger_name is None
    assert result.proof_rule_condition == ""
    assert result.proof_threshold is None
    assert result.proposed_action is None
    assert result.default_actions == ()


@pytest.mark.asyncio
async def test_skill_config_override_changes_threshold_without_editing_skill() -> None:
    result = await evaluate_sensor_reading(
        _request(52.0, skill_config_overrides={"dangerous_overcurrent_threshold": 50.0})
    )

    assert result.matched is True
    assert result.action_tier == "D"
    assert result.proof_threshold == pytest.approx(50.0)


@pytest.mark.asyncio
async def test_higher_override_can_prevent_dangerous_overcurrent_match() -> None:
    result = await evaluate_sensor_reading(
        _request(52.0, skill_config_overrides={"dangerous_overcurrent_threshold": 60.0})
    )

    assert result.matched is False
    assert result.action_tier == "A"


def test_bundled_skill_path_resolves_energy_anomaly_detector() -> None:
    path = bundled_skill_path("energy-anomaly-detector")

    assert path.name == "energy-anomaly-detector"
    assert (path / "skill.yaml").is_file()
    assert (path / "hooks.py").is_file()


def test_runtime_package_declares_pep561_typed_marker() -> None:
    marker = Path(ori.__file__).resolve().parent / "py.typed"

    assert marker.is_file()


@pytest.mark.parametrize("bad_name", ["", "../energy-anomaly-detector", "a/b", "a\\b"])
def test_bundled_skill_path_rejects_invalid_names(bad_name: str) -> None:
    with pytest.raises(ValueError):
        bundled_skill_path(bad_name)


@pytest.mark.parametrize("bad_name", ["../evil", "safe/evil", "safe\\evil", ".."])
def test_skills_root_rejects_traversal_skill_names(
    tmp_path: Path,
    bad_name: str,
) -> None:
    _write_skill(tmp_path, name="safe", condition="value > threshold")

    with pytest.raises(ValueError):
        RuleEvaluationRequest(
            sensor_id="main-circuit-current",
            sensor_type="current_clamp",
            value=12.0,
            unit="ampere",
            timestamp_ms=1,
            skill_name=bad_name,
            skills_root=str(tmp_path),
        )


def test_rule_evaluation_request_rejects_invalid_state_at_construction() -> None:
    with pytest.raises(ValueError, match="sensor_id"):
        RuleEvaluationRequest(
            sensor_id=" ",
            sensor_type="current_clamp",
            value=12.0,
            unit="ampere",
            timestamp_ms=1,
        )


@pytest.mark.asyncio
async def test_session_preserves_trigger_cooldown_state(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        name="cooldown-skill",
        condition="value > threshold",
        cooldown_seconds=600,
    )
    session = RuleEvaluationSession(
        skill_name="cooldown-skill",
        skills_root=str(tmp_path),
    )
    request = _request(
        12.0,
        skill_name="cooldown-skill",
        skills_root=str(tmp_path),
    )

    first = await session.evaluate(request)
    second = await session.evaluate(request)

    assert first.matched is True
    assert second.matched is False


@pytest.mark.asyncio
async def test_non_callable_pre_trigger_eval_is_ignored(tmp_path: Path) -> None:
    _write_skill(
        tmp_path,
        name="non-callable-hook-skill",
        condition="value > threshold",
        hooks="pre_trigger_eval = True\n",
    )

    result = await evaluate_sensor_reading(
        _request(
            12.0,
            skill_name="non-callable-hook-skill",
            skills_root=str(tmp_path),
        )
    )

    assert result.matched is True


@pytest.mark.asyncio
async def test_inline_numeric_threshold_is_exposed_in_proof_fields(
    tmp_path: Path,
) -> None:
    _write_skill(
        tmp_path,
        name="literal-threshold-skill",
        condition="value > 50.0",
    )

    result = await evaluate_sensor_reading(
        _request(
            52.0,
            skill_name="literal-threshold-skill",
            skills_root=str(tmp_path),
        )
    )

    assert result.matched is True
    assert result.proof_threshold_name is None
    assert result.proof_threshold == pytest.approx(50.0)
