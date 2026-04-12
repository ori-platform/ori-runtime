# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.rule_engine import RuleEngine
from ori.skills.hooks_api import HookContext
from ori.skills.loader import SkillLoader


def _skill_dir() -> Path:
    return Path(__file__).parent.parent / "skills" / "site-safety-ppe"


def _load_skill():
    return SkillLoader().load_one(_skill_dir())


def _event(
    *,
    sensor_id: str,
    sensor_type: str,
    value: float,
    quality: float,
    metadata: dict | None = None,
) -> OriEvent:
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type=sensor_type,
        value=value,
        unit="score",
        timestamp=1710000000123,
        quality=quality,
        metadata=metadata or {},
    )
    return OriEvent.from_reading(reading, "site-b-ppe-01")


def _build_rule_context(skill, event):
    ctx = dict(skill.config)
    hook_ctx = HookContext.build(event, None, skill.name, skill_config=skill.config)
    skill.hooks.pre_trigger_eval(hook_ctx)
    ctx.update(hook_ctx.derived)
    return ctx


def test_skill_loads():
    skill = _load_skill()
    assert skill.name == "site-safety-ppe"
    assert len(skill.triggers) == 2


def test_triggers_gate_on_quality():
    skill = _load_skill()
    hardhat = next(t for t in skill.triggers if t.name == "hardhat_violation_detected")
    vest = next(t for t in skill.triggers if t.name == "vest_violation_detected")
    assert "quality > min_detection_quality" in hardhat.condition
    assert "quality > min_detection_quality" in vest.condition


@pytest.mark.asyncio
async def test_low_quality_detection_does_not_match():
    skill = _load_skill()
    trigger = next(t for t in skill.triggers if t.name == "hardhat_violation_detected")
    event = _event(
        sensor_id="ppe-hardhat-cam-01",
        sensor_type="ppe_hardhat_violation_score",
        value=0.95,
        quality=0.4,
    )
    result = await RuleEngine().evaluate(
        event,
        [trigger],
        context=_build_rule_context(skill, event),
    )
    assert result.matched is False


@pytest.mark.asyncio
async def test_high_quality_detection_matches():
    skill = _load_skill()
    trigger = next(t for t in skill.triggers if t.name == "hardhat_violation_detected")
    event = _event(
        sensor_id="ppe-hardhat-cam-01",
        sensor_type="ppe_hardhat_violation_score",
        value=0.95,
        quality=0.93,
    )
    result = await RuleEngine().evaluate(
        event,
        [trigger],
        context=_build_rule_context(skill, event),
    )
    assert result.matched is True
    assert result.rule_name == "hardhat_violation_detected"


@pytest.mark.asyncio
async def test_thresholds_are_configurable_without_yaml_edit():
    skill = _load_skill()
    skill.config["violation_score_threshold"] = 0.95
    skill.config["min_detection_quality"] = 0.9
    trigger = next(t for t in skill.triggers if t.name == "hardhat_violation_detected")
    event = _event(
        sensor_id="ppe-hardhat-cam-01",
        sensor_type="ppe_hardhat_violation_score",
        value=0.9,
        quality=0.95,
    )
    result = await RuleEngine().evaluate(
        event,
        [trigger],
        context=_build_rule_context(skill, event),
    )
    assert result.matched is False


def test_hooks_add_zone_camera_subject_context():
    skill = _load_skill()
    result = ReasoningResult(
        text="PPE violation detected.",
        tier="local_slm",
        model="stub",
        tokens_used=0,
        latency_ms=0,
    )
    event = _event(
        sensor_id="ppe-hardhat-cam-01",
        sensor_type="ppe_hardhat_violation_score",
        value=0.9,
        quality=0.91,
        metadata={
            "zone_id": "line-3",
            "camera_id": "cam-01",
            "subject_id": "worker-12",
        },
    )
    ctx = HookContext.build(event, None, skill.name, skill_config=skill.config)
    updated = skill.hooks.post_reasoning(result, ctx)
    assert "Zone: line-3" in updated.text
    assert "Camera: cam-01" in updated.text
    assert "Worker ref: worker-12" in updated.text
