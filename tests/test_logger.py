# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for ori/actions/logger.py."""

import logging

from ori.actions.logger import LoggerAction
from ori.network.events import ReasoningResult


def _result(
    tier: str = "rule",
    model: str = "rule_engine",
    confidence: float = 0.92,
    latency_ms: int = 3,
) -> ReasoningResult:
    return ReasoningResult(
        text="Overcurrent detected.",
        tier=tier,
        model=model,
        tokens_used=0,
        latency_ms=latency_ms,
        confidence=confidence,
        action_tier="A",
    )


# ── log_reasoning ─────────────────────────────────────────────────────────────


def test_log_reasoning_writes_info(caplog):
    with caplog.at_level(logging.INFO, logger="ori.actions.logger"):
        LoggerAction().log_reasoning(_result(), "load-current", "dev-01")
    assert any(r.levelno == logging.INFO for r in caplog.records)


def test_log_reasoning_contains_tier(caplog):
    with caplog.at_level(logging.INFO, logger="ori.actions.logger"):
        LoggerAction().log_reasoning(_result(tier="local_slm"), "s", "d")
    assert any("local_slm" in r.message for r in caplog.records)


def test_log_reasoning_contains_confidence(caplog):
    with caplog.at_level(logging.INFO, logger="ori.actions.logger"):
        LoggerAction().log_reasoning(_result(confidence=0.75), "s", "d")
    assert any("75%" in r.message for r in caplog.records)


def test_log_reasoning_contains_model(caplog):
    with caplog.at_level(logging.INFO, logger="ori.actions.logger"):
        LoggerAction().log_reasoning(_result(model="qwen2.5"), "s", "d")
    assert any("qwen2.5" in r.message for r in caplog.records)


def test_log_reasoning_contains_latency(caplog):
    with caplog.at_level(logging.INFO, logger="ori.actions.logger"):
        LoggerAction().log_reasoning(_result(latency_ms=42), "s", "d")
    assert any("42ms" in r.message for r in caplog.records)


def test_log_reasoning_never_raises():
    """Must not raise even if called with pathological values."""
    action = LoggerAction()
    action.log_reasoning(_result(confidence=float("nan")), "", "")
    action.log_reasoning(_result(latency_ms=-1), "", "")


# ── log_override ──────────────────────────────────────────────────────────────


def test_log_override_writes_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="ori.actions.logger"):
        LoggerAction().log_override("open_safety_circuit", "rejection", "dev-01")
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_log_override_contains_override_type(caplog):
    with caplog.at_level(logging.WARNING, logger="ori.actions.logger"):
        LoggerAction().log_override("emergency_cutoff", "autonomous_tier_d", "dev-01")
    assert any("autonomous_tier_d" in r.message for r in caplog.records)


def test_log_override_contains_action(caplog):
    with caplog.at_level(logging.WARNING, logger="ori.actions.logger"):
        LoggerAction().log_override("open_safety_circuit", "rejection", "dev-01")
    assert any("open_safety_circuit" in r.message for r in caplog.records)


def test_log_override_never_raises():
    LoggerAction().log_override("", "", "")
    LoggerAction().log_override("x" * 1000, "rejection", "d")
