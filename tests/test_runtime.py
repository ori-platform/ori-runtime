# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for ori/runtime.py — Step 20.

All external dependencies (HAL adapters, WhatsApp, SMS, relay, LocalLLM)
are mocked.  No real hardware, credentials, or network calls are made.
"""

import asyncio
import logging
import os
import textwrap
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from ori.network.deduplicator import EventDeduplicator
from ori.network.event_bus import EventBus
from ori.network.events import OriEvent, SensorReading
from ori.reasoning.elevator import SkillContext
from ori.runtime import (
    OriRuntime,
    _build_local_llm,
    _coap_command_from_context,
    _maybe_autoload_dotenv,
    _process_target_from_context,
    _resolve_local_model_file,
)
from ori.state.store import StateStore

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def minimal_config(tmp_path: Path) -> Path:
    """Write a minimal valid ori.yaml that uses only the psutil adapter."""
    skill_dir = tmp_path / "skills" / "test-skill"
    skill_dir.mkdir(parents=True)
    (skill_dir / "skill.yaml").write_text(
        textwrap.dedent("""\
            name: test-skill
            version: 0.1.0
            author: test
            sensors_required:
              - type: cpu_percent
            triggers:
              - name: high_cpu
                condition: "value > 90"
                action_tier: A
                cooldown_seconds: 0
                escalate_to: local_slm
            actions:
              available:
                - name: alert_whatsapp
                  tier: A
              defaults:
                high_cpu: [alert_whatsapp]
        """),
        encoding="utf-8",
    )

    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: test-device-01
              name: Test Device
              location: Test Lab

            sensors:
              - id: cpu-sensor
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 100

            skills:
              - name: test-skill
                version: "0.1.0"
                config: {{}}

            reasoning:
              default_tier: local
              local_model: ""
              model_path: ""
              offline_fallback: rule

            gateway:
              enabled: false
              broker_url: ""

            actions:
              primary_alert_channel: sms
              whatsapp:
                enabled: false
              sms:
                enabled: false
              relay:
                enabled: false

            skills_dir: {str(tmp_path / "skills")}
        """),
        encoding="utf-8",
    )
    return cfg


def _patch_external(monkeypatch):
    """Patch all external I/O so tests run without hardware or credentials."""
    monkeypatch.setattr(
        "ori.actions.whatsapp.TwilioProvider.send", AsyncMock(return_value=True)
    )
    monkeypatch.setattr("ori.actions.sms.SMSAction.send", AsyncMock(return_value=True))


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestLocalSLMWiring:
    def test_resolve_local_model_from_directory_and_basename(self, tmp_path: Path):
        model_dir = tmp_path / "models"
        model_dir.mkdir()
        model_file = model_dir / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
        model_file.write_bytes(b"fake")

        cfg_path = tmp_path / "ori.yaml"
        cfg_path.write_text("device: {}\n", encoding="utf-8")

        resolved = _resolve_local_model_file(
            local_model="qwen2.5-0.5b-instruct-q4_k_m",
            model_path=str(model_dir),
            config_path=str(cfg_path),
        )
        assert resolved == str(model_file.resolve())

    def test_resolve_local_model_from_absolute_file(self, tmp_path: Path):
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"fake")

        cfg_path = tmp_path / "ori.yaml"
        cfg_path.write_text("device: {}\n", encoding="utf-8")

        resolved = _resolve_local_model_file(
            local_model=str(model_file),
            model_path="",
            config_path=str(cfg_path),
        )
        assert resolved == str(model_file.resolve())

    def test_build_local_llm_returns_none_when_model_missing(self, tmp_path: Path):
        cfg_path = tmp_path / "ori.yaml"
        cfg_path.write_text("device: {}\n", encoding="utf-8")
        reasoning_cfg = SimpleNamespace(
            local_model="missing-model",
            model_path=str(tmp_path / "models"),
            local_context_window=2048,
        )

        llm = _build_local_llm(reasoning_cfg, str(cfg_path))
        assert llm is None

    def test_build_local_llm_constructs_with_resolved_model(
        self, tmp_path, monkeypatch
    ):
        model_dir = tmp_path / "models"
        model_dir.mkdir()
        model_file = model_dir / "qwen2.5-0.5b-instruct-q4_k_m.gguf"
        model_file.write_bytes(b"fake")

        cfg_path = tmp_path / "ori.yaml"
        cfg_path.write_text("device: {}\n", encoding="utf-8")
        reasoning_cfg = SimpleNamespace(
            local_model="qwen2.5-0.5b-instruct-q4_k_m",
            model_path=str(model_dir),
            local_context_window=4096,
        )

        calls = {}

        class _FakeLocalLLM:
            def __init__(self, model_path: str, context_window: int = 2048) -> None:
                calls["model_path"] = model_path
                calls["context_window"] = context_window

            @property
            def is_available(self) -> bool:
                return True

        monkeypatch.setattr("ori.runtime.LocalLLM", _FakeLocalLLM)

        llm = _build_local_llm(reasoning_cfg, str(cfg_path))
        assert isinstance(llm, _FakeLocalLLM)
        assert calls["model_path"] == str(model_file.resolve())
        assert calls["context_window"] == 4096

    async def test_runtime_passes_built_local_llm_to_elevator(
        self, minimal_config, monkeypatch
    ):
        _patch_external(monkeypatch)
        sentinel = object()
        captured = {}

        from ori.reasoning.elevator import IntelligenceElevator as _RealElevator

        monkeypatch.setattr("ori.runtime._build_local_llm", lambda *_: sentinel)

        def _elevator_factory(local_llm=None, config=None):
            captured["local_llm"] = local_llm
            return _RealElevator(local_llm=local_llm, config=config)

        monkeypatch.setattr("ori.runtime.IntelligenceElevator", _elevator_factory)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        await asyncio.gather(runtime.start(), _stop())
        assert captured["local_llm"] is sentinel


class TestDotenvAutoload:
    def test_disabled_does_not_load_dotenv(self, tmp_path: Path, monkeypatch):
        cfg = tmp_path / "ori.yaml"
        cfg.write_text("device: {}\n", encoding="utf-8")
        env_path = tmp_path / ".env"
        env_path.write_text("ORI_AUTOLOAD_SMOKE=from_dotenv\n", encoding="utf-8")

        monkeypatch.delenv("ORI_AUTOLOAD_DOTENV", raising=False)
        monkeypatch.delenv("ORI_AUTOLOAD_SMOKE", raising=False)

        _maybe_autoload_dotenv(str(cfg))
        assert os.environ.get("ORI_AUTOLOAD_SMOKE") is None

    def test_enabled_loads_config_dir_dotenv(self, tmp_path: Path, monkeypatch):
        cfg = tmp_path / "ori.yaml"
        cfg.write_text("device: {}\n", encoding="utf-8")
        env_path = tmp_path / ".env"
        env_path.write_text("ORI_AUTOLOAD_SMOKE=from_dotenv\n", encoding="utf-8")

        monkeypatch.setenv("ORI_AUTOLOAD_DOTENV", "true")
        monkeypatch.delenv("ORI_AUTOLOAD_SMOKE", raising=False)

        _maybe_autoload_dotenv(str(cfg))
        assert os.environ.get("ORI_AUTOLOAD_SMOKE") == "from_dotenv"

    def test_enabled_does_not_override_existing_env(self, tmp_path: Path, monkeypatch):
        cfg = tmp_path / "ori.yaml"
        cfg.write_text("device: {}\n", encoding="utf-8")
        env_path = tmp_path / ".env"
        env_path.write_text("ORI_AUTOLOAD_SMOKE=from_dotenv\n", encoding="utf-8")

        monkeypatch.setenv("ORI_AUTOLOAD_DOTENV", "true")
        monkeypatch.setenv("ORI_AUTOLOAD_SMOKE", "already_set")

        _maybe_autoload_dotenv(str(cfg))
        assert os.environ.get("ORI_AUTOLOAD_SMOKE") == "already_set"


class TestAdapterProtocol:
    async def test_unknown_protocol_raises_config_error(
        self, tmp_path: Path, monkeypatch
    ):
        """A sensor with an unknown protocol must raise ConfigValidationError
        immediately at startup — never silently substitute a wrong adapter."""
        from ori.config import ConfigValidationError

        skill_dir = tmp_path / "skills" / "s"
        skill_dir.mkdir(parents=True)
        (skill_dir / "skill.yaml").write_text(
            "name: s\nversion: 0.1.0\nauthor: t\ntriggers: []\nactions: {}\n",
            encoding="utf-8",
        )
        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent(f"""\
                device:
                  id: dev-01
                  name: Dev
                  location: Lab
                sensors:
                  - id: inv-current
                    type: current
                    protocol: unknown_proto
                    poll_interval_ms: 1000
                skills: []
                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""
                  offline_fallback: rule
                gateway:
                  enabled: false
                  broker_url: ""
                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                  relay:
                    enabled: false
                skills_dir: {str(tmp_path / "skills")}
            """),
            encoding="utf-8",
        )

        runtime = OriRuntime(config_path=str(cfg))

        async def _stop():
            await asyncio.sleep(0.5)
            await runtime.stop()

        with pytest.raises(ConfigValidationError, match="unknown_proto"):
            await asyncio.gather(runtime.start(), _stop())


class TestLifecycle:
    async def test_runtime_starts_and_stops_cleanly(self, minimal_config, monkeypatch):
        """OriRuntime starts, stop() fires after 0.1 s, no error, all tasks cancelled."""
        _patch_external(monkeypatch)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _auto_stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        await asyncio.gather(runtime.start(), _auto_stop())
        # If we reach here, start() returned cleanly after stop()

    async def test_stop_is_idempotent(self, minimal_config, monkeypatch):
        """Calling stop() twice must not raise."""
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        async def _double_stop():
            await asyncio.sleep(0.05)
            await runtime.stop()
            await runtime.stop()  # second call — must be a no-op

        await asyncio.gather(runtime.start(), _double_stop())

    async def test_start_does_not_duplicate_rotating_file_handler(
        self, minimal_config, monkeypatch
    ):
        """Restarting in-process should keep a single RotatingFileHandler per file."""
        from logging.handlers import RotatingFileHandler

        _patch_external(monkeypatch)
        cfg_path = Path(minimal_config)
        custom_log = cfg_path.parent / "runtime-test.log"
        cfg_path.write_text(
            cfg_path.read_text(encoding="utf-8")
            + textwrap.dedent(
                f"""
                logging:
                  file: "{custom_log}"
                  level: INFO
                """
            ),
            encoding="utf-8",
        )

        runtime1 = OriRuntime(config_path=str(cfg_path))
        runtime2 = OriRuntime(config_path=str(cfg_path))

        async def _run_once(runtime: OriRuntime):
            async def _stop():
                await asyncio.sleep(0.1)
                await runtime.stop()

            await asyncio.gather(runtime.start(), _stop())

        await _run_once(runtime1)
        await _run_once(runtime2)

        root = logging.getLogger()
        target = str(custom_log.resolve())
        matches = [
            h
            for h in root.handlers
            if isinstance(h, RotatingFileHandler)
            and Path(getattr(h, "baseFilename", "")).resolve().as_posix()
            == Path(target).as_posix()
        ]
        assert len(matches) == 1

        # Keep global logger state clean for subsequent tests.
        for h in matches:
            root.removeHandler(h)
            h.close()

    async def test_phone_deployment_skips_relay_init(
        self, tmp_path: Path, monkeypatch, caplog
    ):
        _patch_external(monkeypatch)
        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent("""\
                device:
                  id: phone-dev-01
                  name: Phone Gateway
                  location: Lagos
                  deployment_type: phone
                sensors:
                  - id: cpu-sensor
                    type: cpu_percent
                    protocol: psutil
                    poll_interval_ms: 200
                skills: []
                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""
                  offline_fallback: rule
                gateway:
                  enabled: false
                  broker_url: ""
                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                  relay:
                    enabled: true
                    gpio_pin: 26
            """),
            encoding="utf-8",
        )
        runtime = OriRuntime(config_path=str(cfg))
        mocked_connect = AsyncMock(
            side_effect=AssertionError("relay should not connect")
        )
        monkeypatch.setattr("ori.actions.relay.RelayAction.connect", mocked_connect)

        async def _stop():
            await asyncio.sleep(0.2)
            await runtime.stop()

        with caplog.at_level(logging.WARNING):
            await asyncio.gather(runtime.start(), _stop())

        assert mocked_connect.await_count == 0
        assert any(
            "deployment_type=phone with relay enabled" in r.message
            for r in caplog.records
        )


class TestStartupLogs:
    async def test_startup_logs_skill_tiers(self, minimal_config, monkeypatch, caplog):
        """After start(), caplog must contain '[skill]' with trigger + tier."""
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        with caplog.at_level(logging.INFO):
            await asyncio.gather(runtime.start(), _stop())

        skill_lines = [r.message for r in caplog.records if "[skill]" in r.message]
        assert any("test-skill" in line for line in skill_lines), (
            f"Expected '[skill] test-skill' in log. Got: {skill_lines}"
        )
        trigger_lines = [r.message for r in caplog.records if "high_cpu" in r.message]
        assert any("Tier A" in line for line in trigger_lines), (
            f"Expected 'Tier A' in trigger log. Got: {trigger_lines}"
        )

    async def test_runtime_logs_event_loop_ready(
        self, minimal_config, monkeypatch, caplog
    ):
        """Log must contain '[runtime] event loop ready' after startup."""
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        with caplog.at_level(logging.INFO):
            await asyncio.gather(runtime.start(), _stop())

        messages = [r.message for r in caplog.records]
        assert any("event loop ready" in m for m in messages), (
            f"'event loop ready' not found in log. Messages: {messages}"
        )


class TestSkillReload:
    async def test_reload_skills_registers_new_handlers(
        self, minimal_config: Path, monkeypatch
    ):
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        start_task = asyncio.create_task(runtime.start())
        try:
            await asyncio.sleep(0.2)
            assert runtime._event_bus is not None
            assert runtime._event_bus.subscriber_count("cpu_percent") == 1

            skills_root = Path(minimal_config).parent / "skills"
            skill_dir = skills_root / "second-skill"
            skill_dir.mkdir(parents=True, exist_ok=True)
            (skill_dir / "skill.yaml").write_text(
                textwrap.dedent("""\
                    name: second-skill
                    version: 0.1.0
                    author: test
                    sensors_required:
                      - type: cpu_percent
                    triggers:
                      - name: high_cpu_secondary
                        condition: "value > 95"
                        action_tier: A
                        cooldown_seconds: 0
                        escalate_to: local_slm
                    actions:
                      available:
                        - name: alert_whatsapp
                          tier: A
                      defaults:
                        high_cpu_secondary: [alert_whatsapp]
                """),
                encoding="utf-8",
            )

            ok = await runtime.reload_skills()
            assert ok is True
            assert runtime._event_bus.subscriber_count("cpu_percent") == 2
        finally:
            await runtime.stop()
            await start_task

    async def test_reload_skills_keeps_existing_on_empty_result(
        self, minimal_config: Path, monkeypatch
    ):
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))

        start_task = asyncio.create_task(runtime.start())
        try:
            await asyncio.sleep(0.2)
            assert runtime._event_bus is not None
            before = runtime._event_bus.subscriber_count("cpu_percent")
            assert before == 1

            runtime._skills_dir = str(Path(minimal_config).parent / "missing-skills")
            ok = await runtime.reload_skills()
            assert ok is False
            assert runtime._event_bus.subscriber_count("cpu_percent") == before
        finally:
            await runtime.stop()
            await start_task


class TestShutdown:
    async def test_shutdown_drains_tier_d_tasks(self, minimal_config, monkeypatch):
        """Runtime must await dispatcher-tracked Tier D tasks before shutdown."""
        _patch_external(monkeypatch)
        runtime = OriRuntime(config_path=str(minimal_config))
        completed: list[bool] = []

        async def _tier_d_work():
            await asyncio.sleep(0.2)
            completed.append(True)

        async def _inject_and_stop():
            await asyncio.sleep(0.05)
            tier_d_task = asyncio.create_task(_tier_d_work())

            class _FakeDispatcher:
                def get_inflight_tier_d_tasks(self):
                    return {tier_d_task} if not tier_d_task.done() else set()

            runtime._dispatcher = _FakeDispatcher()
            await runtime.stop()
            # Give the drained task time to finish
            await asyncio.sleep(0.25)

        await asyncio.gather(runtime.start(), _inject_and_stop())
        assert completed == [True], "Tier D task was abandoned before completion"


class TestWatchdog:
    async def test_watchdog_skipped_gracefully_without_device(
        self, minimal_config, monkeypatch, caplog
    ):
        """/dev/watchdog absent → warning logged, runtime continues normally."""
        _patch_external(monkeypatch)
        monkeypatch.setattr("ori.runtime.os.path.exists", lambda p: False)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        with caplog.at_level(logging.WARNING):
            await asyncio.gather(runtime.start(), _stop())

        watchdog_warnings = [r.message for r in caplog.records]
        assert watchdog_warnings, "Expected watchdog 'not found' warning in logs"

    async def test_watchdog_writes_magic_v_on_shutdown(
        self, minimal_config, monkeypatch, caplog
    ):
        """/dev/watchdog open/write are called, magic V written on shutdown."""
        import builtins
        from unittest.mock import mock_open

        _patch_external(monkeypatch)
        monkeypatch.setattr("ori.runtime.os.path.exists", lambda p: True)

        m_open = mock_open()
        real_open = builtins.open

        def _smart_open(file, *args, **kwargs):
            if file == "/dev/watchdog":
                return m_open(file, *args, **kwargs)
            return real_open(file, *args, **kwargs)

        monkeypatch.setattr("builtins.open", _smart_open)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.1)
            await runtime.stop()

        with caplog.at_level(logging.INFO):
            await asyncio.gather(runtime.start(), _stop())

        # Assert watchdog device was opened for writing
        m_open.assert_called_with("/dev/watchdog", "wb", buffering=0)

        # Assert magical 'V' was written during shutdown
        handle = m_open()
        writes = [c.args[0] for c in handle.write.call_args_list if c.args]
        assert b"V" in writes, "Expected magic 'V' to be written to watchdog"

        # Check logs for clean shutdown line
        v_log = [r.message for r in caplog.records if "magic V written" in r.message]
        assert v_log, "Expected magic V log message"


class TestSensorPolling:
    async def test_sensor_read_error_does_not_crash_runtime(
        self, minimal_config, monkeypatch, caplog
    ):
        """AdapterReadError during polling must log a warning, not crash."""
        from ori.hal.base import AdapterReadError

        _patch_external(monkeypatch)

        read_count = 0

        async def _failing_read(*_: Any):
            nonlocal read_count
            read_count += 1
            raise AdapterReadError("sensor timeout")

        monkeypatch.setattr("ori.hal.psutil_adapter.PsutilAdapter.read", _failing_read)

        runtime = OriRuntime(config_path=str(minimal_config))

        async def _stop():
            await asyncio.sleep(0.35)  # allow a few poll cycles
            await runtime.stop()

        with caplog.at_level(logging.WARNING):
            await asyncio.gather(runtime.start(), _stop())

        assert read_count >= 2, "Expected at least 2 poll attempts"
        warning_msgs = [r.message for r in caplog.records if "read failed" in r.message]
        assert warning_msgs, "Expected 'read failed' warning log"

    async def test_poll_sensor_sets_non_empty_fingerprint(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = AsyncMock()
        runtime._shutdown_event = asyncio.Event()

        reading = SensorReading(
            sensor_id="cpu-sensor",
            sensor_type="cpu_percent",
            value=42.4,
            unit="percent",
            timestamp=1_700_000_000_000,
            quality=1.0,
            metadata={"source": "psutil"},
        )

        class _OneShotAdapter:
            async def read(self, sensor_id: str) -> SensorReading:
                runtime._shutdown_event.set()
                return reading

        bus = AsyncMock()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        await runtime._poll_sensor(_OneShotAdapter(), sensor_cfg, bus, "dev-01")

        event = bus.publish.call_args.args[0]
        assert isinstance(event.fingerprint, str)
        assert event.fingerprint != ""

    async def test_poll_sensor_fingerprint_stable_across_timestamp_changes(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._state_store = AsyncMock()
        bus = AsyncMock()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)

        async def _run_once(reading: SensorReading) -> OriEvent:
            runtime._shutdown_event = asyncio.Event()

            class _OneShotAdapter:
                async def read(self, sensor_id: str) -> SensorReading:
                    runtime._shutdown_event.set()
                    return reading

            await runtime._poll_sensor(_OneShotAdapter(), sensor_cfg, bus, "dev-01")
            return bus.publish.call_args.args[0]

        first = await _run_once(
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=42.44,  # rounds to 42.4
                unit="percent",
                timestamp=1_700_000_000_000,
                quality=1.0,
                metadata={"source": "psutil"},
            )
        )
        second = await _run_once(
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=42.44,  # same rounded value, different timestamp
                unit="percent",
                timestamp=1_700_000_060_000,
                quality=1.0,
                metadata={"source": "psutil"},
            )
        )

        assert first.fingerprint == second.fingerprint

    async def test_deduplicator_suppresses_identical_readings_within_5_seconds(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()

        class _Store:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def append_history(self, event: OriEvent) -> None:
                self.events.append(event)

        class _Bus:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def publish(self, event: OriEvent) -> None:
                self.events.append(event)

        class _SequenceAdapter:
            def __init__(self, readings: list[SensorReading]) -> None:
                self._readings = readings
                self._idx = 0

            async def read(self, sensor_id: str) -> SensorReading:
                reading = self._readings[self._idx]
                self._idx += 1
                if self._idx >= len(self._readings):
                    runtime._shutdown_event.set()
                return reading

        runtime._state_store = _Store()
        bus = _Bus()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        readings = [
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=41.2,
                unit="percent",
                timestamp=1_700_000_000_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=41.2,
                unit="percent",
                timestamp=1_700_000_001_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
        ]

        with patch("ori.network.deduplicator._now_ms", side_effect=[1_000, 2_000]):
            await runtime._poll_sensor(
                _SequenceAdapter(readings),
                sensor_cfg,
                bus,
                "dev-01",
                EventDeduplicator(),
            )

        assert len(bus.events) == 1
        assert len(runtime._state_store.events) == 2

    async def test_deduplicator_allows_identical_readings_after_6_seconds(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()

        class _Store:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def append_history(self, event: OriEvent) -> None:
                self.events.append(event)

        class _Bus:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def publish(self, event: OriEvent) -> None:
                self.events.append(event)

        class _SequenceAdapter:
            def __init__(self, readings: list[SensorReading]) -> None:
                self._readings = readings
                self._idx = 0

            async def read(self, sensor_id: str) -> SensorReading:
                reading = self._readings[self._idx]
                self._idx += 1
                if self._idx >= len(self._readings):
                    runtime._shutdown_event.set()
                return reading

        runtime._state_store = _Store()
        bus = _Bus()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        readings = [
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=41.2,
                unit="percent",
                timestamp=1_700_000_000_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=41.2,
                unit="percent",
                timestamp=1_700_000_006_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
        ]

        with patch("ori.network.deduplicator._now_ms", side_effect=[1_000, 7_001]):
            await runtime._poll_sensor(
                _SequenceAdapter(readings),
                sensor_cfg,
                bus,
                "dev-01",
                EventDeduplicator(),
            )

        assert len(bus.events) == 2
        assert len(runtime._state_store.events) == 2

    async def test_non_reading_events_bypass_deduplication(self):
        bus = EventBus()
        seen: list[OriEvent] = []

        async def _handler(event: OriEvent) -> None:
            seen.append(event)

        bus.subscribe("system.alert", _handler)
        deduplicator = EventDeduplicator()

        first = OriEvent(
            event_id="evt-1",
            event_type="system.alert",
            device_id="dev-01",
            sensor_id="",
            timestamp=1_700_000_000_000,
            reading=None,
        )
        second = OriEvent(
            event_id="evt-2",
            event_type="system.alert",
            device_id="dev-01",
            sensor_id="",
            timestamp=1_700_000_000_100,
            reading=None,
        )

        for event in (first, second):
            if event.reading is not None and deduplicator.process(event) is None:
                continue
            await bus.publish(event)

        assert len(seen) == 2

    async def test_deduplication_does_not_block_history_writes(self, tmp_path: Path):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()
        runtime._state_store = StateStore(str(tmp_path / "ori.db"))
        await runtime._state_store.open()

        class _Bus:
            def __init__(self) -> None:
                self.events: list[OriEvent] = []

            async def publish(self, event: OriEvent) -> None:
                self.events.append(event)

        class _SequenceAdapter:
            def __init__(self, readings: list[SensorReading]) -> None:
                self._readings = readings
                self._idx = 0

            async def read(self, sensor_id: str) -> SensorReading:
                reading = self._readings[self._idx]
                self._idx += 1
                if self._idx >= len(self._readings):
                    runtime._shutdown_event.set()
                return reading

        bus = _Bus()
        sensor_cfg = SimpleNamespace(id="cpu-sensor", poll_interval_ms=1)
        readings = [
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=22.0,
                unit="percent",
                timestamp=1_700_000_000_000,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
            SensorReading(
                sensor_id="cpu-sensor",
                sensor_type="cpu_percent",
                value=22.0,
                unit="percent",
                timestamp=1_700_000_000_100,
                quality=1.0,
                metadata={"source": "psutil"},
            ),
        ]

        try:
            with patch("ori.network.deduplicator._now_ms", side_effect=[1_000, 2_000]):
                await runtime._poll_sensor(
                    _SequenceAdapter(readings),
                    sensor_cfg,
                    bus,
                    "dev-01",
                    EventDeduplicator(),
                )

            history = await runtime._state_store.get_history("cpu-sensor", limit=10)
            assert len(history) == 2
            assert len(bus.events) == 1
        finally:
            await runtime._state_store.close()


class TestCompactionLoop:
    async def test_compaction_loop_runs_deduplicator_cleanup(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._shutdown_event = asyncio.Event()

        cleanup_calls = {"count": 0}

        class _Dedup:
            def cleanup(self) -> None:
                cleanup_calls["count"] += 1

        async def _compact() -> None:
            runtime._shutdown_event.set()

        runtime._state_store = AsyncMock()
        runtime._state_store.compact_history.side_effect = _compact

        async def _fake_wait_for(awaitable, timeout):  # noqa: ARG001
            if hasattr(awaitable, "close"):
                awaitable.close()
            raise asyncio.TimeoutError

        with patch(
            "ori.runtime.asyncio.wait_for",
            new=AsyncMock(side_effect=_fake_wait_for),
        ):
            await runtime._compaction_loop(_Dedup())

        runtime._state_store.compact_history.assert_awaited_once()
        assert cleanup_calls["count"] == 1


class TestProcessTargetResolution:
    def _ctx(self, *, context: dict | None = None, metadata: dict | None = None):
        reading = SensorReading(
            sensor_id="sleep-blocker",
            sensor_type="sleep_blocking_process",
            value=1.0,
            unit="count",
            timestamp=1_700_000_000_000,
            quality=1.0,
            metadata=metadata or {},
        )
        event = OriEvent.from_reading(reading, "dev-01")
        event.context = context or {}
        return SkillContext(skill=None, event=event, state_store=None)

    def test_prefers_explicit_context_target(self):
        ctx = self._ctx(
            context={"terminate_process": {"pid": 1234, "name": "Zoom"}},
            metadata={"processes": [{"pid": 999, "name": "Other"}]},
        )
        assert _process_target_from_context(ctx) == (1234, "Zoom")

    def test_reads_single_metadata_process(self):
        ctx = self._ctx(metadata={"processes": [{"pid": 2222, "name": "Slack"}]})
        assert _process_target_from_context(ctx) == (2222, "Slack")

    def test_returns_none_on_ambiguous_processes(self):
        ctx = self._ctx(
            metadata={
                "processes": [
                    {"pid": 1, "name": "A"},
                    {"pid": 2, "name": "B"},
                ]
            }
        )
        assert _process_target_from_context(ctx) == (None, "")

    def test_uses_recommended_process_when_present(self):
        ctx = self._ctx(
            metadata={
                "processes": [
                    {"pid": 1, "name": "A"},
                    {"pid": 2, "name": "B"},
                ],
                "recommended_process": {"pid": 2, "name": "B"},
            }
        )
        assert _process_target_from_context(ctx) == (2, "B")


class TestCoapCommandResolution:
    def test_prefers_event_context(self):
        reading = SensorReading(
            sensor_id="s-1",
            sensor_type="temperature",
            value=1.0,
            unit="celsius",
            timestamp=1_700_000_000_000,
            quality=1.0,
        )
        event = OriEvent.from_reading(reading, "dev-01")
        event.context = {
            "coap_command": "open_bypass_valve",
            "coap_payload": '{"state":"open"}',
        }
        ctx = SkillContext(
            skill=SimpleNamespace(config={}),
            event=event,
            state_store=None,
            trigger_name="trigger-a",
        )
        command, payload = _coap_command_from_context(ctx)
        assert command == "open_bypass_valve"
        assert payload == '{"state":"open"}'

    def test_uses_skill_trigger_mapping(self):
        reading = SensorReading(
            sensor_id="s-1",
            sensor_type="temperature",
            value=1.0,
            unit="celsius",
            timestamp=1_700_000_000_000,
            quality=1.0,
        )
        event = OriEvent.from_reading(reading, "dev-01")
        ctx = SkillContext(
            skill=SimpleNamespace(
                config={
                    "coap": {
                        "trigger_commands": {
                            "probable_c2_or_shell_foothold": "isolate_vlan",
                        }
                    }
                }
            ),
            event=event,
            state_store=None,
            trigger_name="probable_c2_or_shell_foothold",
        )
        command, payload = _coap_command_from_context(ctx)
        assert command == "isolate_vlan"
        assert payload is None


class TestWebhookIngest:
    async def test_ingest_sms_webhook_returns_false_without_sms_action(self):
        runtime = OriRuntime(config_path="ori.yaml")
        ok = await runtime.ingest_sms_webhook({"from": "+234", "text": "YES"})
        assert ok is False

    async def test_ingest_sms_webhook_delegates_to_sms_action(self):
        runtime = OriRuntime(config_path="ori.yaml")
        runtime._sms_action = AsyncMock()
        runtime._sms_action.ingest_incoming_webhook.return_value = True
        ok = await runtime.ingest_sms_webhook({"from": "+234", "text": "YES"})
        assert ok is True
        runtime._sms_action.ingest_incoming_webhook.assert_awaited_once()


class TestWebhookServerStartup:
    async def test_runtime_starts_sms_webhook_when_enabled(self, tmp_path, monkeypatch):
        _patch_external(monkeypatch)

        skill_dir = tmp_path / "skills" / "test-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "skill.yaml").write_text(
            textwrap.dedent("""\
                name: test-skill
                version: 0.1.0
                author: test
                sensors_required:
                  - type: cpu_percent
                    protocol: psutil
                triggers:
                  - name: high_cpu
                    condition: "value > 90"
                    action_tier: A
                    cooldown_seconds: 0
                    escalate_to: local_slm
                actions:
                  available:
                    - name: alert_whatsapp
                      tier: A
                  defaults:
                    high_cpu: [alert_whatsapp]
            """),
            encoding="utf-8",
        )

        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent(f"""\
                device:
                  id: test-device-01
                  name: Test Device
                  location: Test Lab

                sensors:
                  - id: cpu-sensor
                    type: cpu_percent
                    protocol: psutil
                    poll_interval_ms: 100

                skills:
                  - name: test-skill
                    version: "0.1.0"
                    config: {{}}

                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""
                  offline_fallback: rule

                gateway:
                  enabled: false
                  broker_url: ""

                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                    incoming_webhook:
                      enabled: true
                      host: "127.0.0.1"
                      port: 0
                      path: "/webhooks/sms/africastalking"
                      token: "test-token"
                  relay:
                    enabled: false

                skills_dir: {str(tmp_path / "skills")}
            """),
            encoding="utf-8",
        )

        runtime = OriRuntime(config_path=str(cfg))

        class _FakeServer:
            def __init__(self, *args, **kwargs):
                self.args = args
                self.kwargs = kwargs
                self.serve_until = AsyncMock(side_effect=self._serve_until)

            async def _serve_until(self, shutdown_event):
                await shutdown_event.wait()

        fake_instance = _FakeServer()

        with patch("ori.runtime.SMSWebhookServer", return_value=fake_instance) as cls:

            async def _stop():
                await asyncio.sleep(0.1)
                await runtime.stop()

            await asyncio.gather(runtime.start(), _stop())

        cls.assert_called_once()
        fake_instance.serve_until.assert_awaited_once()

    async def test_runtime_skips_sms_webhook_without_token(self, tmp_path, monkeypatch):
        _patch_external(monkeypatch)

        skill_dir = tmp_path / "skills" / "test-skill"
        skill_dir.mkdir(parents=True)
        (skill_dir / "skill.yaml").write_text(
            textwrap.dedent("""\
                name: test-skill
                version: 0.1.0
                author: test
                sensors_required:
                  - type: cpu_percent
                    protocol: psutil
                triggers:
                  - name: high_cpu
                    condition: "value > 90"
                    action_tier: A
                    cooldown_seconds: 0
                    escalate_to: local_slm
                actions:
                  available:
                    - name: alert_whatsapp
                      tier: A
                  defaults:
                    high_cpu: [alert_whatsapp]
            """),
            encoding="utf-8",
        )

        cfg = tmp_path / "ori.yaml"
        cfg.write_text(
            textwrap.dedent(f"""\
                device:
                  id: test-device-01
                  name: Test Device
                  location: Test Lab
                sensors:
                  - id: cpu-sensor
                    type: cpu_percent
                    protocol: psutil
                    poll_interval_ms: 100
                skills:
                  - name: test-skill
                    version: "0.1.0"
                    config: {{}}
                reasoning:
                  default_tier: local
                  local_model: ""
                  model_path: ""
                  offline_fallback: rule
                gateway:
                  enabled: false
                  broker_url: ""
                actions:
                  primary_alert_channel: sms
                  whatsapp:
                    enabled: false
                  sms:
                    enabled: false
                    incoming_webhook:
                      enabled: true
                      token: ""
                  relay:
                    enabled: false
                skills_dir: {str(tmp_path / "skills")}
            """),
            encoding="utf-8",
        )

        runtime = OriRuntime(config_path=str(cfg))
        with patch("ori.runtime.SMSWebhookServer") as cls:

            async def _stop():
                await asyncio.sleep(0.1)
                await runtime.stop()

            await asyncio.gather(runtime.start(), _stop())

        cls.assert_not_called()
