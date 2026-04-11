# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
import builtins
import sys
import textwrap
import types
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from ori.runtime import OriRuntime


def _patch_external(monkeypatch):
    monkeypatch.setattr(
        "ori.actions.whatsapp.TwilioProvider.send", AsyncMock(return_value=True)
    )
    monkeypatch.setattr("ori.actions.sms.SMSAction.send", AsyncMock(return_value=True))


def _write_runtime_config(tmp_path: Path, hal_block: str = "") -> Path:
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
        textwrap.dedent(
            f"""\
            device:
              id: watchdog-test-01
              name: Watchdog Test
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
            {hal_block}
            skills_dir: {str(tmp_path / "skills")}
            """
        ),
        encoding="utf-8",
    )
    return cfg


@pytest.mark.asyncio
async def test_disabled_by_default(tmp_path: Path, monkeypatch):
    _patch_external(monkeypatch)
    cfg = _write_runtime_config(tmp_path)
    runtime = OriRuntime(config_path=str(cfg))

    mocked_external_loop = AsyncMock()
    monkeypatch.setattr(runtime, "_external_watchdog_loop", mocked_external_loop)

    async def _stop():
        await asyncio.sleep(0.15)
        await runtime.stop()

    await asyncio.gather(runtime.start(), _stop())
    assert mocked_external_loop.await_count == 0


@pytest.mark.asyncio
async def test_enabled_starts_loop(monkeypatch):
    runtime = OriRuntime(config_path="ori.yaml")

    class _Pin:
        def __init__(self):
            self.on_calls = 0
            self.off_calls = 0

        def on(self):
            self.on_calls += 1

        def off(self):
            self.off_calls += 1

        def close(self):
            return None

    pin = _Pin()
    fake_gpiozero = types.SimpleNamespace(DigitalOutputDevice=lambda _pin: pin)
    monkeypatch.setitem(sys.modules, "gpiozero", fake_gpiozero)

    task = asyncio.create_task(
        runtime._external_watchdog_loop(gpio_pin=17, ping_interval_s=0.05)
    )
    await asyncio.sleep(0.2)
    runtime._shutdown_event.set()
    await asyncio.wait_for(task, timeout=1.0)

    assert pin.on_calls >= 1
    assert pin.off_calls >= 1


@pytest.mark.asyncio
async def test_no_gpiozero_silent(monkeypatch):
    runtime = OriRuntime(config_path="ori.yaml")

    real_import = builtins.__import__

    def _import(name, *args, **kwargs):
        if name == "gpiozero":
            raise ImportError("gpiozero not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _import)
    await runtime._external_watchdog_loop(gpio_pin=17, ping_interval_s=0.01)
