# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A started runtime registers itself: the command records, the runtime seals.

The runtime is started for real, serves its own health socket and holds its
own store; `evidence commission` runs as a subprocess against both; the
runtime's reconciliation loop seals the registration without a restart; and a
second start reports the same pending-since time.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
import tempfile
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

from ori.runtime import OriRuntime

REPO = Path(__file__).resolve().parent.parent.parent
DEVICE = "bench-01"
SECRET_ENV = "ORI_TEST_REGISTRATION_SECRET"
REFERENCE = "sha256:" + "ef" * 32


def _config(root: Path) -> Path:
    path = root / "ori.yaml"
    path.write_text(
        textwrap.dedent(f"""\
            device:
              id: {DEVICE}
              name: Bench
              location: Test Lab
              deployment_profile: development
            sensors:
              - id: cpu
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 1000
            skills: []
            reasoning:
              default_tier: rule
            database:
              path: {root / "state.db"}
            health_socket:
              path: {root / "h.sock"}
            evidence:
              enabled: true
              db_path: {root / "evidence.db"}
              key_path: {root / "evidence.key"}
              device_secret_env: {SECRET_ENV}
            logging:
              level: INFO
              file: {root / "ori.log"}
            """),
        encoding="utf-8",
    )
    return path


async def _started(config: Path) -> tuple[OriRuntime, asyncio.Task[None]]:
    runtime = OriRuntime(config_path=str(config))
    task = asyncio.create_task(runtime.start())
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if task.done():
            raise AssertionError(f"the runtime did not start: {task.exception()!r}")
        if (config.parent / "h.sock").exists() and runtime._evidence_attestor:
            return runtime, task
        await asyncio.sleep(0.05)
    raise AssertionError("the runtime never served health")


async def _stopped(runtime: OriRuntime, task: asyncio.Task[None]) -> None:
    await runtime.stop()
    task.cancel()
    _, pending = await asyncio.wait({task}, timeout=10)
    assert not pending


async def _until_status(runtime: OriRuntime, status: str) -> dict[str, Any]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        health = await runtime._evidence_health()
        if health.get("registration_status") == status:
            return health
        await asyncio.sleep(0.05)
    raise AssertionError(f"registration never reached {status}")


@pytest.fixture
def root(monkeypatch):
    path = Path(tempfile.mkdtemp(prefix="ori-rr-", dir="/tmp"))
    monkeypatch.setenv(SECRET_ENV, "install-secret-for-runtime-registration")
    monkeypatch.setattr("ori.runtime.RECONCILE_INTERVAL_S", 0.1)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


async def test_a_started_runtime_registers_itself_and_the_state_survives_restart(root):
    config = _config(root)
    runtime, task = await _started(config)
    try:
        before = await _until_status(runtime, "pending_authorisation")
        assert before["anchor_epoch_id"].startswith("sha256:")

        env = {k: v for k, v in os.environ.items() if k != SECRET_ENV}
        env["PYTHONPATH"] = str(REPO)
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ori.cli_bridge",
            "evidence",
            "commission",
            "--path",
            str(config),
            "--reference",
            REFERENCE,
            "--socket",
            str(root / "h.sock"),
            cwd=str(root),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=60)
        assert proc.returncode == 0, (out, err)
        result = json.loads(out)["result"]
        assert result["anchor_epoch_id"] == before["anchor_epoch_id"]
        assert result["registration_status"] == "pending_confirmation"

        # The whole snapshot a started runtime serves, measured against the
        # bridge's read limit rather than assumed to fit.
        from ori.cli_bridge import _HEALTH_REPLY_LIMIT_BYTES

        probe = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ori.cli_bridge",
            "health",
            "snapshot",
            "--socket",
            str(root / "h.sock"),
            cwd=str(root),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        snapshot, _ = await asyncio.wait_for(probe.communicate(), timeout=60)
        assert probe.returncode == 0, snapshot
        assert "sensors" in json.loads(snapshot)["result"]["health"]
        assert len(snapshot) * 16 < _HEALTH_REPLY_LIMIT_BYTES, len(snapshot)

        after = await _until_status(runtime, "pending_confirmation")
        since = after["registration_pending_since_ms"]
        assert isinstance(since, int)
        assert after["registration_confirmation_overdue"] is False
        attestor = runtime._evidence_attestor
        assert attestor is not None and attestor.outbound is not None
        [carried] = await attestor.outbound.pending_artifacts()
        assert json.loads(carried["artifact_json"])["commissioning_digest"] == REFERENCE
    finally:
        await _stopped(runtime, task)

    runtime, task = await _started(config)
    try:
        again = await _until_status(runtime, "pending_confirmation")
        assert again["registration_pending_since_ms"] == since
        assert again["anchor_epoch_id"] == before["anchor_epoch_id"]
    finally:
        await _stopped(runtime, task)
