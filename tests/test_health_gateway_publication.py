# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""runtime-health/v4 `gateway_publication`: a clock that stops publication.

Driven through the real heartbeat publisher and signing clock, and read from
the real `_build_health_snapshot`, so the block and `status` are what a reader
of the snapshot sees.
"""

from __future__ import annotations

import json
import pathlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from ori.gateway import node_heartbeat as node_heartbeat_module
from ori.gateway.envelope_auth import build_gateway_envelope_state
from ori.runtime import OriRuntime
from ori.runtime._gateway_wiring import build_runtime_node_heartbeat_publisher
from ori.security.gateway_messages import (
    GatewayMessageAuthConfig,
    GatewayMessageAuthenticator,
)
from ori.security.signing_clock import SigningClock
from tests.test_health_signing_domains_and_ingress import _gateway_config
from tests.test_runtime_node_heartbeat import _FakeClient, _publisher, _verifier_cache
from tests.waiting import wait_until

HEALTH_V4 = json.loads(
    (
        pathlib.Path(__file__).resolve().parent
        / "vectors"
        / "runtime_health"
        / "health-vectors-v4.json"
    ).read_text()
)
LAST_SEEN_MAX = 2**53 - 1


def _runtime(tmp_path: Path, *, enabled: bool = True) -> OriRuntime:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    runtime._config = _gateway_config(tmp_path, enabled=enabled)
    return runtime


def _refusing_clock(tmp_path: Path) -> SigningClock:
    # A store that cannot open: the clock refuses every signing time.
    return SigningClock(str(tmp_path / "missing" / "state.db"))


async def test_no_gateway_is_disabled(tmp_path: Path) -> None:
    runtime = OriRuntime(config_path="ori.yaml")
    runtime._device_id = "dev-01"
    snapshot = await runtime._build_health_snapshot()
    assert snapshot["gateway_publication"] == {"state": "disabled"}
    runtime = _runtime(tmp_path, enabled=False)
    assert runtime._gateway_publication_health() == {"state": "disabled"}


async def test_no_running_clock_reads_false_and_healthy(tmp_path: Path) -> None:
    """Heartbeat disabled and gateway auth disabled: neither clock runs."""
    runtime = _runtime(tmp_path)
    config = runtime._config
    assert config is not None
    config.gateway.node_heartbeat = {"enabled": False}
    runtime._gateway_envelope_state = build_gateway_envelope_state(config)
    runtime._runtime_node_heartbeat_publisher = build_runtime_node_heartbeat_publisher(
        config, health_snapshot_provider=dict
    )
    assert runtime._gateway_envelope_state is None
    assert runtime._runtime_node_heartbeat_publisher is None
    snapshot = await runtime._build_health_snapshot()
    assert snapshot["gateway_publication"] == {
        "state": "available",
        "heartbeat_clock_out_of_range": False,
        "signing_clock_refusing": False,
    }
    assert "status" not in snapshot and snapshot["critical"] is False


@pytest.mark.parametrize("bad_ms", [0, LAST_SEEN_MAX + 1], ids=["zero", "past-max"])
@pytest.mark.parametrize("good_ms", [1, LAST_SEEN_MAX], ids=["one", "max"])
async def test_an_out_of_range_tick_degrades_until_an_in_range_tick(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_ms: int, good_ms: int
) -> None:
    client = _FakeClient()
    publisher = _publisher(client=client)
    runtime = _runtime(tmp_path)
    runtime._runtime_node_heartbeat_publisher = publisher

    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: bad_ms)
    await publisher._publish_once(client)
    snapshot = await runtime._build_health_snapshot()
    assert client.published == []
    assert snapshot["gateway_publication"]["heartbeat_clock_out_of_range"] is True
    assert snapshot["status"] == "degraded"

    monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: good_ms)
    await publisher._publish_once(client)
    snapshot = await runtime._build_health_snapshot()
    assert len(client.published) == 1
    assert snapshot["gateway_publication"]["heartbeat_clock_out_of_range"] is False
    assert "status" not in snapshot and snapshot["critical"] is False


async def test_the_wall_clock_recovers_while_signing_still_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The heartbeat flag clears on an in-range tick that publishes nothing."""
    clock = _refusing_clock(tmp_path)
    authenticator = GatewayMessageAuthenticator(
        GatewayMessageAuthConfig(shared_secret="site-test-secret", max_skew_ms=300_000),
        replay_cache=_verifier_cache(),
        signing_clock=clock,
    )
    client = _FakeClient()
    publisher = _publisher(client=client, authenticator=authenticator)
    runtime = _runtime(tmp_path)
    runtime._runtime_node_heartbeat_publisher = publisher
    runtime._gateway_envelope_state = SimpleNamespace(  # type: ignore[assignment]
        signing_clock=clock
    )
    try:
        monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 0)
        await publisher._publish_once(client)
        monkeypatch.setattr(node_heartbeat_module, "now_ms", lambda: 1_000_000)
        await publisher._publish_once(client)
        snapshot = await runtime._build_health_snapshot()
    finally:
        clock.stop()
    assert client.published == []
    assert snapshot["gateway_publication"] == {
        "state": "available",
        "heartbeat_clock_out_of_range": False,
        "signing_clock_refusing": True,
    }
    assert snapshot["status"] == "degraded"


def test_the_condition_folds_at_runtime_health_v4s_severity() -> None:
    assert HEALTH_V4["conditions"]["gateway_publication_clock_refused"] == "degraded"


async def test_the_signing_flag_is_current_not_the_last_attempt(
    tmp_path: Path,
) -> None:
    """True before any signing attempt, and false once the store recovers,
    whether or not anything signs in between."""
    store = tmp_path / "later" / "state.db"
    clock = SigningClock(str(store))
    runtime = _runtime(tmp_path)
    runtime._gateway_envelope_state = SimpleNamespace(  # type: ignore[assignment]
        signing_clock=clock
    )
    try:
        snapshot = await runtime._build_health_snapshot()
        assert snapshot["gateway_publication"]["signing_clock_refusing"] is True
        assert snapshot["status"] == "degraded"
        store.parent.mkdir()
        await wait_until(lambda: not clock.refusing(), what="the clock to claim")
        snapshot = await runtime._build_health_snapshot()
    finally:
        clock.stop()
    assert snapshot["gateway_publication"]["signing_clock_refusing"] is False
    assert "status" not in snapshot
