# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""`poll_interval_ms` must reach the adapters that poll on it.

`_parse_sensors` lifts `poll_interval_ms` out of metadata into `SensorConfig`,
and the runtime did not put it back when assembling an adapter's connection
config. `CoapAdapter` and `HttpAdapter` read it anyway, so the read always
returned their own default (ori-runtime #417).

That is not only a setting that failed to apply. Both adapters run a background
loop that refreshes a cache, and `read()` serves that cache. The runtime polls
on the operator's interval while the cache refreshed on the adapter's default of
ten seconds, so a sensor configured at one second served the same reading ten
times over as though each were fresh.

`SmartAdapter` read the same key and never used the value. That read is gone
rather than fed: a read whose result nothing consumes is the same defect from
the other side.
"""

from __future__ import annotations

import pathlib
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from ori.config import SensorConfig
from ori.runtime import adapter_connect_config


def _config() -> Any:
    return SimpleNamespace(
        hal=SimpleNamespace(circuit_breaker={}),
        actions=SimpleNamespace(coap={}),
    )


def _sensor(protocol: str, poll_interval_ms: int, **metadata: Any) -> SensorConfig:
    return SensorConfig(
        id="s1",
        type="temperature",
        protocol=protocol,
        poll_interval_ms=poll_interval_ms,
        metadata=metadata,
        calibration={},
    )


def test_the_assembly_supplies_the_configured_interval() -> None:
    cfg = adapter_connect_config(_sensor("coap", 1500), _config())
    assert cfg["poll_interval_ms"] == 1500


def test_metadata_cannot_displace_the_interval() -> None:
    """It is supplied after the spread, like the other runtime-owned keys.

    `_parse_sensors` already keeps this name out of metadata, so this asserts
    the assembly does not depend on that having happened.
    """
    poisoned = SensorConfig(
        id="s1",
        type="temperature",
        protocol="coap",
        poll_interval_ms=1500,
        metadata={"poll_interval_ms": 99999},
        calibration={},
    )
    assert adapter_connect_config(poisoned, _config())["poll_interval_ms"] == 1500


# ── The adapters that poll on it ─────────────────────────────────────────────


async def test_the_http_adapter_receives_the_configured_interval() -> None:
    """Asserted on the adapter's own state after a connection that succeeded.

    An assembly that supplied the key beside an adapter that ignored it would
    pass a dict-only check and still poll at ten seconds on a device. The
    connection is required to succeed rather than suppressed: an adapter that
    refused before reaching the assignment would otherwise leave the default in
    place and the assertion would read it as proof.
    """
    from ori.hal.http_adapter import HttpAdapter

    adapter = HttpAdapter()
    cfg = adapter_connect_config(
        _sensor("http", 1500, url="https://host/r", json_path="v"), _config()
    )
    try:
        await adapter.connect(cfg)
        assert adapter.is_connected
        assert adapter._poll_interval_ms == 1500
    finally:
        await adapter.close()


async def test_the_coap_adapter_receives_the_configured_interval() -> None:
    """Same assertion for CoAP, without depending on aiocoap being installed.

    `aiocoap` ships in neither requirements file, so a test that needs the real
    library skips in CI as well as locally — proving nothing while looking
    covered. The availability flag and module are patched instead, which is how
    tests/test_coap_adapter.py already exercises this adapter.

    `create_client_context` is awaited by production code, so the fake returns
    an awaitable. A synchronous fake raises `TypeError` inside `connect()`,
    which a suppressed exception would hide — and `_poll_interval_ms` is
    assigned before that point, so the assertion would still pass over an
    adapter that never connected.
    """
    from ori.hal.coap_adapter import CoapAdapter

    class _FakeContext:
        async def shutdown(self) -> None:
            return None

    async def _create_client_context() -> _FakeContext:
        return _FakeContext()

    fake_aiocoap = SimpleNamespace(
        GET="GET",
        Message=lambda code, uri, payload: SimpleNamespace(code=code),
        Context=SimpleNamespace(
            create_client_context=staticmethod(_create_client_context)
        ),
    )

    adapter = CoapAdapter()
    cfg = adapter_connect_config(
        _sensor(
            "coap", 1500, uri="coap://host/r", json_path="v", allowed_hosts=["host"]
        ),
        _config(),
    )
    with (
        patch("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True),
        patch("ori.hal.coap_adapter._aiocoap", fake_aiocoap),
    ):
        try:
            await adapter.connect(cfg)
            assert adapter.is_connected
            assert adapter._poll_interval_ms == 1500
        finally:
            await adapter.close()


@pytest.mark.parametrize("protocol", ["coap", "http"])
async def test_the_adapter_default_is_no_longer_what_an_operator_gets(
    protocol: str,
) -> None:
    """The defect, stated as the thing that must not recur."""
    if protocol == "coap":
        from ori.hal import coap_adapter as module
    else:
        from ori.hal import http_adapter as module

    cfg = adapter_connect_config(_sensor(protocol, 1000), _config())
    assert cfg["poll_interval_ms"] != module._DEFAULT_POLL_INTERVAL_MS


# ── The adapter that never used it ───────────────────────────────────────────


def test_smart_adapter_no_longer_reads_an_interval_it_ignores() -> None:
    """It assigned the value and read it back nowhere.

    Feeding it would have been the wrong fix: the correct answer to a read
    nothing consumes is to remove the read.
    """
    source = pathlib.Path("ori/hal/smart_adapter.py").read_text()
    assert "poll_interval_ms" not in source


def test_no_adapter_directly_reads_a_key_the_assembly_never_supplies() -> None:
    """The general form of #417, for reads this can actually see.

    Every key an adapter reads must be one an operator can set in sensor
    metadata, or one the runtime supplies. A key in neither set resolves to the
    adapter's default no matter what the operator writes.

    **This does not close the class.** `adapter_metadata()` finds literal
    `config.get(...)` calls inside adapter classes and nothing else, so a
    setting an adapter resolves through a shared helper is invisible to it.
    That limitation is not hypothetical: it appeared during #411, when moving
    baud resolution into a helper made both serial adapters look as though they
    read nothing, and it is why those adapters pass presence and values into
    the resolver explicitly rather than handing it the config dict.

    So this catches the next *direct* instance. A helper-resolved one needs
    either a stronger extractor or the same explicit-read discipline #411
    adopted.
    """
    from tests.golden.build_config_surface_inventory import adapter_metadata

    supplied = set(adapter_connect_config(_sensor("psutil", 1000), _config()))
    withheld = {"id", "type", "protocol", "poll_interval_ms", "calibration"}

    unreachable: dict[str, list[str]] = {}
    for name, keys in adapter_metadata().items():
        dead = sorted(k for k in keys if k in withheld and k not in supplied)
        if dead:
            unreachable[name] = dead

    assert not unreachable, (
        f"adapters directly read keys the runtime never supplies: {unreachable}"
    )
