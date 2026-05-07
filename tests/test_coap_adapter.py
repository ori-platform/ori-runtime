# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import (
    AdapterConnectionError,
    AdapterReadError,
    AdapterTimeoutError,
    CircuitState,
)
from ori.hal.coap_adapter import CoapAdapter


def _config(
    sensor_id: str = "coap-temp-01",
    sensor_type: str = "temperature",
    poll_interval_ms: int = 1000,
    timeout_s: float = 0.1,
    failure_threshold: int = 2,
) -> dict:
    return {
        "sensor_id": sensor_id,
        "sensor_type": sensor_type,
        "uri": "coap://192.168.1.70/telemetry/temp",
        "method": "GET",
        "json_path": "metrics.temp_c",
        "unit": "celsius",
        "poll_interval_ms": poll_interval_ms,
        "timeout_s": timeout_s,
        "allowed_hosts": ["192.168.1.70"],
        "circuit_breaker": {
            "failure_threshold": failure_threshold,
            "recovery_timeout_s": 300,
            "success_threshold": 2,
        },
    }


class _FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload


class _FakeRequester:
    def __init__(self, response_fut: asyncio.Future):
        self.response = response_fut


class _FakeContext:
    def __init__(self, response_futures: list[asyncio.Future]):
        self._responses = response_futures
        self.messages = []
        self.shutdown_called = False

    def request(self, message):
        self.messages.append(message)
        if not self._responses:
            fut: asyncio.Future = asyncio.Future()
            fut.set_exception(RuntimeError("no fake response configured"))
            return _FakeRequester(fut)
        return _FakeRequester(self._responses.pop(0))

    async def shutdown(self):
        self.shutdown_called = True


def _completed_future(value):
    fut = asyncio.Future()
    fut.set_result(value)
    return fut


async def _neverending_poll_loop(*_args, **_kwargs):
    await asyncio.sleep(60)


class TestCoapAdapter:
    @pytest.mark.asyncio
    async def test_connect_raises_when_aiocoap_missing(self):
        adapter = CoapAdapter()
        with (
            patch("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", False),
            patch("ori.hal.coap_adapter._aiocoap", None),
        ):
            with pytest.raises(AdapterConnectionError, match="aiocoap"):
                await adapter.connect(_config())

    @pytest.mark.asyncio
    async def test_connect_rejects_uri_host_not_in_allowlist(self):
        adapter = CoapAdapter()
        cfg = _config()
        cfg["uri"] = "coap://10.0.0.9/telemetry/temp"
        fake_aiocoap = SimpleNamespace(
            GET="GET",
            Message=lambda code, uri, payload: SimpleNamespace(
                code=code, uri=uri, payload=payload
            ),
            Context=SimpleNamespace(
                create_client_context=staticmethod(
                    lambda: _completed_future(_FakeContext([]))
                )
            ),
        )
        with (
            patch("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True),
            patch("ori.hal.coap_adapter._aiocoap", fake_aiocoap),
        ):
            with pytest.raises(AdapterConnectionError, match="allowed_hosts"):
                await adapter.connect(cfg)

    @pytest.mark.asyncio
    async def test_successful_poll_caches(self):
        adapter = CoapAdapter()
        response_future = _completed_future(
            _FakeResponse(b'{"metrics":{"temp_c":27.5}}')
        )
        fake_context = _FakeContext([response_future])
        fake_aiocoap = SimpleNamespace(
            GET="GET",
            Message=lambda code, uri, payload: SimpleNamespace(
                code=code, uri=uri, payload=payload
            ),
            Context=SimpleNamespace(
                create_client_context=staticmethod(
                    lambda: _completed_future(fake_context)
                )
            ),
        )
        with (
            patch("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True),
            patch("ori.hal.coap_adapter._aiocoap", fake_aiocoap),
            patch.object(CoapAdapter, "_poll_loop", new=_neverending_poll_loop),
        ):
            await adapter.connect(_config())
            await adapter._poll_once()
            reading = await adapter.read("coap-temp-01")
            assert reading.value == pytest.approx(27.5)
            assert reading.sensor_type == "temperature"
            assert reading.unit == "celsius"
            assert reading.metadata["source"] == "coap"
            await adapter.close()
            assert fake_context.shutdown_called is True

    @pytest.mark.asyncio
    async def test_read_before_poll_raises(self):
        adapter = CoapAdapter()
        fake_context = _FakeContext([_completed_future(_FakeResponse(b"{}"))])
        fake_aiocoap = SimpleNamespace(
            GET="GET",
            Message=lambda code, uri, payload: SimpleNamespace(
                code=code, uri=uri, payload=payload
            ),
            Context=SimpleNamespace(
                create_client_context=staticmethod(
                    lambda: _completed_future(fake_context)
                )
            ),
        )
        with (
            patch("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True),
            patch("ori.hal.coap_adapter._aiocoap", fake_aiocoap),
            patch.object(CoapAdapter, "_poll_loop", new=_neverending_poll_loop),
        ):
            await adapter.connect(_config())
            with pytest.raises(AdapterReadError, match="no data available yet"):
                await adapter.read("coap-temp-01")
            await adapter.close()

    @pytest.mark.asyncio
    async def test_timeout_raises_adapter_timeout(self):
        adapter = CoapAdapter()
        pending = asyncio.Future()
        fake_context = _FakeContext([pending])
        fake_aiocoap = SimpleNamespace(
            GET="GET",
            Message=lambda code, uri, payload: SimpleNamespace(
                code=code, uri=uri, payload=payload
            ),
            Context=SimpleNamespace(
                create_client_context=staticmethod(
                    lambda: _completed_future(fake_context)
                )
            ),
        )
        with (
            patch("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True),
            patch("ori.hal.coap_adapter._aiocoap", fake_aiocoap),
            patch.object(CoapAdapter, "_poll_loop", new=_neverending_poll_loop),
        ):
            await adapter.connect(_config(timeout_s=0.01))
            with pytest.raises(AdapterTimeoutError, match="timeout polling"):
                await adapter._poll_once()
            await adapter.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = CoapAdapter()
        bad1 = _completed_future(_FakeResponse(b'{"metrics":{"temp_c":"bad"}}'))
        bad2 = _completed_future(_FakeResponse(b'{"metrics":{"temp_c":"bad"}}'))
        fake_context = _FakeContext([bad1, bad2])
        fake_aiocoap = SimpleNamespace(
            GET="GET",
            Message=lambda code, uri, payload: SimpleNamespace(
                code=code, uri=uri, payload=payload
            ),
            Context=SimpleNamespace(
                create_client_context=staticmethod(
                    lambda: _completed_future(fake_context)
                )
            ),
        )
        with (
            patch("ori.hal.coap_adapter._AIOCOAP_AVAILABLE", True),
            patch("ori.hal.coap_adapter._aiocoap", fake_aiocoap),
            patch.object(CoapAdapter, "_poll_loop", new=_neverending_poll_loop),
        ):
            await adapter.connect(_config(failure_threshold=2))
            with pytest.raises(AdapterReadError):
                await adapter._poll_once()
            assert adapter._breaker is not None
            assert adapter._breaker.state == CircuitState.CLOSED

            with pytest.raises(AdapterReadError):
                await adapter._poll_once()
            assert adapter._breaker.state == CircuitState.OPEN

            with pytest.raises(AdapterReadError, match="circuit breaker OPEN"):
                await adapter._poll_once()
            await adapter.close()
