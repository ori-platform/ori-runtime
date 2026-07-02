# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from ori.hal.base import AdapterConnectionError, AdapterReadError, CircuitState
from ori.hal.http_adapter import HttpAdapter


def _config(
    sensor_id: str = "outdoor-temperature",
    sensor_type: str = "temperature",
    poll_interval_ms: int = 1000,
    failure_threshold: int = 2,
) -> dict:
    return {
        "sensor_id": sensor_id,
        "sensor_type": sensor_type,
        "url": "http://example.local/metrics",
        "json_path": "main.temp",
        "unit": "kelvin",
        "poll_interval_ms": poll_interval_ms,
        "timeout_s": 2.0,
        "circuit_breaker": {
            "failure_threshold": failure_threshold,
            "recovery_timeout_s": 300,
            "success_threshold": 2,
        },
    }


class _FakeResponse:
    def __init__(
        self, payload: dict | None = None, raise_error: Exception | None = None
    ):
        self._payload = payload or {}
        self._raise_error = raise_error

    def raise_for_status(self) -> None:
        if self._raise_error is not None:
            raise self._raise_error

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    def __init__(self, responses: list[_FakeResponse], timeout: float):
        self._responses = responses
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def get(self, _url: str):
        if not self._responses:
            raise RuntimeError("no fake response configured")
        return self._responses.pop(0)


def _fake_httpx_module(responses: list[_FakeResponse]) -> SimpleNamespace:
    def _factory(*, timeout: float):
        return _FakeClient(responses=responses, timeout=timeout)

    return SimpleNamespace(AsyncClient=_factory)


async def _neverending_poll_loop(*_args, **_kwargs) -> None:
    await asyncio.sleep(60)


class TestHttpAdapter:
    def test_extract_nested_path(self):
        value = HttpAdapter._extract({"main": {"temp": 300.5}}, "main.temp")
        assert value == pytest.approx(300.5)

    def test_extract_invalid_path(self):
        with pytest.raises(AdapterReadError, match="json_path"):
            HttpAdapter._extract({"main": {"temp": 300.5}}, "main.humidity")

    @pytest.mark.asyncio
    async def test_read_before_poll(self):
        adapter = HttpAdapter()
        with (
            patch("ori.hal.http_adapter._HTTPX_AVAILABLE", True),
            patch(
                "ori.hal.http_adapter._httpx",
                _fake_httpx_module([_FakeResponse({"main": {"temp": 300.0}})]),
            ),
            patch.object(HttpAdapter, "_poll_loop", new=_neverending_poll_loop),
        ):
            await adapter.connect(_config())
            with pytest.raises(AdapterReadError, match="no data available yet"):
                await adapter.read("outdoor-temperature")
            await adapter.close()

    @pytest.mark.asyncio
    async def test_successful_poll_caches(self):
        adapter = HttpAdapter()
        responses = [_FakeResponse({"main": {"temp": 300.5}})]
        with (
            patch("ori.hal.http_adapter._HTTPX_AVAILABLE", True),
            patch("ori.hal.http_adapter._httpx", _fake_httpx_module(responses)),
            patch.object(HttpAdapter, "_poll_loop", new=_neverending_poll_loop),
        ):
            await adapter.connect(_config())
            await adapter._poll_once()
            reading = await adapter.read("outdoor-temperature")
            assert reading.value == pytest.approx(300.5)
            assert reading.unit == "kelvin"
            assert reading.sensor_type == "temperature"
            await adapter.close()

    @pytest.mark.asyncio
    async def test_poll_failure_keeps_cache(self):
        adapter = HttpAdapter()
        responses = [
            _FakeResponse({"main": {"temp": 301.1}}),
            _FakeResponse(raise_error=RuntimeError("500")),
        ]
        with (
            patch("ori.hal.http_adapter._HTTPX_AVAILABLE", True),
            patch("ori.hal.http_adapter._httpx", _fake_httpx_module(responses)),
            patch.object(HttpAdapter, "_poll_loop", new=_neverending_poll_loop),
        ):
            await adapter.connect(_config())
            await adapter._poll_once()
            first = await adapter.read("outdoor-temperature")
            assert first.value == pytest.approx(301.1)

            with pytest.raises(AdapterReadError):
                await adapter._poll_once()

            after_failure = await adapter.read("outdoor-temperature")
            assert after_failure.value == pytest.approx(301.1)
            await adapter.close()

    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        adapter = HttpAdapter()
        responses = [
            _FakeResponse(raise_error=RuntimeError("500")),
            _FakeResponse(raise_error=RuntimeError("500")),
        ]
        with (
            patch("ori.hal.http_adapter._HTTPX_AVAILABLE", True),
            patch("ori.hal.http_adapter._httpx", _fake_httpx_module(responses)),
            patch.object(HttpAdapter, "_poll_loop", new=_neverending_poll_loop),
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

    @pytest.mark.asyncio
    async def test_connect_raises_when_httpx_missing(self):
        adapter = HttpAdapter()
        with (
            patch("ori.hal.http_adapter._HTTPX_AVAILABLE", False),
            patch("ori.hal.http_adapter._httpx", None),
        ):
            with pytest.raises(AdapterConnectionError, match="httpx"):
                await adapter.connect(_config())
            assert adapter.is_connected is False
