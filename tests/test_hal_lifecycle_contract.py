# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The lifecycle guarantee on `BaseAdapter`, driven against every adapter.

`connect()` does its blocking work off the event loop and `close()` releases
with awaits of its own, so the two can interleave: a close releases what has
been taken so far while the connect's worker goes on taking more, and the
adapter ends up believing it is connected while holding resources nobody else
believes are in use.

ori-platform/ori-runtime#501 fixed that in `I2CAdapter` with a per-adapter lock
and counter. #513 moved the rule to `BaseAdapter`, because copying a counter
into six files multiplies the surface that has to stay correct and gives each
adapter its own chance to get it subtly wrong. These tests drive the guarantee
against each adapter rather than one representative, so an adapter that stops
meeting it fails here by name.

Not every adapter had the defect. Only `SerialAdapter` and `UsbSerialAdapter`
awaited during `connect()`; `SmartAdapter` awaits nothing, and `GrowattAdapter`
and `SolarmanModbusAdapter` already captured the client into a local before
yielding, so their close released only what it had taken. They take the shared
guarantee anyway: an await added to any of them later would otherwise reopen
the race silently.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from ori.hal.base import AdapterConnectionError, BaseAdapter
from ori.hal.coap_adapter import CoapAdapter
from ori.hal.growatt_adapter import GrowattAdapter
from ori.hal.http_adapter import HttpAdapter
from ori.hal.i2c_adapter import I2CAdapter
from ori.hal.lorawan_adapter import LoraWanAdapter
from ori.hal.mqtt_adapter import MqttAdapter
from ori.hal.mqtt_perception_adapter import MqttPerceptionAdapter
from ori.hal.opcua_adapter import OpcUaAdapter
from ori.hal.psutil_adapter import PsutilAdapter
from ori.hal.serial_adapter import SerialAdapter
from ori.hal.smart_adapter import SmartAdapter
from ori.hal.solarman_modbus_adapter import SolarmanModbusAdapter
from ori.hal.usb_serial_adapter import UsbSerialAdapter
from ori.hal.victron_adapter import VictronAdapter
from ori.hal.zigbee_adapter import ZigbeeAdapter

# Every concrete adapter in `ori/hal/`. The list is asserted complete against
# the package below, so a new adapter cannot be added without appearing here.
ADAPTERS = [
    pytest.param(I2CAdapter, id="i2c"),
    pytest.param(SerialAdapter, id="serial"),
    pytest.param(UsbSerialAdapter, id="usb_serial"),
    pytest.param(SmartAdapter, id="smart"),
    pytest.param(GrowattAdapter, id="growatt"),
    pytest.param(SolarmanModbusAdapter, id="solarman_modbus"),
    pytest.param(PsutilAdapter, id="psutil"),
    pytest.param(HttpAdapter, id="http"),
    pytest.param(CoapAdapter, id="coap"),
    pytest.param(OpcUaAdapter, id="opcua"),
    pytest.param(MqttAdapter, id="mqtt"),
    pytest.param(MqttPerceptionAdapter, id="mqtt_perception"),
    pytest.param(LoraWanAdapter, id="lorawan"),
    pytest.param(VictronAdapter, id="victron"),
    pytest.param(ZigbeeAdapter, id="zigbee"),
]


def test_every_adapter_in_the_package_is_covered():
    """The contract is universal, so the list that proves it must be too.

    `BaseAdapter` states the guarantee for every subclass. An adapter added
    later would inherit that claim silently unless something notices, so the
    package is enumerated rather than trusted.
    """
    import importlib
    import inspect
    import pkgutil

    import ori.hal as hal_package

    covered = {param.values[0] for param in ADAPTERS}
    found: set[type] = set()
    for module in pkgutil.iter_modules(hal_package.__path__):
        imported = importlib.import_module(f"ori.hal.{module.name}")
        for _, obj in inspect.getmembers(imported, inspect.isclass):
            if (
                issubclass(obj, BaseAdapter)
                and obj is not BaseAdapter
                and not inspect.isabstract(obj)
                and obj.__module__ == imported.__name__
            ):
                found.add(obj)

    assert found - covered == set(), sorted(c.__name__ for c in found - covered)


class _Probe(BaseAdapter):
    """A minimal adapter that uses the contract and nothing else.

    The guarantee is a property of `BaseAdapter`, so it is asserted here
    without any hardware library, driver or simulation in the way.
    """

    def __init__(self) -> None:
        self.opened = 0
        self.released = 0
        self.release_gate: asyncio.Event | None = None
        self.opening = asyncio.Event()

    async def connect(self, config: dict) -> None:
        async with self._connecting("the probe", release=self._release):
            self.opening.set()
            if self.release_gate is not None:
                await self.release_gate.wait()
            self.opened += 1

    async def read(self, sensor_id: str):  # pragma: no cover - never called
        raise NotImplementedError

    async def close(self) -> None:
        async with self._closing():
            await self._release()

    async def _release(self) -> None:
        self.released += 1


class TestTheGuaranteeItself:
    @pytest.mark.asyncio
    async def test_a_close_during_connect_leaves_it_disconnected(self):
        probe = _Probe()
        probe.release_gate = asyncio.Event()

        connecting = asyncio.create_task(probe.connect({}))
        await probe.opening.wait()
        closing = asyncio.create_task(probe.close())
        await asyncio.sleep(0)

        probe.release_gate.set()
        with pytest.raises(AdapterConnectionError, match="closed while it was still"):
            await asyncio.wait_for(connecting, 5)
        await asyncio.wait_for(closing, 5)

        assert probe.is_connected is False
        assert probe.released >= 1

    @pytest.mark.asyncio
    async def test_a_close_declares_itself_before_it_waits(self):
        """A close waiting on the lock is what the connect must be able to see."""
        probe = _Probe()
        probe.release_gate = asyncio.Event()

        connecting = asyncio.create_task(probe.connect({}))
        await probe.opening.wait()
        closing = asyncio.create_task(probe.close())
        await asyncio.sleep(0)

        assert probe._close_generation == 1

        probe.release_gate.set()
        with pytest.raises(AdapterConnectionError):
            await asyncio.wait_for(connecting, 5)
        await asyncio.wait_for(closing, 5)

    @pytest.mark.asyncio
    async def test_a_connect_queued_behind_another_still_sees_the_close(self):
        """Why the generation is sampled before the lock, not inside it.

        Three-way: one connect holds the lock, a second queues behind it, and
        a close is then requested. The close declares itself immediately, but
        cannot act until both connects release the lock. A second connect that
        sampled the generation *after* winning the lock would compare against
        a value the close had already bumped, find them equal, and report
        success for an adapter that a close outstanding before its body ran is
        about to tear down.
        """
        probe = _Probe()
        probe.release_gate = asyncio.Event()

        first = asyncio.create_task(probe.connect({}))
        await probe.opening.wait()

        second = asyncio.create_task(probe.connect({}))
        # Let the second reach the lock, so it has sampled before the close.
        for _ in range(4):
            await asyncio.sleep(0)

        closing = asyncio.create_task(probe.close())
        await asyncio.sleep(0)
        probe.release_gate.set()

        with pytest.raises(AdapterConnectionError, match="closed while it was still"):
            await asyncio.wait_for(first, 5)
        with pytest.raises(AdapterConnectionError, match="closed while it was still"):
            await asyncio.wait_for(second, 5)
        await asyncio.wait_for(closing, 5)

        assert probe.is_connected is False

    @pytest.mark.asyncio
    async def test_a_release_that_raises_does_not_replace_the_real_failure(self):
        """The caller must see why the connect failed, not why cleanup did."""

        class _BadRelease(_Probe):
            async def _release(self) -> None:
                self.released += 1
                raise RuntimeError("cleanup exploded")

            async def connect(self, config: dict) -> None:
                async with self._connecting("the probe", release=self._release):
                    raise AdapterConnectionError("the real reason")

        probe = _BadRelease()
        with pytest.raises(AdapterConnectionError, match="the real reason"):
            await probe.connect({})
        assert probe.released == 1
        assert probe.is_connected is False

    @pytest.mark.asyncio
    async def test_a_connect_that_fails_gives_back_what_it_took(self):
        class _Failing(_Probe):
            async def connect(self, config: dict) -> None:
                async with self._connecting("the probe", release=self._release):
                    raise AdapterConnectionError("boom")

        probe = _Failing()
        with pytest.raises(AdapterConnectionError, match="boom"):
            await probe.connect({})
        assert probe.released == 1
        assert probe.is_connected is False

    @pytest.mark.asyncio
    async def test_a_successful_connect_releases_nothing(self):
        probe = _Probe()
        await probe.connect({})
        assert probe.is_connected is True
        assert probe.released == 0

    @pytest.mark.asyncio
    async def test_the_lock_serialises_two_connects(self):
        """The second waits rather than interleaving, then is refused."""
        probe = _Probe()
        probe.release_gate = asyncio.Event()

        first = asyncio.create_task(probe.connect({}))
        await probe.opening.wait()
        second = asyncio.create_task(probe.connect({}))
        await asyncio.sleep(0)

        assert not second.done()
        probe.release_gate.set()
        await asyncio.wait_for(first, 5)
        with pytest.raises(AdapterConnectionError, match="already connected"):
            await asyncio.wait_for(second, 5)
        assert probe.opened == 1


# Each entry: the adapter, a first config, a second naming a different target,
# and the attributes a refused second connect must not have changed. The
# drivers are stubbed so the real `connect()` runs without hardware.
ADAPTER_CASES = [
    pytest.param(
        SerialAdapter,
        {"sensor_type": "voltage", "port": "/dev/ttyUSB0", "slave_id": 1},
        {"sensor_type": "current", "port": "/dev/ttyUSB9", "slave_id": 42},
        ("_sensor_type", "_port", "_slave_id"),
        id="serial",
    ),
    pytest.param(
        UsbSerialAdapter,
        {"sensor_type": "usb_power", "device_path": "/dev/ttyUSB0", "slave_id": 1},
        {"sensor_type": "usb_voltage", "device_path": "/dev/ttyUSB9", "slave_id": 42},
        ("_sensor_type", "_device_path", "_slave_id"),
        id="usb_serial",
    ),
    pytest.param(
        SmartAdapter,
        {"sensor_type": "drive_temp_celsius", "device": "/dev/sda"},
        {"sensor_type": "power_on_hours", "device": "/dev/sdz"},
        ("_sensor_type", "_device"),
        id="smart",
    ),
    pytest.param(
        GrowattAdapter,
        {"sensor_type": "growatt_pv_power", "host": "10.0.0.1", "serial": "AAA"},
        {"sensor_type": "growatt_grid_power", "host": "10.0.0.2", "serial": "BBB"},
        ("_sensor_type", "_host", "_serial"),
        id="growatt",
    ),
    pytest.param(
        SolarmanModbusAdapter,
        {
            "sensor_type": "deye_grid_power",
            "profile": "deye_hybrid",
            "host": "10.0.0.1",
            "serial": "AAA",
        },
        {
            "sensor_type": "deye_battery_soc",
            "profile": "deye_hybrid",
            "host": "10.0.0.2",
            "serial": "BBB",
        },
        ("_sensor_type", "_host", "_serial"),
        id="solarman_modbus",
    ),
    pytest.param(
        PsutilAdapter,
        {"sensor_type": "cpu_temp", "sensor_id": "a"},
        {"sensor_type": "battery_percent", "sensor_id": "b"},
        ("_sensor_type", "_sensor_id"),
        id="psutil",
    ),
    pytest.param(
        HttpAdapter,
        {"sensor_type": "power", "url": "http://h/1", "json_path": "v"},
        {"sensor_type": "voltage", "url": "http://h/2", "json_path": "w"},
        ("_sensor_type", "_url", "_json_path"),
        id="http",
    ),
    pytest.param(
        CoapAdapter,
        {"sensor_type": "power", "uri": "coap://h/1", "json_path": "v"},
        {"sensor_type": "voltage", "uri": "coap://h/2", "json_path": "w"},
        ("_sensor_type", "_uri", "_json_path"),
        id="coap",
    ),
    pytest.param(
        OpcUaAdapter,
        {"sensor_type": "power", "url": "opc.tcp://h:1", "node_id": "ns=2;i=1"},
        {"sensor_type": "voltage", "url": "opc.tcp://h:2", "node_id": "ns=2;i=2"},
        ("_sensor_type", "_url", "_node_id"),
        id="opcua",
    ),
    pytest.param(
        MqttAdapter,
        {"sensor_type": "power", "topic": "a/1"},
        {"sensor_type": "voltage", "topic": "a/2"},
        ("_sensor_type", "_topic"),
        id="mqtt",
    ),
    pytest.param(
        MqttPerceptionAdapter,
        {"sensor_type": "ppe_hardhat_violation_score", "topic": "p/1"},
        {"sensor_type": "ppe_vest_violation_score", "topic": "p/2"},
        ("_sensor_type", "_topic"),
        id="mqtt_perception",
    ),
    pytest.param(
        LoraWanAdapter,
        {"sensor_type": "lorawan_humidity", "topic": "l/1"},
        {"sensor_type": "lorawan_battery_percent", "topic": "l/2"},
        ("_sensor_type", "_topic"),
        id="lorawan",
    ),
    pytest.param(
        ZigbeeAdapter,
        {"sensor_type": "battery_percent", "topic": "z/1"},
        {"sensor_type": "contact", "topic": "z/2"},
        ("_sensor_type", "_topic"),
        id="zigbee",
    ),
    pytest.param(
        VictronAdapter,
        {"sensor_type": "victron_battery_soc", "portal_id": "AAA"},
        {"sensor_type": "victron_battery_power", "portal_id": "BBB"},
        ("_sensor_type", "_portal_id"),
        id="victron",
    ),
]


@pytest.fixture
def stub_drivers(monkeypatch):
    """Let every adapter's real `connect()` run without hardware."""
    import ori.hal.growatt_adapter as growatt
    import ori.hal.serial_adapter as serial_module
    import ori.hal.solarman_modbus_adapter as solarman
    import ori.hal.usb_serial_adapter as usb

    monkeypatch.setattr(serial_module, "_SERIAL_AVAILABLE", True)
    monkeypatch.setattr(SerialAdapter, "_open_port", lambda self: None)
    monkeypatch.setattr(usb, "_PYSERIAL_AVAILABLE", True)
    monkeypatch.setattr(usb, "_serial_module", object())
    monkeypatch.setattr(UsbSerialAdapter, "_open_port_sync", lambda self: None)
    monkeypatch.setattr(growatt, "_PYSOLARMAN_AVAILABLE", True)
    monkeypatch.setattr(solarman, "_PYSOLARMAN_AVAILABLE", True)

    import ori.hal.coap_adapter as coap
    import ori.hal.http_adapter as http
    import ori.hal.mqtt_base as mqtt_base
    import ori.hal.opcua_adapter as opcua

    async def _noop(self, *args, **kwargs):
        return None

    monkeypatch.setattr(http, "_HTTPX_AVAILABLE", True)
    monkeypatch.setattr(http, "_httpx", object())
    monkeypatch.setattr(HttpAdapter, "_poll_loop", _noop)

    monkeypatch.setattr(coap, "_AIOCOAP_AVAILABLE", True)

    class _Context:
        @staticmethod
        async def create_client_context():
            return object()

    monkeypatch.setattr(coap, "_aiocoap", SimpleNamespace(Context=_Context))
    monkeypatch.setattr(CoapAdapter, "_poll_loop", _noop)
    monkeypatch.setattr(CoapAdapter, "_validate_target", lambda self: None)
    monkeypatch.setattr(CoapAdapter, "_shutdown_context", _noop)

    class _UaClient:
        def __init__(self, url):
            self.url = url

        async def connect(self):
            return None

        async def disconnect(self):
            return None

        def get_node(self, node_id):
            return node_id

    monkeypatch.setattr(opcua, "_ASYNCUA_AVAILABLE", True)
    monkeypatch.setattr(opcua, "_AsyncUaClient", _UaClient)

    # The MQTT family's broker work is `_connect_mqtt`; what is under test is
    # whether each subclass runs its body inside the guard.
    monkeypatch.setattr(mqtt_base, "_AIOMQTT_AVAILABLE", True)
    monkeypatch.setattr(mqtt_base.MqttCachedAdapter, "_connect_mqtt", _noop)
    monkeypatch.setattr(mqtt_base.MqttCachedAdapter, "_close_mqtt", _noop)


class TestEveryAdapterInherits:
    """Driven through each adapter's real `connect()`, not through the base class.

    An earlier version of these tests called `adapter._connecting(...)`
    directly and asserted on `inspect.getsource`. That re-tested `BaseAdapter`
    six times under six ids and proved nothing about any adapter: the contract
    could be dead-coded out of one of them and the whole suite still passed.
    """

    @pytest.mark.parametrize(
        ("adapter_class", "first", "second", "guarded"), ADAPTER_CASES
    )
    @pytest.mark.asyncio
    async def test_a_second_connect_is_refused(
        self, stub_drivers, adapter_class, first, second, guarded
    ):
        adapter = adapter_class()
        await adapter.connect(dict(first))
        assert adapter.is_connected is True

        with pytest.raises(AdapterConnectionError, match="already connected"):
            await adapter.connect(dict(second))

    @pytest.mark.parametrize(
        ("adapter_class", "first", "second", "guarded"), ADAPTER_CASES
    )
    @pytest.mark.asyncio
    async def test_a_refused_connect_changes_nothing(
        self, stub_drivers, adapter_class, first, second, guarded
    ):
        """The refusal must fire before the adapter's configuration moves.

        Assigning first leaves the adapter connected on the old handle while
        its fields name the new target, so `read()` samples one device and
        labels the reading with another.
        """
        adapter = adapter_class()
        await adapter.connect(dict(first))
        before = {name: getattr(adapter, name) for name in guarded}
        breaker_before = adapter._breaker

        with pytest.raises(AdapterConnectionError):
            await adapter.connect(dict(second))

        assert {name: getattr(adapter, name) for name in guarded} == before
        assert adapter._breaker is breaker_before
        assert adapter.is_connected is True

    @pytest.mark.parametrize(
        ("adapter_class", "first", "second", "guarded"), ADAPTER_CASES
    )
    @pytest.mark.asyncio
    async def test_connect_after_close_is_admitted(
        self, stub_drivers, adapter_class, first, second, guarded
    ):
        """The refusal is about a *live* adapter, not a spent one."""
        adapter = adapter_class()
        await adapter.connect(dict(first))
        await adapter.close()
        assert adapter.is_connected is False

        await adapter.connect(dict(second))

        assert adapter.is_connected is True
        assert getattr(adapter, guarded[1]) == second[guarded[1].lstrip("_")]

    @pytest.mark.parametrize(
        ("adapter_class", "first", "second", "guarded"), ADAPTER_CASES
    )
    @pytest.mark.asyncio
    async def test_a_close_during_connect_refuses_and_disconnects(
        self, stub_drivers, adapter_class, first, second, guarded
    ):
        """The race, through the adapter's own `connect()`."""
        adapter = adapter_class()
        gate = asyncio.Event()
        original = type(adapter)._connecting

        def gated(self, description, *, release=None):
            @asynccontextmanager
            async def run():
                async with original(self, description, release=release):
                    await gate.wait()
                    yield

            return run()

        monkeypatch = pytest.MonkeyPatch()
        monkeypatch.setattr(type(adapter), "_connecting", gated)
        try:
            task = asyncio.create_task(adapter.connect(dict(first)))
            await asyncio.sleep(0)
            closing = asyncio.create_task(adapter.close())
            await asyncio.sleep(0)
            gate.set()
            with pytest.raises(AdapterConnectionError, match="closed while"):
                await asyncio.wait_for(task, 5)
            await asyncio.wait_for(closing, 5)
        finally:
            monkeypatch.undo()

        assert adapter.is_connected is False

    @pytest.mark.parametrize("adapter_class", ADAPTERS)
    @pytest.mark.asyncio
    async def test_the_lifecycle_lock_is_per_adapter(self, adapter_class):
        one = adapter_class()
        another = adapter_class()
        assert one._lifecycle is not another._lifecycle
        assert one._lifecycle is one._lifecycle
