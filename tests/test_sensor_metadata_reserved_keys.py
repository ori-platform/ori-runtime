# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""A sensor entry must not displace what the runtime supplies to an adapter.

`runtime.py` injects the sensor's identity and the HAL circuit-breaker settings
into the dict handed to `adapter.connect()`. Those names were not in the
first-class set `_parse_sensors` withholds, and metadata was spread last, so a
sensor entry could overwrite them (ori-runtime #416).

Two consequences made this a safety defect rather than an untidiness. A sensor
could raise `failure_threshold` to a value its adapter would never reach,
disabling breaker recovery for that adapter while `hal.circuit_breaker` still
read as configured. And a sensor declared one type could reach its adapter as
another, so the reading was produced under an identity nobody declared.

Both layers are tested separately on purpose. Config load refuses the entry;
the runtime's assembly order refuses to be displaced even if something reaches
it anyway. A check that holds only because an earlier check held is not a
boundary.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from ori.config import (
    RESERVED_SENSOR_METADATA_KEYS,
    ConfigValidationError,
    SensorConfig,
    _parse_sensors,
)
from ori.hal.base import CircuitState
from ori.hal.psutil_adapter import PsutilAdapter
from ori.runtime import adapter_connect_config


def _sensor(**overrides: Any) -> list[dict]:
    return [
        {"id": "load-current", "type": "current", "protocol": "psutil", **overrides}
    ]


# ── Layer 1: config load refuses the entry ───────────────────────────────────


@pytest.mark.parametrize("key", sorted(RESERVED_SENSOR_METADATA_KEYS))
def test_a_reserved_key_on_a_sensor_is_refused(key: str) -> None:
    with pytest.raises(ConfigValidationError, match="supplied by the runtime"):
        _parse_sensors(_sensor(**{key: "anything"}))


def test_the_refusal_names_every_offending_key() -> None:
    """One error listing all of them, not one error per run of the loader."""
    with pytest.raises(ConfigValidationError) as excinfo:
        _parse_sensors(_sensor(sensor_type="temperature", circuit_breaker={}))
    message = str(excinfo.value)
    assert "'circuit_breaker'" in message
    assert "'sensor_type'" in message


def test_the_refusal_says_where_the_setting_belongs() -> None:
    """A refusal that does not say what to do instead invites a workaround."""
    with pytest.raises(ConfigValidationError) as excinfo:
        _parse_sensors(_sensor(circuit_breaker={"failure_threshold": 999}))
    assert "hal.circuit_breaker" in str(excinfo.value)


def test_calibration_is_not_in_the_reserved_set() -> None:
    """It is a first-class sensor key, so it never reaches metadata at all.

    Reserving it would refuse `calibration:` on every sensor that uses it.
    """
    assert "calibration" not in RESERVED_SENSOR_METADATA_KEYS
    assert _parse_sensors(_sensor(calibration={"sensitivity": 0.066}))[0].calibration


def test_an_ordinary_sensor_still_loads() -> None:
    sensors = _parse_sensors(_sensor(port="/dev/ttyUSB0"))
    assert sensors[0].metadata == {"port": "/dev/ttyUSB0"}


# ── Layer 2: the runtime's assembly cannot be displaced ──────────────────────


def _config(circuit_breaker: dict[str, Any] | None = None) -> Any:
    """A Config stub carrying only what the assembly reads."""
    return SimpleNamespace(
        hal=SimpleNamespace(
            circuit_breaker=circuit_breaker
            or {
                "failure_threshold": 5,
                "recovery_timeout_s": 300,
                "success_threshold": 2,
            }
        ),
        actions=SimpleNamespace(coap={}),
    )


def _poisoned(**metadata: Any) -> SensorConfig:
    """A sensor whose metadata names runtime-supplied keys.

    Built directly rather than through the loader, because the loader now
    refuses exactly this. That is the point: the assembly must hold on its own,
    for a value that reached it by any route the loader did not see.
    """
    return SensorConfig(
        id="load-current",
        type="cpu_percent",
        protocol="psutil",
        poll_interval_ms=1000,
        metadata=metadata,
        calibration={},
    )


@pytest.mark.parametrize(
    "key, poison",
    [
        ("sensor_id", "spoofed"),
        ("sensor_type", "temperature"),
        ("circuit_breaker", {"failure_threshold": 999}),
    ],
)
def test_metadata_cannot_displace_a_runtime_supplied_key(key: str, poison: Any) -> None:
    cfg = adapter_connect_config(_poisoned(**{key: poison}), _config())
    assert cfg[key] != poison


def test_metadata_that_names_nothing_reserved_survives_assembly() -> None:
    cfg = adapter_connect_config(_poisoned(port="/dev/ttyUSB0"), _config())
    assert cfg["port"] == "/dev/ttyUSB0"


def test_every_reserved_key_is_actually_supplied_by_the_assembly() -> None:
    """The reserved set and what the runtime supplies must not drift apart.

    A name reserved at load but no longer supplied would refuse a key for a
    reason that stopped being true; one supplied but not reserved is #416 again.
    """
    assert RESERVED_SENSOR_METADATA_KEYS <= set(
        adapter_connect_config(_poisoned(), _config())
    )


# ── Behavioural: a real adapter, connected, keeps the runtime's breaker ──────
#
# Everything above inspects a dict. This drives a real HAL adapter through the
# real assembly and asserts the breaker it built, because an assembly that
# produces the right dict and an adapter that ignores it would pass the
# structural check and still be wrong on a device.


async def test_a_connected_adapter_uses_the_runtime_breaker_not_the_sensor_one() -> (
    None
):
    global_cb = {
        "failure_threshold": 5,
        "recovery_timeout_s": 300,
        "success_threshold": 2,
    }
    sensor = _poisoned(
        circuit_breaker={"failure_threshold": 999, "recovery_timeout_s": 1}
    )

    adapter = PsutilAdapter()
    await adapter.connect(adapter_connect_config(sensor, _config(global_cb)))

    breaker = adapter._breaker
    assert breaker is not None
    assert breaker.failure_threshold == 5, "the sensor's 999 must not reach the breaker"
    assert breaker.recovery_timeout_s == 300


async def test_a_connected_adapter_keeps_the_declared_sensor_identity() -> None:
    # Both types are ones PsutilAdapter supports, so a win by the poison would
    # silently read the wrong metric rather than raising.
    sensor = _poisoned(sensor_type="memory_percent", sensor_id="spoofed")

    adapter = PsutilAdapter()
    await adapter.connect(adapter_connect_config(sensor, _config()))

    # `read()` takes the sensor id from its caller, so the identity that comes
    # from config -- and therefore the one at risk here -- is the type.
    reading = await adapter.read("load-current")
    assert adapter._sensor_type == "cpu_percent"
    assert reading.sensor_type == "cpu_percent"
    assert reading.unit == "percent"


async def test_the_breaker_still_opens_at_the_configured_threshold() -> None:
    """A boundary that produced an unusable breaker would also pass the above."""
    adapter = PsutilAdapter()
    await adapter.connect(
        adapter_connect_config(_poisoned(), _config({"failure_threshold": 2}))
    )
    breaker = adapter._breaker
    assert breaker is not None
    assert breaker.state is CircuitState.CLOSED
    for _ in range(2):
        breaker._record_failure()
    assert breaker.state is CircuitState.OPEN


def test_start_uses_the_shared_assembly_rather_than_its_own_dict() -> None:
    """The join, not the unit.

    Everything above drives `adapter_connect_config` directly. All of it would
    still pass if `start()` went back to building its own `connect_cfg` literal,
    which is precisely how the defect existed in the first place. This asserts
    the call site, so the unit and its caller cannot drift apart.
    """
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path("ori/runtime.py").read_text())
    calls, literals = 0, 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(
            isinstance(t, ast.Name) and t.id == "connect_cfg" for t in node.targets
        ):
            continue
        if isinstance(node.value, ast.Dict):
            literals += 1
        elif (
            isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "adapter_connect_config"
        ):
            calls += 1

    assert calls == 1, (
        "start() must build the adapter config through the shared assembly"
    )
    assert literals == 0, "no dict literal may rebuild connect_cfg alongside it"
