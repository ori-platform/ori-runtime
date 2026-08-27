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

from typing import Any

import pytest

from ori.config import (
    RESERVED_SENSOR_METADATA_KEYS,
    ConfigValidationError,
    _parse_sensors,
)


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


def _assemble(metadata: dict[str, Any]) -> dict[str, Any]:
    """Reproduce runtime.py's connect_cfg assembly for a sensor.

    Built from the real source rather than restated, so a change to the
    ordering in runtime.py fails here instead of passing against a copy that
    drifted.
    """
    import ast
    import pathlib

    source = pathlib.Path("ori/runtime.py").read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "connect_cfg" for t in node.targets
            )
            and isinstance(node.value, ast.Dict)
        ):
            keys: list[str | None] = [
                k.value
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
                else None
                for k in node.value.keys
            ]
            # None marks the ** spread of metadata.
            spread_at = keys.index(None)
            injected_after = [k for k in keys[spread_at + 1 :] if k is not None]
            result: dict[str, Any] = dict(metadata)
            for name in injected_after:
                result[name] = f"<runtime:{name}>"
            return result
    raise AssertionError("connect_cfg assignment not found in ori/runtime.py")


@pytest.mark.parametrize("key", ["sensor_id", "sensor_type", "circuit_breaker"])
def test_metadata_cannot_displace_a_runtime_supplied_key(key: str) -> None:
    """The spread comes first; the runtime's values are applied over it."""
    assembled = _assemble({key: "spoofed"})
    assert assembled[key] == f"<runtime:{key}>"


def test_metadata_that_names_nothing_reserved_survives_assembly() -> None:
    assembled = _assemble({"port": "/dev/ttyUSB0"})
    assert assembled["port"] == "/dev/ttyUSB0"


def test_every_reserved_key_is_actually_injected_by_the_runtime() -> None:
    """The reserved set and the runtime's injection must not drift apart.

    A name reserved at load but no longer injected would refuse a key for a
    reason that stopped being true; one injected but not reserved is #416 again.
    """
    injected = set(_assemble({}))
    assert RESERVED_SENSOR_METADATA_KEYS <= injected
