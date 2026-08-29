# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The commissioned actuation seam: outcome → coil state → level, never assumed."""

from __future__ import annotations

import pytest

from ori.actions.commissioned_actuator import CommissionedActuator
from ori.security.commissioning.binding import AcceptedZone


class _Driver:
    """Records coil commands; the seam must never touch a level directly."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[str] = []
        self.energised = False
        self._fail = fail

    async def trigger(self, duration_seconds: float | None = None) -> bool:
        self.calls.append("trigger")
        if self._fail:
            return False
        self.energised = True
        return True

    async def release(self) -> bool:
        self.calls.append("release")
        if self._fail:
            return False
        self.energised = False
        return True

    @property
    def is_active(self) -> bool:
        return self.energised


def _zone(*, active_high: bool, open_outcome: str) -> AcceptedZone:
    close_outcome = "energised" if open_outcome == "de_energised" else "de_energised"
    return AcceptedZone(
        zone_id="bench",
        sensor_id="clamp",
        quantity="current",
        unit="ampere",
        direction="positive_is_load_draw",
        range_min=0.0,
        range_max=100.0,
        noise_floor=0.05,
        calibration_ref="bench",
        rated_capacity_parameter="rated_capacity_amps",
        rated_capacity_value=10.0,
        kind="local_gpio",
        identity={"gpio_pin": 26, "active_high": active_high},
        mapping={
            "open_protected_circuit": open_outcome,
            "close_protected_circuit": close_outcome,
            "de_energised_terminal_state": "open"
            if open_outcome == "de_energised"
            else "closed",
        },
        proof_method="actuate_and_observe",
        proof_performed_at_ms=1,
    )


@pytest.mark.parametrize(
    "open_outcome, expected_calls",
    [("de_energised", ["release", "trigger"]), ("energised", ["trigger", "release"])],
)
async def test_outcomes_resolve_through_the_mapping_not_a_convention(
    open_outcome: str, expected_calls: list[str]
) -> None:
    """Two zones with opposite mappings drive opposite coil operations for
    the same outcome; a seam that assumed 'trip energises' fails one of them."""
    driver = _Driver()
    actuator = CommissionedActuator(
        driver=driver,
        zone=_zone(active_high=True, open_outcome=open_outcome),
        binding_seq=3,
    )
    assert await actuator.command("open_protected_circuit")
    assert await actuator.command("close_protected_circuit")
    assert driver.calls == expected_calls
    assert actuator.last is not None
    assert actuator.last.binding_seq == 3


@pytest.mark.parametrize(
    "active_high, coil_state, level",
    [
        (True, "energised", "high"),
        (True, "de_energised", "low"),
        (False, "energised", "low"),
        (False, "de_energised", "high"),
    ],
)
def test_the_level_follows_the_commissioned_polarity(
    active_high: bool, coil_state: str, level: str
) -> None:
    actuator = CommissionedActuator(
        driver=_Driver(),
        zone=_zone(active_high=active_high, open_outcome="de_energised"),
        binding_seq=1,
    )
    assert actuator.level_for(coil_state) == level


async def test_startup_commands_de_energised_explicitly() -> None:
    """The coil is commanded, not assumed: a release is issued whatever the
    platform default level would have been."""
    driver = _Driver()
    driver.energised = True  # whatever the platform left the pin at
    actuator = CommissionedActuator(
        driver=driver,
        zone=_zone(active_high=False, open_outcome="de_energised"),
        binding_seq=1,
    )
    assert await actuator.command_coil("de_energised", reason="startup")
    assert driver.calls == ["release"]
    assert not actuator.coil_energised
    health = actuator.health()
    assert health["coil"] == "de_energised"
    assert health["last_command"] == {
        "outcome": "startup",
        "coil_state": "de_energised",
        "level": "high",
        "executed": True,
    }


async def test_a_driver_failure_is_reported_not_hidden() -> None:
    driver = _Driver(fail=True)
    actuator = CommissionedActuator(
        driver=driver,
        zone=_zone(active_high=True, open_outcome="energised"),
        binding_seq=1,
    )
    assert not await actuator.command("open_protected_circuit")
    assert actuator.last is not None and actuator.last.executed is False


def test_only_protected_circuit_outcomes_and_coil_states_are_accepted() -> None:
    actuator = CommissionedActuator(
        driver=_Driver(),
        zone=_zone(active_high=True, open_outcome="energised"),
        binding_seq=1,
    )
    with pytest.raises(ValueError):
        actuator.coil_state_for("trip_relay")
    zone = _zone(active_high=True, open_outcome="energised")
    firmware = AcceptedZone(
        **{
            **zone.__dict__,
            "kind": "firmware_channel",
            "identity": {"firmware_device_id": "fw", "channel": "relay0"},
        }
    )
    with pytest.raises(ValueError):
        CommissionedActuator(driver=_Driver(), zone=firmware, binding_seq=1)


async def test_an_unknown_coil_state_is_refused() -> None:
    actuator = CommissionedActuator(
        driver=_Driver(),
        zone=_zone(active_high=True, open_outcome="energised"),
        binding_seq=1,
    )
    with pytest.raises(ValueError):
        await actuator.command_coil("half", reason="test")
