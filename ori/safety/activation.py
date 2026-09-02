# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Which release-shipped profiles protect which commissioned zones.

Activation is a pure decision over an accepted binding's zones and the loaded
profile set: every eligible zone-profile pair activates, is pending that
profile's ratification, or is refused — the consumer does not choose, and no
skill, configuration or policy is an input. Checks that repeat the binding
verifier's are recomputed here on purpose: a check that holds only because an
earlier check held is not a boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ori.security.commissioning.profiles import Profile, ProfileSet

POSITIVE_IS_LOAD_DRAW = "positive_is_load_draw"
UNDEMONSTRATED = "undemonstrated"

START = "start"
START_DEGRADED = "start_degraded"
REFUSE = "refuse"


@dataclass(frozen=True)
class ZoneFacts:
    """The commissioned facts activation consults, and nothing else."""

    zone_id: str
    sensor_id: str
    quantity: str
    unit: str
    direction: str
    range_min: float
    range_max: float
    rated_capacity_parameter: str
    rated_capacity_value: float
    proof_method: str

    @classmethod
    def from_accepted_zone(cls, zone: Any) -> "ZoneFacts":
        return cls(
            zone_id=zone.zone_id,
            sensor_id=zone.sensor_id,
            quantity=zone.quantity,
            unit=zone.unit,
            direction=zone.direction,
            range_min=zone.range_min,
            range_max=zone.range_max,
            rated_capacity_parameter=zone.rated_capacity_parameter,
            rated_capacity_value=zone.rated_capacity_value,
            proof_method=zone.proof_method,
        )


@dataclass(frozen=True)
class ActivatedProfile:
    zone_id: str
    sensor_id: str
    profile_id: str
    trip_point: float
    outcome: str


@dataclass(frozen=True)
class ActivationRefusal:
    zone_id: str
    profile_id: str
    reason: str


@dataclass(frozen=True)
class PendingProfile:
    zone_id: str
    profile_id: str


@dataclass(frozen=True)
class ActivationResult:
    activated: tuple[ActivatedProfile, ...]
    refused: tuple[ActivationRefusal, ...]
    pending: tuple[PendingProfile, ...]
    uncovered_zones: tuple[str, ...]

    def startup_verdict(self, *, hardened: bool) -> str:
        """Whether the consumer may start, per safety-profile/v1.

        A refused eligible zone refuses hardened startup outright; in
        development the consumer starts degraded with those zones' profiles
        inactive. Pending ratification and uncovered zones never block: the
        site has done nothing wrong.
        """
        if not self.refused:
            return START
        return REFUSE if hardened else START_DEGRADED


def trip_point(profile: Profile, zone: ZoneFacts) -> float:
    """The value the condition compares against, on this zone."""
    if profile.kind == "upper_capacity_multiplier":
        assert profile.multiplier is not None
        return profile.multiplier * zone.rated_capacity_value
    assert profile.threshold is not None
    return profile.threshold


def activate(profile_set: ProfileSet, zones: Iterable[ZoneFacts]) -> ActivationResult:
    """Run the contract's ordered activation checks for every eligible pair."""
    activated: list[ActivatedProfile] = []
    refused: list[ActivationRefusal] = []
    pending: list[PendingProfile] = []
    uncovered: list[str] = []

    for zone in zones:
        eligible = [p for p in profile_set.profiles if p.quantity == zone.quantity]
        if not eligible:
            uncovered.append(zone.zone_id)
            continue
        for profile in eligible:
            verdict = _check_pair(profile, zone)
            if verdict is None:
                activated.append(
                    ActivatedProfile(
                        zone_id=zone.zone_id,
                        sensor_id=zone.sensor_id,
                        profile_id=profile.id,
                        trip_point=trip_point(profile, zone),
                        outcome=profile.outcome,
                    )
                )
            elif verdict == "pending_ratification":
                pending.append(
                    PendingProfile(zone_id=zone.zone_id, profile_id=profile.id)
                )
            else:
                refused.append(
                    ActivationRefusal(
                        zone_id=zone.zone_id, profile_id=profile.id, reason=verdict
                    )
                )

    return ActivationResult(
        activated=tuple(activated),
        refused=tuple(refused),
        pending=tuple(pending),
        uncovered_zones=tuple(uncovered),
    )


def _check_pair(profile: Profile, zone: ZoneFacts) -> str | None:
    """The ordered checks for one eligible pair; None means it activates."""
    if profile.status != "ratified":
        return "pending_ratification"
    if zone.unit != profile.unit:
        return "unit_mismatch"
    if zone.direction != POSITIVE_IS_LOAD_DRAW:
        return "direction_unsupported"
    if (
        profile.kind == "upper_capacity_multiplier"
        and zone.rated_capacity_parameter != profile.capacity_parameter
    ):
        return "parameter_mismatch"
    point = trip_point(profile, zone)
    if not zone.range_min <= point <= zone.range_max:
        return "trip_point_unobservable"
    if zone.proof_method == UNDEMONSTRATED:
        return "undemonstrated_binding"
    return None
