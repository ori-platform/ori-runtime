# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The release-shipped safety profile set, loaded under its closed grammar.

safety-profile/v1 ships `profiles.json` inside the release and says a set that
fails to load is a broken release: refuse in every posture. This module holds
that grammar. Activation, evaluation and trip state belong to the safety
registry (#324); what the binding verifier needs from the set today is the
capacity multiplier that bounds a zone's trip point.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROFILE_ID = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\.v[1-9][0-9]*$")
PROFILE_KEYS = frozenset({"v", "id", "status", "observes", "condition", "outcome"})
OBSERVES_KEYS = frozenset({"quantity", "unit"})
CONDITION_KEYS: dict[str, frozenset[str]] = {
    "upper_capacity_multiplier": frozenset(
        {"kind", "capacity_parameter", "multiplier"}
    ),
    "upper_bound": frozenset({"kind", "threshold"}),
}
STATUSES = frozenset({"ratified", "candidate"})
OUTCOMES = frozenset({"open_protected_circuit"})
SHIPPED_PATH = Path(__file__).with_name("profiles.json")


class ProfileSetError(ValueError):
    """`malformed_profile`: the set cannot state its own conditions."""


@dataclass(frozen=True)
class Profile:
    id: str
    status: str
    quantity: str
    unit: str
    kind: str
    capacity_parameter: str | None
    multiplier: float | None
    threshold: float | None
    outcome: str


@dataclass(frozen=True)
class ProfileSet:
    profiles: tuple[Profile, ...]
    digest: str

    def capacity_multiplier(
        self, *, quantity: str, unit: str, capacity_parameter: str
    ) -> float | None:
        """The largest capacity multiplier a matching profile applies, if any."""
        matches = [
            p.multiplier
            for p in self.profiles
            if p.kind == "upper_capacity_multiplier"
            and p.quantity == quantity
            and p.unit == unit
            and p.capacity_parameter == capacity_parameter
            and p.multiplier is not None
        ]
        return max(matches) if matches else None


def _bad(condition: bool, detail: str) -> None:
    if condition:
        raise ProfileSetError(f"malformed_profile: {detail}")


def _text(value: Any, name: str) -> str:
    _bad(
        not isinstance(value, str) or not value.strip(),
        f"{name} must be non-empty text",
    )
    return str(value)


def _agreement_zone_number(value: Any, name: str) -> float:
    _bad(
        isinstance(value, bool) or not isinstance(value, (int, float)),
        f"{name} must be a number",
    )
    if isinstance(value, int):
        _bad(abs(value) > 9007199254740991, f"{name} is outside the agreement zone")
        return float(value)
    _bad(not math.isfinite(value), f"{name} must be finite")
    _bad(
        value != 0.0 and not (1e-4 <= abs(value) < 1e16),
        f"{name} is outside the agreement zone",
    )
    return float(value)


def _parse_profile(raw: Any) -> Profile:
    _bad(
        not isinstance(raw, dict) or set(raw) != PROFILE_KEYS,
        "profile keys are not exactly the declared set",
    )
    _bad(
        isinstance(raw["v"], bool) or raw["v"] != 1 or not isinstance(raw["v"], int),
        "v must be the integer 1",
    )
    profile_id = _text(raw["id"], "id")
    _bad(
        not PROFILE_ID.match(profile_id),
        f"id {profile_id!r} is not a versioned profile id",
    )
    status = raw["status"]
    _bad(
        not isinstance(status, str) or status not in STATUSES,
        "status must be ratified or candidate",
    )
    observes = raw["observes"]
    _bad(
        not isinstance(observes, dict) or set(observes) != OBSERVES_KEYS,
        "observes keys are not exactly quantity and unit",
    )
    quantity = _text(observes["quantity"], "observes.quantity")
    unit = _text(observes["unit"], "observes.unit")
    condition = raw["condition"]
    _bad(
        not isinstance(condition, dict) or "kind" not in condition,
        "condition must name a kind",
    )
    kind = condition["kind"]
    _bad(
        not isinstance(kind, str) or kind not in CONDITION_KEYS,
        "condition.kind is outside the closed vocabulary",
    )
    _bad(
        set(condition) != CONDITION_KEYS[kind],
        f"condition keys are not exactly those of {kind}",
    )
    capacity_parameter: str | None = None
    multiplier: float | None = None
    threshold: float | None = None
    if kind == "upper_capacity_multiplier":
        capacity_parameter = _text(
            condition["capacity_parameter"], "condition.capacity_parameter"
        )
        multiplier = _agreement_zone_number(
            condition["multiplier"], "condition.multiplier"
        )
        _bad(
            not 1.0 < multiplier <= 100.0,
            "condition.multiplier must exceed 1.0 and be at most 100.0",
        )
    else:
        threshold = _agreement_zone_number(
            condition["threshold"], "condition.threshold"
        )
    outcome = raw["outcome"]
    _bad(
        not isinstance(outcome, str) or outcome not in OUTCOMES,
        "outcome is outside the closed vocabulary",
    )
    return Profile(
        id=profile_id,
        status=status,
        quantity=quantity,
        unit=unit,
        kind=kind,
        capacity_parameter=capacity_parameter,
        multiplier=multiplier,
        threshold=threshold,
        outcome=outcome,
    )


def load_profile_set(raw_profiles: Any, *, digest: str = "") -> ProfileSet:
    """Load a profile list under the closed grammar; refuse the whole set on any fault."""
    _bad(
        not isinstance(raw_profiles, list) or not raw_profiles,
        "the profile set must be a non-empty list",
    )
    profiles = tuple(_parse_profile(raw) for raw in raw_profiles)
    ids = [p.id for p in profiles]
    _bad(len(set(ids)) != len(ids), "profile ids must be unique within the set")
    return ProfileSet(profiles=profiles, digest=digest)


def load_shipped_profile_set(path: Path = SHIPPED_PATH) -> ProfileSet:
    """The set the release ships, byte-for-byte, with its digest."""
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ProfileSetError(
            f"malformed_profile: the shipped set is unreadable ({exc})"
        ) from exc
    try:
        document = json.loads(payload)
    except ValueError as exc:
        raise ProfileSetError("malformed_profile: the shipped set is not JSON") from exc
    _bad(
        not isinstance(document, dict) or "profiles" not in document,
        "the shipped set carries no profiles",
    )
    return load_profile_set(
        document["profiles"], digest=hashlib.sha256(payload).hexdigest()
    )
