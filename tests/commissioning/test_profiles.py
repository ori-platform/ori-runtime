# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The shipped safety profile set and its closed grammar, against the corpus."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ori.security.commissioning.profiles import (
    SHIPPED_PATH,
    ProfileSetError,
    load_profile_set,
    load_shipped_profile_set,
)

VECTOR_DIR = Path(__file__).parent.parent / "vectors" / "safety_profile"
PROFILES_VECTOR = VECTOR_DIR / "profiles.json"
LOAD_CASES = json.loads((VECTOR_DIR / "profile-load.json").read_text())["cases"]


def test_the_shipped_profile_set_is_the_vendored_one() -> None:
    """Byte-for-byte, and pinned: the release ships the contract's file."""
    manifest = json.loads((VECTOR_DIR / "MANIFEST.json").read_text())
    pinned = manifest["files"]["profiles.json"]
    assert hashlib.sha256(PROFILES_VECTOR.read_bytes()).hexdigest() == pinned
    assert SHIPPED_PATH.read_bytes() == PROFILES_VECTOR.read_bytes()
    loaded = load_shipped_profile_set()
    assert loaded.digest == pinned
    assert [p.id for p in loaded.profiles] == [
        "electrical.overcurrent.v1",
        "electrical.overvoltage.v1",
        "gas.concentration.v1",
    ]


@pytest.mark.parametrize("case", LOAD_CASES, ids=lambda c: c["name"])
def test_profile_load_cases_agree_with_the_contract(case: dict) -> None:
    if case["expect"] == "loaded":
        loaded = load_profile_set(case["profiles"])
        assert len(loaded.profiles) == len(case["profiles"])
    else:
        assert case["expect"] == "malformed_profile"
        with pytest.raises(ProfileSetError):
            load_profile_set(case["profiles"])


def test_every_load_outcome_is_exercised() -> None:
    assert {c["expect"] for c in LOAD_CASES} == {"loaded", "malformed_profile"}


def test_the_capacity_multiplier_is_looked_up_by_quantity_unit_and_parameter() -> None:
    loaded = load_shipped_profile_set()
    assert (
        loaded.capacity_multiplier(
            quantity="current", unit="ampere", capacity_parameter="rated_capacity_amps"
        )
        == 2.0
    )
    # A fixed-threshold profile bounds nothing here; that is activation's check.
    assert (
        loaded.capacity_multiplier(
            quantity="voltage", unit="volt", capacity_parameter="rated_capacity_amps"
        )
        is None
    )
    # Same quantity, wrong unit or parameter: no match, never the nearest one.
    assert (
        loaded.capacity_multiplier(
            quantity="current",
            unit="milliampere",
            capacity_parameter="rated_capacity_amps",
        )
        is None
    )
    assert (
        loaded.capacity_multiplier(
            quantity="current", unit="ampere", capacity_parameter="rated_capacity_kw"
        )
        is None
    )


def test_a_broken_shipped_set_is_refused_not_tolerated(tmp_path: Path) -> None:
    broken = tmp_path / "profiles.json"
    broken.write_text('{"profiles": []}')
    with pytest.raises(ProfileSetError):
        load_shipped_profile_set(broken)
    broken.write_text("not json")
    with pytest.raises(ProfileSetError):
        load_shipped_profile_set(broken)
    with pytest.raises(ProfileSetError):
        load_shipped_profile_set(tmp_path / "absent.json")
