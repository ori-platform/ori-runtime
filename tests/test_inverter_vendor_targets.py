# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import pytest

from ori.hal.inverter_vendor_targets import (
    VendorTargetStatus,
    list_vendor_targets,
    target_by_family,
)


def test_vendor_targets_cover_core_african_inverter_landscape() -> None:
    families = {target.family for target in list_vendor_targets()}

    assert {
        "growatt",
        "deye_family",
        "victron",
        "solis",
        "sofar",
        "goodwe",
        "huawei",
        "sungrow",
        "felicity",
        "axpert_voltronic",
        "closed_or_unknown",
    } <= families


def test_implemented_targets_point_to_real_profiles_or_adapter_paths() -> None:
    growatt = target_by_family("growatt")
    deye = target_by_family("deye_family")
    victron = target_by_family("victron")

    assert growatt.status == VendorTargetStatus.IMPLEMENTED_PROFILE
    assert growatt.bundled_profile == "growatt_spf"
    assert deye.status == VendorTargetStatus.IMPLEMENTED_PROFILE
    assert deye.bundled_profile == "deye_hybrid"
    assert victron.status == VendorTargetStatus.IMPLEMENTED_PROFILE
    assert victron.bundled_profile == ""
    assert victron.fallback == "venus_os_mqtt"


def test_candidate_targets_do_not_claim_live_profiles() -> None:
    candidate_families = {
        "solis",
        "sofar",
        "goodwe",
        "huawei",
        "sungrow",
        "felicity",
        "axpert_voltronic",
    }

    for family in candidate_families:
        target = target_by_family(family)
        assert target.status == VendorTargetStatus.VALIDATION_TARGET
        assert target.bundled_profile == ""
        assert target.evidence_required


def test_closed_or_unknown_target_uses_brand_blind_fallback() -> None:
    target = target_by_family("closed_or_unknown")

    assert target.status == VendorTargetStatus.FALLBACK_ONLY
    assert target.bundled_profile == ""
    assert target.fallback == "usb_pzem"
    assert "No inverter profile required" in target.evidence_required


def test_unknown_vendor_target_raises_clear_error() -> None:
    with pytest.raises(KeyError, match="unknown inverter vendor family"):
        target_by_family("not-a-real-family")
