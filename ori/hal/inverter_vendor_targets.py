# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Vendor-agnostic inverter telemetry target catalog.

This catalog is deliberately not a support matrix that overclaims live
capability. It gives provisioning, the phone/APK path, and reviewers one
runtime-owned list of inverter families Ori should handle, whether each family
has a bundled read profile today, and which fallback applies when local inverter
telemetry is not yet qualified.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


class VendorTargetStatus:
    """Read-telemetry status values for inverter families."""

    IMPLEMENTED_PROFILE = "implemented_profile"
    VALIDATION_TARGET = "validation_target"
    FALLBACK_ONLY = "fallback_only"


@dataclass(frozen=True)
class VendorTelemetryTarget:
    """One inverter-family target for vendor-agnostic telemetry."""

    family: str
    brands: tuple[str, ...]
    likely_transports: tuple[str, ...]
    status: str
    bundled_profile: str = ""
    fallback: str = "usb_pzem"
    evidence_required: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_TARGETS: tuple[VendorTelemetryTarget, ...] = (
    VendorTelemetryTarget(
        family="growatt",
        brands=("Growatt",),
        likely_transports=("solarman_v5",),
        status=VendorTargetStatus.IMPLEMENTED_PROFILE,
        bundled_profile="growatt_spf",
        evidence_required=(
            "Exact model, firmware, logger serial, raw register dump, same-minute "
            "vendor display/app or PZEM/clamp comparison."
        ),
        notes="Bundled profile is community_derived; field qualification is still required.",
    ),
    VendorTelemetryTarget(
        family="deye_family",
        brands=("Deye", "Sunsynk", "Sol-Ark"),
        likely_transports=("solarman_v5",),
        status=VendorTargetStatus.IMPLEMENTED_PROFILE,
        bundled_profile="deye_hybrid",
        evidence_required=(
            "Exact brand/model/firmware/logger; import/export sign validation; "
            "LCD/app/PZEM evidence for every bundled metric."
        ),
        notes=(
            "Deye/Sunsynk/Sol-Ark remain family candidates until exact units are "
            "field-qualified."
        ),
    ),
    VendorTelemetryTarget(
        family="victron",
        brands=("Victron",),
        likely_transports=("venus_os_mqtt", "modbus_tcp"),
        status=VendorTargetStatus.IMPLEMENTED_PROFILE,
        bundled_profile="",
        fallback="venus_os_mqtt",
        evidence_required=(
            "Portal ID, local MQTT or Modbus reachability, same-minute vendor "
            "display/app comparison for PV/grid/load/battery metrics."
        ),
        notes=(
            "Victron local telemetry exists through the dedicated adapter path, "
            "not this Modbus profile registry."
        ),
    ),
    VendorTelemetryTarget(
        family="solis",
        brands=("Solis", "Ginlong"),
        likely_transports=("solarman_v5", "modbus_tcp"),
        status=VendorTargetStatus.VALIDATION_TARGET,
        evidence_required=(
            "Published/community register source plus raw frames covering PV, grid, "
            "load, battery SOC/voltage, and status for exact model/firmware."
        ),
        notes="Add a profile only after source licensing and decode vectors are reviewed.",
    ),
    VendorTelemetryTarget(
        family="sofar",
        brands=("Sofar",),
        likely_transports=("solarman_v5", "modbus_tcp", "modbus_serial"),
        status=VendorTargetStatus.VALIDATION_TARGET,
        evidence_required=(
            "Transport proof and signed grid-power validation across import/export."
        ),
    ),
    VendorTelemetryTarget(
        family="goodwe",
        brands=("GoodWe",),
        likely_transports=("modbus_tcp", "vendor_lan_api"),
        status=VendorTargetStatus.VALIDATION_TARGET,
        evidence_required=(
            "Local API or Modbus source, raw capture, and independent display/app "
            "comparison for exact model/firmware."
        ),
    ),
    VendorTelemetryTarget(
        family="huawei",
        brands=("Huawei",),
        likely_transports=("modbus_tcp", "modbus_serial"),
        status=VendorTargetStatus.VALIDATION_TARGET,
        evidence_required=(
            "SmartLogger/inverter Modbus map source, site-local reachability, and "
            "same-minute vendor display/app evidence."
        ),
    ),
    VendorTelemetryTarget(
        family="sungrow",
        brands=("Sungrow",),
        likely_transports=("modbus_tcp", "modbus_serial"),
        status=VendorTargetStatus.VALIDATION_TARGET,
        evidence_required=(
            "Published/community register source plus raw capture for exact "
            "model/firmware/logger."
        ),
    ),
    VendorTelemetryTarget(
        family="felicity",
        brands=("Felicity", "Felicitysolar"),
        likely_transports=("modbus_serial", "rs232", "rs485"),
        status=VendorTargetStatus.VALIDATION_TARGET,
        evidence_required=(
            "USB/serial transport proof, battery/inverter register source, and "
            "PZEM/clamp comparison for grid/load power where possible."
        ),
        notes="Expected to use serial Modbus class rather than SolarmanV5.",
    ),
    VendorTelemetryTarget(
        family="axpert_voltronic",
        brands=("Axpert", "Voltronic", "MPP Solar", "Kodak"),
        likely_transports=("serial_text_protocol", "modbus_serial"),
        status=VendorTargetStatus.VALIDATION_TARGET,
        evidence_required=(
            "Exact protocol command set, serial capture, and independent display/app "
            "comparison for every metric."
        ),
        notes="Often not Solarman/Modbus; keep adapter work separate from profiles.",
    ),
    VendorTelemetryTarget(
        family="closed_or_unknown",
        brands=("Luminous", "Su-Kam", "Other closed/proprietary inverters"),
        likely_transports=("none",),
        status=VendorTargetStatus.FALLBACK_ONLY,
        fallback="usb_pzem",
        evidence_required=(
            "No inverter profile required; use Ori USB/PZEM or clamp telemetry as "
            "brand-blind operational measurement."
        ),
        notes="Fallback keeps Ori useful when the inverter exposes no trustworthy local API.",
    ),
)


def list_vendor_targets() -> list[VendorTelemetryTarget]:
    """Return all known inverter-family telemetry targets."""

    return list(_TARGETS)


def target_by_family(family: str) -> VendorTelemetryTarget:
    """Return a target by family name."""

    normalized = str(family or "").strip().lower()
    for target in _TARGETS:
        if target.family == normalized:
            return target
    available = ", ".join(target.family for target in _TARGETS)
    raise KeyError(f"unknown inverter vendor family {family!r}; available: {available}")


__all__ = [
    "VendorTargetStatus",
    "VendorTelemetryTarget",
    "list_vendor_targets",
    "target_by_family",
]
