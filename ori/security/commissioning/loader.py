# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Load the commissioned binding a device holds, and report what it holds.

The binding arrives as a signed envelope at `commissioning/binding.json` under
the data directory, verified against the anchors the installer delivered and
the inventory the configuration declares, and retained whole in the state
store. A document that fails any stage leaves the accepted binding in force;
the verdict is reported by stage and reason, never as a generic failure.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ori.security.commissioning.anchors import CommissioningAnchors
from ori.security.commissioning.binding import (
    AcceptedBinding,
    AcceptedZone,
    BindingRefusedError,
    Posture,
    VerifierContext,
    ZoneState,
    actuator_identity,
    canonical_bytes,
    parse_document,
    verify_binding_envelope,
)
from ori.security.commissioning.profiles import ProfileSet
from ori.utils.time_utils import now_ms

logger = logging.getLogger(__name__)

BINDING_RELATIVE_PATH = Path("commissioning") / "binding.json"


class BindingStore(Protocol):
    async def retain_commissioned_binding(
        self,
        *,
        binding_seq: int,
        canonical_hash: str,
        device_id: str,
        inventory_generation: int,
        signer_id: str,
        supersedes: str | None,
        canonical_json: str,
        signature: str,
        zones_json: str,
        accepted_at_ms: int | None = None,
    ) -> None:
        """Retain an accepted binding and retire the one in force."""

    async def get_commissioned_binding_in_force(self) -> dict | None:
        """The retained row with no retired_at_ms, or None."""


@dataclass(frozen=True)
class DeclaredInventory:
    """What the provisioning document says exists: sensors by id, actuators by identity."""

    sensor_ids: frozenset[str]
    actuators: tuple[tuple[str, str], ...]

    @classmethod
    def from_config(
        cls, sensor_ids: list[str], relay_gpio_pin: int | None
    ) -> DeclaredInventory:
        actuators: list[tuple[str, str]] = []
        if relay_gpio_pin is not None:
            actuators.append(
                actuator_identity("local_gpio", {"gpio_pin": int(relay_gpio_pin)})
            )
        return cls(sensor_ids=frozenset(sensor_ids), actuators=tuple(actuators))


@dataclass(frozen=True)
class Verdict:
    stage: str
    reason: str
    binding_seq: int | None
    at_ms: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CommissioningState:
    """The binding in force and how the last presented document fared."""

    anchors: CommissioningAnchors
    inventory: DeclaredInventory
    in_force: AcceptedBinding | None = None
    last_verdict: Verdict | None = None
    problems: list[str] = field(default_factory=list)

    @property
    def actuation_licensed(self) -> bool:
        """Every declared actuator is bound by the binding in force."""
        if self.in_force is None:
            return not self.inventory.actuators
        bound = {zone.identity_key for zone in self.in_force.zones}
        return set(self.inventory.actuators) <= bound

    def zone_for_local_gpio(self, gpio_pin: int) -> AcceptedZone | None:
        if self.in_force is None:
            return None
        return self.in_force.zone_for_actuator(
            "local_gpio", {"gpio_pin": int(gpio_pin)}
        )

    def health(self) -> dict[str, Any]:
        binding = self.in_force
        return {
            "binding_seq": binding.binding_seq if binding else 0,
            "binding_hash": binding.canonical_hash if binding else None,
            "anchors_configured": self.anchors.configured,
            "zones": [
                {
                    "zone_id": zone.zone_id,
                    "sensor_id": zone.sensor_id,
                    "actuator": {"kind": zone.kind, "identity": dict(zone.identity)},
                    "commissioned_mapping": dict(zone.mapping),
                    "proof_method": zone.proof_method,
                    "proof_performed_at_ms": zone.proof_performed_at_ms,
                }
                for zone in (binding.zones if binding else ())
            ],
            "last_verdict": self.last_verdict.as_dict() if self.last_verdict else None,
            "actuation_licensed": self.actuation_licensed,
        }


def accepted_from_row(row: dict[str, Any]) -> AcceptedBinding:
    zones = tuple(AcceptedZone(**zone) for zone in json.loads(row["zones_json"]))
    return AcceptedBinding(
        binding_seq=int(row["binding_seq"]),
        canonical_hash=str(row["canonical_hash"]),
        inventory_generation=int(row["inventory_generation"]),
        device_id=str(row["device_id"]),
        signer_id=str(row["signer_id"]),
        issued_at_ms=0,
        supersedes=row["supersedes"],
        zones=zones,
        canonical_bytes=str(row["canonical_json"]).encode("utf-8"),
        signature=str(row["signature"]),
    )


def _zones_json(binding: AcceptedBinding) -> str:
    return json.dumps([asdict(zone) for zone in binding.zones], sort_keys=True)


def verifier_context(
    *,
    device_id: str,
    anchors: CommissioningAnchors,
    provisioning_anchor: bytes | None,
    in_force: AcceptedBinding | None,
    inventory: DeclaredInventory,
    posture: Posture,
    profiles: ProfileSet,
    document: Any,
) -> VerifierContext:
    multiplier: float | None = None
    # The bound consults the profile set for the zone's quantity; the widest
    # applicable multiplier is the binding one, since it produces the highest
    # trip point the sensor would have to observe.
    zones = (
        document.get("binding", {}).get("zones") if isinstance(document, dict) else None
    )
    if isinstance(zones, list):
        for zone in zones:
            if not isinstance(zone, dict):
                continue
            raw_sensor = zone.get("sensor")
            raw_capacity = zone.get("rated_capacity")
            sensor: dict[str, Any] = raw_sensor if isinstance(raw_sensor, dict) else {}
            capacity: dict[str, Any] = (
                raw_capacity if isinstance(raw_capacity, dict) else {}
            )
            found = profiles.capacity_multiplier(
                quantity=str(sensor.get("quantity", "")),
                unit=str(sensor.get("unit", "")),
                capacity_parameter=str(capacity.get("parameter", "")),
            )
            if found is not None and (multiplier is None or found > multiplier):
                multiplier = found
    return VerifierContext(
        device_id=device_id,
        commissioning_anchor_current=anchors.current,
        commissioning_anchor_previous=anchors.previous,
        provisioning_anchor=provisioning_anchor,
        accepted_binding_seq=in_force.binding_seq if in_force else 0,
        accepted_binding_hash=in_force.canonical_hash if in_force else None,
        declared_sensor_ids=inventory.sensor_ids,
        declared_actuators=inventory.actuators,
        deployment_posture=posture,
        profile_multiplier=multiplier,
        accepted_zone_state={
            zone.zone_id: ZoneState(
                identity=dict(zone.identity),
                mapping=dict(zone.mapping),
                calibration_ref=zone.calibration_ref,
                proof_at_ms=zone.proof_performed_at_ms,
            )
            for zone in (in_force.zones if in_force else ())
        },
    )


async def load_commissioning_state(
    *,
    data_path: Path,
    device_id: str,
    anchors: CommissioningAnchors,
    provisioning_anchor: bytes | None,
    inventory: DeclaredInventory,
    posture: Posture,
    profiles: ProfileSet,
    store: BindingStore,
) -> CommissioningState:
    """Reload the binding in force, then present the file beside the config if any."""
    state = CommissioningState(anchors=anchors, inventory=inventory)
    row = await store.get_commissioned_binding_in_force()
    if row is not None:
        state.in_force = accepted_from_row(row)
        if state.in_force.device_id != device_id:
            state.problems.append("retained_binding_for_another_device")
            state.in_force = None

    path = data_path / BINDING_RELATIVE_PATH
    if not path.is_file():
        if inventory.actuators and state.in_force is None:
            state.problems.append("binding_missing")
        return state

    try:
        document = parse_document(path.read_text(encoding="utf-8"))
    except (OSError, BindingRefusedError):
        state.last_verdict = Verdict("parses", "malformed", None, now_ms())
        logger.warning(
            "[commissioning] %s is not a readable document; binding in force unchanged",
            path,
        )
        return state

    presented_seq = _presented_seq(document)
    if state.in_force is not None and is_the_binding_in_force(document, state.in_force):
        # The file is the document already in force, byte for byte; there is
        # nothing to re-decide and nothing to retain twice.
        state.last_verdict = Verdict("accepted", "accepted", presented_seq, now_ms())
        return state

    context = verifier_context(
        device_id=device_id,
        anchors=anchors,
        provisioning_anchor=provisioning_anchor,
        in_force=state.in_force,
        inventory=inventory,
        posture=posture,
        profiles=profiles,
        document=document,
    )
    try:
        accepted = verify_binding_envelope(document, context)
    except BindingRefusedError as refusal:
        state.last_verdict = Verdict(
            refusal.stage, refusal.reason, presented_seq, now_ms()
        )
        logger.warning(
            "[commissioning] binding at %s refused at %s: %s; binding in force unchanged",
            path,
            refusal.stage,
            refusal.reason,
        )
        return state
    except Exception:  # noqa: BLE001 - a verifier defect must not stop the runtime
        # The contract's rule for input that breaks the verifier rather than a
        # check is a malformed verdict, and its rule for a document failing any
        # stage is that the binding in force is unchanged. Letting the error
        # propagate would abort startup, Tier D protection included, over a
        # file that should have been refused. The problem marker keeps the
        # distinction visible: this was not a grammar refusal.
        state.last_verdict = Verdict("parses", "malformed", presented_seq, now_ms())
        if "binding_verifier_error" not in state.problems:
            state.problems.append("binding_verifier_error")
        logger.exception(
            "[commissioning] binding at %s could not be verified; binding in force "
            "unchanged",
            path,
        )
        return state

    await store.retain_commissioned_binding(
        binding_seq=accepted.binding_seq,
        canonical_hash=accepted.canonical_hash,
        device_id=accepted.device_id,
        inventory_generation=accepted.inventory_generation,
        signer_id=accepted.signer_id,
        supersedes=accepted.supersedes,
        canonical_json=accepted.canonical_bytes.decode("utf-8"),
        signature=accepted.signature,
        zones_json=_zones_json(accepted),
    )
    state.in_force = accepted
    state.last_verdict = Verdict("accepted", "accepted", accepted.binding_seq, now_ms())
    state.problems = [p for p in state.problems if p != "binding_missing"]
    logger.info(
        "[commissioning] binding %d accepted (%s) with %d zone(s)",
        accepted.binding_seq,
        accepted.canonical_hash,
        len(accepted.zones),
    )
    return state


def is_the_binding_in_force(document: Any, in_force: AcceptedBinding) -> bool:
    """Same signed bytes and same signature as the retained document."""
    if not isinstance(document, dict) or set(document) != {"binding", "signature"}:
        return False
    if document.get("signature") != in_force.signature:
        return False
    try:
        return canonical_bytes(document["binding"]) == in_force.canonical_bytes
    except BindingRefusedError:
        return False


def _presented_seq(document: Any) -> int | None:
    try:
        seq = document["binding"]["binding_seq"]
    except (TypeError, KeyError, IndexError):
        return None
    return seq if isinstance(seq, int) and not isinstance(seq, bool) else None
