# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The commissioned binding and the Tier C authority facts and record health it gives."""

import logging
from pathlib import Path
from typing import Any

from ori.config import Config, ConfigValidationError, requires_production_posture
from ori.reasoning.dispatch_plan import (
    CLOSE_PROTECTED_CIRCUIT,
    OPEN_PROTECTED_CIRCUIT,
    BindingView,
)
from ori.reasoning.tier_c_admission import TierCAuthorityFacts
from ori.runtime._constants import RECORD_STALL_MS
from ori.runtime._core import RuntimeCore
from ori.runtime._firmware_wiring import provisioning_anchor_bytes
from ori.security.commissioning.anchors import CommissioningAnchors
from ori.security.commissioning.loader import (
    DeclaredInventory,
    load_commissioning_state,
)
from ori.security.commissioning.profiles import (
    ProfileSetError,
    load_shipped_profile_set,
)

logger = logging.getLogger("ori.runtime")


class Commissioning(RuntimeCore):
    """Loading the commissioned binding, and the Tier C facts and record health drawn from it."""

    def _binding_seq_in_force(self) -> int | None:
        state = self._commissioning_state
        if state is None or state.in_force is None:
            return None
        return state.in_force.binding_seq

    def _tier_c_authority_facts(
        self, zone_id: str | None = None
    ) -> TierCAuthorityFacts | None:
        """What a governed Tier C proposal binds, from the commissioned facts.

        None until a zone is accepted and its actuator connected: a physical
        Tier C proposal is refused rather than bound to nothing. With
        *zone_id*, None unless it names the commissioned zone.
        """
        actuator = getattr(self, "_commissioned_actuator", None)
        state = self._commissioning_state
        if actuator is None or state is None or state.in_force is None:
            return None
        zone = actuator.zone
        if zone_id is not None and zone_id != zone.zone_id:
            return None
        registry = getattr(self, "_safety_registry", None)
        profile_digest = ""
        if registry is not None and zone.zone_id in registry.zones_with_active_pairs:
            digest = str(getattr(self, "_shipped_profile_digest", "") or "")
            profile_digest = f"sha256:{digest}" if digest else ""
        resource = f"relay-gpio-{zone.identity.get('gpio_pin', '')}"
        return TierCAuthorityFacts(
            zone_id=zone.zone_id,
            zone_document={
                "zone_id": zone.zone_id,
                "kind": zone.kind,
                "identity": dict(zone.identity),
                "mapping": dict(zone.mapping),
                "sensor": zone.sensor,
            },
            binding_digest=str(state.in_force.canonical_hash),
            safety_profile_digest=profile_digest,
            resource_for={
                OPEN_PROTECTED_CIRCUIT: resource,
                CLOSE_PROTECTED_CIRCUIT: resource,
            },
            deployment_inputs=dict(
                getattr(self, "_tier_c_deployment_inputs", {}) or {}
            ),
        )

    def _records_lost_or_stalled(self) -> bool:
        """Whether an action record was lost, or has waited past the stall bound."""
        dispatcher = self._dispatcher
        if dispatcher is None or not hasattr(dispatcher, "record_backlog"):
            return False
        backlog = dispatcher.record_backlog()
        return bool(
            backlog.get("lost")
            or backlog.get("oldest_pending_age_ms", 0) > RECORD_STALL_MS
        )

    def _decision_records_lost(self) -> int:
        dispatcher = self._dispatcher
        if dispatcher is None or not hasattr(dispatcher, "decision_records_lost"):
            return 0
        return int(dispatcher.decision_records_lost())

    def _commissioning_health(self) -> dict[str, Any]:
        state = self._commissioning_state
        if state is None:
            health: dict[str, Any] = {
                "binding_seq": 0,
                "binding_hash": None,
                "anchors_configured": False,
                "zones": [],
                "last_verdict": None,
                "actuation_licensed": False,
            }
        else:
            health = state.health()
        actuator = self._commissioned_actuator
        health["actuator"] = actuator.health() if actuator is not None else None
        return health

    async def _load_commissioning(
        self, config: Config, anchors: CommissioningAnchors
    ) -> None:
        """Load the binding in force and decide what startup may claim.

        The profile set ships with the release and is refused in every posture
        when it cannot load. Declared actuating hardware with no accepted
        binding refuses a hardened start and degrades a development one; it
        never licenses actuation through the commissioned seam either way.
        """
        assert self._state_store is not None
        try:
            profiles = load_shipped_profile_set()
        except ProfileSetError as exc:
            logger.error("[commissioning] %s — aborting", exc)
            raise ConfigValidationError(str(exc)) from exc
        hardened = requires_production_posture(
            device=config.device, security=config.security
        )
        relay_pin = config.actions.relay.get("gpio_pin")
        inventory = DeclaredInventory.from_config(
            [str(sensor.id) for sensor in config.sensors],
            int(relay_pin) if relay_pin is not None else None,
        )
        state = await load_commissioning_state(
            data_path=Path(self._config_path).resolve().parent,
            device_id=str(config.device.id),
            anchors=anchors,
            provisioning_anchor=provisioning_anchor_bytes(config),
            inventory=inventory,
            posture="production" if hardened else "development",
            profiles=profiles,
            store=self._state_store,
        )
        self._commissioning_state = state
        if inventory.actuators and not state.actuation_licensed:
            if state.provisional is not None:
                detail = (
                    f"binding {state.provisional.binding_seq} is provisional: "
                    "a proof leg is unproven"
                )
            elif state.last_verdict is not None:
                detail = (
                    f"binding verdict {state.last_verdict.stage}:"
                    f"{state.last_verdict.reason}"
                )
            else:
                detail = "no binding presented"
            if hardened:
                logger.error(
                    "[commissioning] declared actuating hardware has no binding in "
                    "force (%s) — aborting under hardened posture",
                    detail,
                )
                raise ConfigValidationError(
                    "commissioning: declared actuating hardware has no binding in "
                    f"force ({detail}); a hardened runtime does not start "
                    "unprotected, and commissioning precedes hardening"
                )
            if "binding_missing" not in state.problems:
                state.problems.append("binding_missing")
            logger.warning(
                "[commissioning] declared actuating hardware has no binding in force "
                "(%s); starting degraded with no protection claim, no actuation "
                "through the commissioned seam, and no coil command",
                detail,
            )
        elif state.in_force is not None:
            logger.info(
                "[commissioning] binding %d in force: %d zone(s), actuation %s",
                state.in_force.binding_seq,
                len(state.in_force.zones),
                "licensed" if state.actuation_licensed else "withheld",
            )

    def _binding_view(self) -> BindingView | None:
        """What the commissioned binding establishes about driving this device.

        The binding records which coil state each outcome corresponds to; it
        records no reversibility field, so the runtime takes the conservative
        consequence class for a protected-circuit outcome rather than inferring
        one. The shape admits a per-zone value when the contract carries one.
        """
        actuator = getattr(self, "_commissioned_actuator", None)
        if actuator is None:
            return None
        zone = actuator.zone
        return BindingView(
            zone_identity_key=zone.identity_key,
            binding_revision=str(actuator.binding_seq),
            consequence_by_outcome={
                OPEN_PROTECTED_CIRCUIT: "hard",
                CLOSE_PROTECTED_CIRCUIT: "hard",
            },
        )
