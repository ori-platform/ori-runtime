# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime's health snapshot and the component reports it folds together."""

import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from ori.hal.base import silence_bound_ms
from ori.runtime._commissioning import Commissioning
from ori.runtime._health_status import degradation_reasons, fold_health_status
from ori.security.evidence.chain import SCHEMA_VERSION as EVIDENCE_SCHEMA_VERSION
from ori.security.evidence.registration import RegistrationOffer, RegistrationStatus
from ori.utils.bool_utils import is_truthy
from ori.utils.path_utils import path_is_relative_to
from ori.utils.time_utils import now_ms

logger = logging.getLogger("ori.runtime")


class HealthSnapshot(Commissioning):
    """Building the health snapshot from each component's report."""

    async def _evidence_health(self) -> dict[str, Any]:
        attestor = self._evidence_attestor
        enabled = bool(
            self._config is not None
            and getattr(self._config, "evidence", None) is not None
            and self._config.evidence.enabled
        )
        health: dict[str, Any] = {
            "enabled": enabled,
            "available": bool(attestor is not None and attestor.available),
            # This device's own anchor, which is its own property to report.
            "public_key_hex": attestor.public_key_hex if attestor else "",
            # `artifact_version` is deliberately absent: ori-specs
            # runtime-health/v2 removed it and v3 keeps it absent. The private component's version is
            # implementation metadata an operator has no part in, and
            # `available` with `protocol_version` already answer whether this
            # device can sign and against which public contract.
            #
            # It was briefly removed during the disclosure audit and restored,
            # because v1 still required it and a published contract is not a
            # runtime's to change unilaterally. v2 is what licenses this.
            "protocol_version": (
                EVIDENCE_SCHEMA_VERSION
                if attestor is not None and attestor.available
                else ""
            ),
            # Vocabulary the device will emit for new Tier C/D attestations.
            # Only meaningful while signing is available; '' otherwise, so a
            # mixed-fleet rollout can be confirmed per device before the
            # first Tier C/D action fires.
            "action_event_type": (
                attestor.action_event_type
                if attestor is not None and attestor.available
                else ""
            ),
            "chain_head_hash": None,
            "pending_export_count": None,
            # Held by a courier and not yet receipted by the authority: a
            # receipt refused or lost shows here and nowhere else on the
            # device. A diagnostic; it decides no severity.
            "awaiting_receipt_count": None,
            "oldest_awaiting_receipt_age_ms": None,
            # Whether inbound authority artifacts can currently arrive. A route
            # that is down stalls delivery without stalling anything else, so
            # nothing on the device would otherwise show it.
            "inbound_route_connected": (
                self._evidence_inbound_subscriber.connected
                if self._evidence_inbound_subscriber is not None
                else False
            ),
            "last_attested_action_id": None,
            "attestation_gap_count": 0,
            "status_counts": {},
            # Authority artifacts ingest refused, retained by the ledger so a
            # refused receipt is distinguishable from one that never arrived.
            "ingest_refusal_count": None,
            "last_ingest_refusal": None,
            # runtime-health/v4's application-storage fault signal, carried
            # into this v3 snapshot: the store failed deciding or applying a
            # verified inbound artifact, and none has been applied since. In
            # memory, so it reads while the store does not; false while
            # evidence is disabled or not yet open.
            "application_storage_fault": bool(
                enabled
                and attestor is not None
                and attestor.available
                and getattr(attestor, "application_storage_fault", False)
            ),
            # Why evidence trust is not established, from a closed vocabulary;
            # empty when it is. Signing can be available while trust is not.
            "posture_problems": list(getattr(self, "_evidence_posture_problems", ())),
            "anchor_epoch_id": "",
            "foreign_identity_pending_count": None,
            "stopped_local_artifact_count": None,
            "stopped_local_bytes": None,
            "oldest_stopped_local_since_ms": None,
            # Tier C action-outcome records, per tier-c-approval/v1; None
            # until the dispatcher exists.
            "action_records": (
                dispatcher.action_records()
                if (dispatcher := getattr(self, "_dispatcher", None)) is not None
                and hasattr(dispatcher, "action_records")
                else None
            ),
        }
        if not enabled:
            health.update(
                registration_status=RegistrationStatus.DISABLED.value,
                registration_pending_since_ms=None,
                registration_confirmation_overdue=False,
                registration_offer=RegistrationOffer.NOT_APPLICABLE.value,
                last_disposition=None,
            )
        if attestor is not None and attestor.available:
            anchor = getattr(attestor, "anchor", None)
            health["anchor_epoch_id"] = anchor.anchor_epoch_id if anchor else ""
            # Omitted, not guessed, when it cannot be read: a consumer treats
            # absence as unknown, and never as confirmed.
            read_registration = getattr(attestor, "registration_health", None)
            if read_registration is not None:
                registration = await read_registration(now_ms())
                if registration is not None:
                    health.update(registration)
            health["chain_head_hash"] = await attestor.chain_head_hash()
            health["pending_export_count"] = await attestor.pending_export_count()
            awaiting = await attestor.awaiting_receipt(now_ms())
            if awaiting is not None:
                (
                    health["awaiting_receipt_count"],
                    health["oldest_awaiting_receipt_age_ms"],
                ) = awaiting
            refusals = await attestor.ingest_refusal_summary()
            if refusals is not None:
                health["ingest_refusal_count"] = refusals["count"]
                health["last_ingest_refusal"] = refusals["last"]
        if (
            enabled
            and self._state_store is not None
            and hasattr(self._state_store, "get_attestation_summary")
        ):
            try:
                summary = await self._state_store.get_attestation_summary()
                health["last_attested_action_id"] = summary["last_attested_action_id"]
                health["attestation_gap_count"] = summary["attestation_gap_count"]
                health["status_counts"] = summary["status_counts"]
                unresolved = int(summary.get("contributor_links_unresolved", 0))
                if unresolved != getattr(self, "_contributor_links_unresolved", 0):
                    self._contributor_links_unresolved = unresolved
                    if unresolved:
                        # The holder a contributor joined left no row: the act's
                        # own record was lost. Reported, never back-filled.
                        logger.error(
                            "[evidence] %d contributor record(s) name a holder "
                            "whose action-log row was never written",
                            unresolved,
                        )
            except Exception:
                logger.warning("[evidence] attestation summary read failed")
        return health

    def _telemetry_export_health(self) -> dict[str, Any]:
        """Report export state. It never contributes to `status` or `critical`.

        Export suspension is driven by product-side account state. Letting it
        degrade the device's health verdict would put billing state on a path
        that reaches protection decisions, which is the boundary this must not
        cross.
        """
        exporter = self._telemetry_exporter
        if exporter is None:
            return {"enabled": False}
        snapshot = exporter.status_snapshot()
        snapshot["enabled"] = True
        return snapshot

    async def _build_health_snapshot(self) -> dict[str, Any]:
        now = now_ms()
        uptime_s = (
            max(0.0, (now - self._runtime_started_at_ms) / 1000.0)
            if self._runtime_started_at_ms > 0
            else 0.0
        )

        posture = (
            vars(self._capability_posture_tracker.get_snapshot())
            if self._capability_posture_tracker is not None
            else None
        )
        if posture is None:
            capability_posture = {
                "available": False,
                "sms_available": False,
                "whatsapp_available": False,
                "gateway_reachable": False,
                "local_slm_loaded": False,
                "relay_connected": False,
                "internet_available": False,
                "checked_at_ms": 0,
                "expires_at_ms": 0,
                "gateway_last_heartbeat_ms": None,
            }
        else:
            capability_posture = {
                "available": True,
                "sms_available": bool(posture["sms_available"]),
                "whatsapp_available": bool(posture["whatsapp_available"]),
                "gateway_reachable": bool(posture["gateway_reachable"]),
                "local_slm_loaded": bool(posture["local_slm_loaded"]),
                "relay_connected": bool(posture["relay_connected"]),
                "internet_available": bool(posture["internet_available"]),
                "checked_at_ms": int(posture["checked_at_ms"]),
                "expires_at_ms": int(posture["expires_at_ms"]),
                "gateway_last_heartbeat_ms": posture["gateway_last_heartbeat_ms"],
            }

        sensors: list[dict[str, Any]] = []
        for sensor_cfg in self._configured_sensors:
            sensor_id = str(sensor_cfg.id)
            poll_ms = int(sensor_cfg.poll_interval_ms)
            last_seen_ms = self._sensor_last_seen_ms.get(sensor_id)
            stale = False
            if last_seen_ms is not None:
                stale = (now - int(last_seen_ms)) > silence_bound_ms(poll_ms)
            sensors.append(
                {
                    "id": sensor_id,
                    "type": str(sensor_cfg.type),
                    "protocol": str(sensor_cfg.protocol),
                    "poll_interval_ms": poll_ms,
                    "connected": sensor_id in self._connected_sensor_ids,
                    "measurement_degraded": sensor_id in self._measurement_degraded,
                    "consecutive_refusals": self._measurement_refusals.get(
                        sensor_id, 0
                    ),
                    "measurement_refusal_reason": (
                        self._measurement_refusal_reason.get(sensor_id)
                    ),
                    "last_seen_ms": int(last_seen_ms)
                    if last_seen_ms is not None
                    else None,
                    "stale": bool(stale),
                }
            )

        community_skills_health = self._community_skills_health()
        config_authority_health = self._config_authority_health()

        safety_state: dict[str, Any] | None = (
            self._safety_registry.health_snapshot()
            if self._safety_registry is not None
            else None
        )

        device_policy_state: dict[str, Any]
        if self._dispatcher is not None:
            device_policy_state = self._dispatcher.get_policy_state_snapshot()
        else:
            device_policy_state = {
                "available": False,
                "policy_version": None,
                "tier": None,
                "relay_b_enabled": None,
                "relay_c_enabled": None,
                "cloud_llm_enabled": None,
                "valid_until": None,
                "issued_at": None,
                "is_expired": None,
            }
        device_policy_state["enabled"] = self._device_policy_enabled
        lockout_stale_after_ms = int(
            self._remote_command_lockout_config["state_stale_after_ms"]
        )
        remote_command_lockout_senders: list[dict[str, Any]] = []
        for state in self._remote_command_lockout_states.values():
            item = dict(state)
            checked_at_ms = int(item.get("checked_at_ms") or 0)
            item["stale"] = checked_at_ms <= 0 or (
                now - checked_at_ms > lockout_stale_after_ms
            )
            remote_command_lockout_senders.append(item)

        alert_outbox = await self._build_alert_outbox_health(now)
        firmware_liveness_health = self._firmware_liveness_health()

        snapshot: dict[str, Any] = {
            "device_id": self._device_id,
            "uptime_s": uptime_s,
            "health_socket_path": self._health_socket_path,
            "firmware_mqtt_operator": {
                "available": self._firmware_mqtt_operator_server is not None,
                "socket_path": self._firmware_mqtt_operator_socket_path,
                "contract": "ori.runtime.firmware-mqtt-operator",
                "schema_version": 1,
            },
            "capability_posture": capability_posture,
            "gateway_broker_posture": self._gateway_broker_posture_health(),
            "state_store_encryption": self._state_store_encryption_health(),
            "sensors": sensors,
            "safety": safety_state,
            "last_alert_timestamps": {
                "by_channel": dict(self._last_alert_timestamps_by_channel),
                "by_trigger": dict(self._last_alert_timestamps_by_trigger),
            },
            "alert_outbox": alert_outbox,
            "device_policy": device_policy_state,
            "remote_command_lockout": {
                "enforcement_enabled": is_truthy(
                    self._remote_command_lockout_config.get(
                        "enforcement_enabled", False
                    )
                ),
                "risk_window_ms": int(
                    self._remote_command_lockout_config["risk_window_ms"]
                ),
                "stale_after_ms": lockout_stale_after_ms,
                "incident_sender_limit": int(
                    self._remote_command_lockout_config["incident_sender_limit"]
                ),
                "senders": remote_command_lockout_senders,
            },
            "evidence": await self._evidence_health(),
            "commissioning": self._commissioning_health(),
            "community_skills": community_skills_health,
            "config_authority": config_authority_health,
            "firmware_liveness": firmware_liveness_health,
            "firmware_reading_age": self._firmware_reading_age_health(),
            "firmware_controller_profiles": (
                await self._firmware_controller_profiles_health()
            ),
            "telemetry_export": self._telemetry_export_health(),
        }
        # `runtime-health/v3` types this as an array and reads absence as
        # unknown, so a device with no registry omits the key entirely rather
        # than carrying a null a consumer would iterate.
        safety_zones: list[dict[str, Any]] = []
        if self._safety_registry is not None:
            safety_zones = self._safety_registry.safety_zones()
            snapshot["safety_zones"] = safety_zones
        # Each condition contributes its severity and none assigns `status`, so
        # the order they are evaluated in never lets a degraded condition
        # overwrite a critical one.
        severities: list[str] = []
        if firmware_liveness_health["degraded"]:
            # A stopped or stalled liveness loop puts timely publication at
            # risk for one or more supervised devices while the rest of the
            # runtime looks healthy. A report that does not say which kind it
            # is counts as critical.
            severities.append(
                "critical"
                if firmware_liveness_health.get("critical", True)
                else "degraded"
            )
        if self._measurement_degraded:
            # A sensor that connected and then refused a run of windows is not
            # measuring either, and the reasoning one branch below applies to it
            # word for word. Reported per sensor and carried into the
            # aggregate, so a fleet view keyed on `status` cannot read green
            # while a channel goes unmeasured — which is the condition
            # `docs/MEASUREMENT_SUPERVISION.md` exists to make impossible to
            # miss. Degraded rather than critical, and it names no
            # `degradation_reasons` token because that vocabulary is closed and
            # carries none for this yet; the health contract has no token for
            # a sensor that stopped measuring.
            severities.append("degraded")
        if self._unconnected_sensors:
            # A configured sensor that never connected is not a healthy
            # runtime: something it was told to measure is not being measured.
            # Degraded rather than critical, and it names no token in
            # `degradation_reasons` because that vocabulary is closed and
            # carries none for this yet; the sensor
            # itself reports `connected: false` in the meantime.
            severities.append("degraded")
        if community_skills_health["refused_skills"]:
            # An anchor the deployment cannot verify with drops every
            # community skill on the device. Authority still failed closed, so
            # this is degraded rather than critical — but a device running
            # none of the skills it was configured with is not healthy, and
            # until now the only signal was one log line per dropped skill.
            #
            # The count, not the anchor, is what degrades. The default anchor
            # is unconfigured, so a device carrying only first-party skills
            # would otherwise report degraded with nothing wrong.
            severities.append("degraded")
        if config_authority_health["unsigned_value_source"]:
            # A signature covers the document before expansion. When a .env
            # supplied what `${VAR}` fields expanded to, the signature still
            # verifies and says nothing about the values the runtime is
            # actually running on. Hardened posture refuses the autoload
            # outright; a development deployment that asked for a signature
            # gets to keep running, and gets told.
            severities.append("degraded")
        if getattr(self, "_evidence_posture_problems", ()):
            # Evidence trust not established is degraded, not critical: the
            # safety path is unaffected, and what is at risk is the record.
            severities.append("degraded")
        envelope_state = getattr(self, "_gateway_envelope_state", None)
        if envelope_state is not None and envelope_state.signing_clock.refusing():
            # No claimed signing time is left while the state store stalls, so
            # runtime-gateway envelopes go unsigned and unsent: heartbeats,
            # reasoning requests, export responses and inbound acks. Degraded,
            # and no token: the vocabulary is closed and carries none for it.
            severities.append("degraded")
        if snapshot["evidence"].get("application_storage_fault") is True:
            # The record of what the authority said is what is at risk, so
            # degraded; it gates no action, no Tier D and no safety binding.
            severities.append("degraded")
        records_dispatcher = getattr(self, "_dispatcher", None)
        if (
            records_dispatcher is not None
            and hasattr(records_dispatcher, "action_records_degrade_health")
            and records_dispatcher.action_records_degrade_health()
        ):
            # An uncertain or unappended Tier C outcome, or the pending
            # structure full: the evidence object carries no status of its
            # own, so this is the aggregate's to say. Degraded, never critical:
            # the approval stands, and no act was replayed or delayed.
            severities.append("degraded")
        if self._records_lost_or_stalled():
            # A record the store never took is gone from the action log, and
            # one that has waited this long is a store that is not answering.
            # Losses are logged CRITICAL; health is degraded rather than
            # critical for the same reason as above — the acts ran, the record
            # did not. runtime-health/v3 defines no row for the record queue,
            # so the condition is reported through `status` and the log alone.
            severities.append("degraded")
        if self._decision_records_lost():
            # An operator's decision whose record the store never took. The
            # decision invariant is the one PATF names critical, and the
            # contract's `action_records` row, which the approval admission
            # brings, classifies a lost approved decision record the same way.
            severities.append("critical")
        commissioning = getattr(self, "_commissioning_state", None)
        if commissioning is not None and commissioning.problems:
            # Declared actuating hardware with no accepted binding is a device
            # that cannot claim protection; it must not read as healthy.
            severities.append("degraded")
        if any(
            zone.get("activation") == "active"
            and zone.get("protection_claim") == "unprotected"
            for zone in safety_zones
        ):
            # An active pair is one the device has undertaken to protect, and
            # `unprotected` says it is not doing so. `runtime-health/v3` does
            # not require this, so it is a decision rather than a conformance
            # gap: a fleet view aggregating `status` would otherwise show
            # nothing wrong while a zone the device claims to protect is not
            # being protected. Commissioning problems already degrade for the
            # same class of fact, one step earlier.
            #
            # Only `active` pairs count. A pair held for ratification or
            # refused reports `unprotected` too, and correctly — the device
            # never undertook to protect it, and degrading on those would make
            # every device carrying a candidate profile permanently degraded.
            #
            # Degraded, never critical, and it changes nothing about Tier D:
            # this is a report, and the protection path neither reads it nor
            # is gated by it.
            #
            # The consequence to expect: `_backend_drivable` is a constant
            # `False` until the actuation seam carries a non-actuating
            # drivability member, which is not built yet, so
            # the first ratified profile makes every device carrying one
            # permanently degraded on a fully commissioned zone with nothing
            # wrong. That is the honest report — the producer cannot establish
            # protection — but it is a fleet-wide change the day ratification
            # lands, and `degradation_reasons` carries no token for it, so the
            # reason is not nameable until the health contract adds one.
            severities.append("degraded")

        # Named reasons for the site view. The rich diagnostics above stay
        # local: fleet counts reveal deployment topology and per-device
        # identity is a disclosure this contract does not make. Only closed,
        # non-sensitive tokens cross the boundary.
        status = fold_health_status(severities)
        if status is not None:
            snapshot["status"] = status
        snapshot["critical"] = status == "critical"

        snapshot["degradation_reasons"] = degradation_reasons(
            firmware_liveness_degraded=bool(firmware_liveness_health["degraded"]),
        )
        return snapshot

    def _community_skills_health(self) -> dict[str, Any]:
        """Whether community skills can be verified here, and what was dropped.

        Reported from one load rather than answered live: pairing this load's
        count with a later reading of the anchor would describe a state the
        device was never in.
        """
        if self._skill_loader is None:
            # Before skills are loaded there is no answer, and an unusable
            # anchor with no fault to name is a contradiction a consumer would
            # try to act on. `available` is how the rest of this snapshot says
            # a subsystem has not reported yet.
            return {
                "available": False,
                "anchor_usable": False,
                "anchor_fault": None,
                "refused_skills": 0,
            }
        admission = self._skill_loader.community_admission()
        return {
            "available": True,
            "anchor_usable": admission.anchor_usable,
            "anchor_fault": admission.anchor_fault,
            "refused_skills": admission.refused_skills,
        }

    def _config_authority_health(self) -> dict[str, Any]:
        """What decided the configuration values this runtime is running on.

        ``unsigned_value_source`` is the fact worth acting on: a signature was
        asked for, and a file outside what it covers supplied the values of
        fields inside it.
        """
        signature: dict[str, Any] = {}
        if self._config is not None:
            candidate = self._config.security.get("config_signature")
            if isinstance(candidate, dict):
                signature = candidate
        required = bool(signature.get("required", False))
        verified = bool(signature.get("verified", False))
        supplied = self._dotenv_variables
        referenced = self._config_env_placeholders
        # The file's existence is not a supplied value. `load_dotenv` runs with
        # `override=False`, so it decides nothing the environment already
        # carried, and a document naming no variable it supplied expands to the
        # same values with or without it. Reporting on existence degraded a
        # device whose `.env` changed nothing about what it was running.
        #
        # Unknown is not the same as none: until the document has been read
        # there is nothing to intersect, and a file that was loaded is then
        # assumed to have decided something.
        decided = supplied is not None and (
            referenced is None or bool(supplied & referenced)
        )
        return {
            # Reporting "no signature required" from a document that has not
            # been read yet is a claim, not a reading.
            "available": self._config is not None,
            "signature_required": required,
            "signature_verified": verified,
            "dotenv_loaded": supplied is not None,
            # A .env on a deployment that signs nothing undermines no
            # authority; it is the ordinary development convenience the toggle
            # is documented as. What is reportable is the combination.
            "unsigned_value_source": decided and (required or verified),
        }

    def _firmware_reading_age_health(self) -> dict[str, Any]:
        """Per device, how long ago its latest accepted reading was polled, at most.

        Only a bound this runtime computed from its own liveness signing, named
        and anchored to the instant it was computed, or "unbounded". Never a
        claim that a reading is fresh, current or live.
        """
        tracker = self._firmware_reading_age
        if tracker is None:
            # No firmware telemetry is accepted, so there is no reading to bound.
            return {"enabled": False}
        return {
            "enabled": True,
            "signing_runtime": tracker.table is not None,
            "devices": tracker.health(),
        }

    async def _firmware_controller_profiles_health(self) -> dict[str, Any]:
        """Profile documents held and each foreign controller's alarm state.

        An alarm state is shown as of the reading it came from, named by key
        epoch and (boot_id, seq), never as the controller's state now; the
        acceptance time beside it is the runtime's, never the poll's.
        """
        library = self._firmware_profile_library
        tracker = self._firmware_alarm_tracker
        if library is None or tracker is None or self._state_store is None:
            return {"enabled": False}
        try:
            alarm_channels = await tracker.states(self._state_store.get_firmware_device)
        except Exception:
            logger.exception("[health] could not read controller alarm states")
            alarm_channels = []
        reading_age = self._firmware_reading_age
        for state in alarm_channels:
            reading = state.get("reading") or state.get("latest_reading")
            if not isinstance(reading, dict):
                continue
            bound = (
                None
                if reading_age is None
                else reading_age.message_bound(
                    str(state.get("device_id")),
                    str(reading["key_epoch_id"]),
                    reading["boot_id"],
                    reading["seq"],
                )
            )
            # A snapshot of the device's poll, never the controller's state now.
            reading["liveness_bound"] = (
                "unbounded"
                if bound is None
                else {**bound.as_health(), "text": f"snapshot {bound.text()}"}
            )
        return {
            "enabled": True,
            "documents_held": library.held(),
            "documents_refused": list(library.refused),
            "alarm_channels": alarm_channels,
        }

    def _firmware_liveness_health(self) -> dict[str, Any]:
        scheduler = self._firmware_liveness_scheduler
        if scheduler is None:
            # Not configured is not degraded: no command egress means this
            # runtime is not the authority for any device, so there is no
            # obligation to be failing.
            return {
                "enabled": False,
                "running": False,
                "degraded": False,
            }
        health = dict(scheduler.health())
        health["enabled"] = True
        return health

    def _gateway_broker_posture_health(self) -> dict[str, Any]:
        if self._config is None:
            return {
                "available": False,
                "gateway_enabled": False,
                "deployment_check": "unknown",
                "anonymous_access": "unknown",
                "acl_policy": "unknown",
                "require_credentials": False,
                "credentials_configured": False,
                "requires_acl_hardening": True,
            }
        broker_posture = self._config.gateway.broker_posture
        broker_url = str(self._config.gateway.broker_url or "").strip()
        parsed = urlparse(broker_url if "://" in broker_url else f"mqtt://{broker_url}")
        credentials_configured = bool(parsed.username and parsed.password)
        hardened = (
            broker_posture.get("deployment_check") == "required"
            and broker_posture.get("anonymous_access") == "disabled"
            and broker_posture.get("acl_policy") == "per_device_required"
            and is_truthy(broker_posture.get("require_credentials", False))
            and credentials_configured
        )
        return {
            "available": True,
            "gateway_enabled": bool(self._config.gateway.enabled),
            "deployment_check": str(broker_posture.get("deployment_check", "warning")),
            "anonymous_access": str(broker_posture.get("anonymous_access", "unknown")),
            "acl_policy": str(broker_posture.get("acl_policy", "unknown")),
            "require_credentials": is_truthy(
                broker_posture.get("require_credentials", False)
            ),
            "credentials_configured": credentials_configured,
            "requires_acl_hardening": bool(self._config.gateway.enabled)
            and not hardened,
        }

    def _state_store_encryption_health(self) -> dict[str, Any]:
        if self._config is None:
            return {
                "available": False,
                "mode": "unknown",
                "satisfied": False,
                "marker_configured": False,
                "path_prefix_configured": False,
            }

        encryption = self._config.state.encryption
        marker_ok = bool(
            encryption.marker_file
            and Path(encryption.marker_file).expanduser().is_file()
        )
        db_path = Path(self._config.database_path).expanduser().resolve(strict=False)
        prefix_ok = any(
            path_is_relative_to(
                db_path,
                Path(prefix).expanduser().resolve(strict=False),
            )
            for prefix in encryption.encrypted_path_prefixes
        )
        return {
            "available": True,
            "mode": encryption.mode,
            "satisfied": bool(encryption.mode == "filesystem_required")
            and (marker_ok or prefix_ok),
            "marker_configured": bool(encryption.marker_file),
            "path_prefix_configured": bool(encryption.encrypted_path_prefixes),
        }

    async def _build_alert_outbox_health(self, now: int) -> dict[str, Any]:
        summary = {
            "backlog_count": 0,
            "oldest_queued_original_ts": None,
            "oldest_queued_at_ms": None,
            "oldest_queued_age_ms": None,
        }
        if self._state_store is not None:
            try:
                raw_summary = await self._state_store.get_alert_outbox_summary()
                oldest_ts = raw_summary.get("oldest_queued_original_ts")
                oldest_queued_at = raw_summary.get("oldest_queued_at_ms")
                summary = {
                    "backlog_count": int(raw_summary.get("backlog_count") or 0),
                    "oldest_queued_original_ts": int(oldest_ts)
                    if oldest_ts is not None
                    else None,
                    "oldest_queued_at_ms": int(oldest_queued_at)
                    if oldest_queued_at is not None
                    else None,
                    # Queue latency is the store's own interval; the event's
                    # producer time is reported beside it and never ages it.
                    "oldest_queued_age_ms": max(0, now - int(oldest_queued_at))
                    if oldest_queued_at is not None
                    else None,
                }
            except Exception:
                logger.exception("[runtime] alert outbox health summary failed")

        return {
            **summary,
            "retry_interval_minutes": self._alert_outbox_retry_interval_s / 60.0,
            "max_non_tier_d_attempts": self._alert_outbox_max_non_tier_d_attempts,
            "tier_d_critical_warning_threshold": self._alert_outbox_tier_d_critical_threshold,
            "batch_size": self._alert_outbox_batch_size,
        }
