# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The firmware epoch confirmation gate stays off the action path.

`FirmwareCommandService.publish_command`, `FirmwareCommandSigner.sign_command`
and `FirmwareCommandService._require_approved_device` refuse until the
evidence store has confirmed the device's `anchor_epoch_id`. The contracts put
that gate on granting authority, and keep evidence off the action path:

- device-provisioning/v1, Failure semantics: granting or changing authority
  fails closed, so an approval is not published until the evidence store
  confirms the identical `anchor_epoch_id`; previously confirmed authority
  fails stable.
- evidence-exchange/v1, Fail-closed and fail-open: recording what happened
  fails open, and an unreachable authority MUST NOT block, delay or gate a
  Tier C/D action. Under `pending_authorisation`, the pending state never
  blocks, delays or gates a local Tier D safety action.

No executor or dispatch path reaches the gate today. The guards below hold
that against accidental and honest architectural regressions: a change that,
in this codebase's ordinary spellings, puts the gate, firmware command egress
or a firmware reading's provenance on the action path. Code written
specifically to evade a test is outside what they prove, and `_LIMIT` names
the spellings they do not see. They are one guard on the boundary, not a proof
of the physical boundary by themselves. Two layers:

- Behavioural, the primary guard. Sentinels replace every function in the
  gate's modules that reaches the confirmation query, and every function
  there named for signing or publishing (both derived from source, not
  listed), before the runtime is built, and record every call from any task.
  After start, the signing keys and the transport's client beneath those are
  sentinels too. A real `OriRuntime.start` with
  firmware command egress, CoAP commands and a commissioned relay zone then
  registers every executor it has. Each executor is invoked with a context it
  resolves a target from and must reach its own leaf, and every registered
  action is driven through each dispatch route (Tier A, B, B under approval,
  C approved, C refused, D) from a local reading and from firmware readings of
  three devices whose epochs are unconfirmed in different ways, interleaved
  and repeated; every physical action must execute on the C and D routes,
  with a Tier C proposal actually sent before any reply exists. An act
  reported executed must be observed at its own leaf (the commissioned
  outcome and the coil state, for a relay action). Everything each leaf was
  asked, positional and named, including every alert, dashboard log, coil
  write and approval listen, must match the local dispatch, and no leaf may
  act after its dispatch returned. The probe epochs are seeded in the store before start;
  every store method over the table the gate reads, the evidence side's
  confirmed-epoch reader, and the production confirmation coordinator and
  reconciler (installed on the runtime) are sentinels too; and every SQLite
  connection records reads of the confirmation tables at the engine, whatever the SQL is
  called from. No sentinel may fire and no engine read may precede execution,
  during the test or from work still running after stop,
  the unconfirmed epoch may not change any outcome, and the one evidence read
  the dispatcher does make, attestation of a firmware-sourced Tier C or D row,
  must follow the execution of the act it could delay, not merely of whatever
  ran first in that dispatch. Every dispatch is also timed, so a delay no
  recorder observes still fails when it depends on firmware provenance or
  exceeds an absolute bound. One dispatch at a time is all
  this proves: whether that read delays a later act in the same event is the
  cross-action ordering `_LIMIT` names.
- Static, for what the behavioural guard cannot construct: wiring that exists
  only in another configuration, or code no test reaches. It resolves imports
  and attribute chains, scans string constants, and keeps an inventory of every
  touch on the firmware command surface keyed by qualified scope.

`_LIMIT` states what neither layer proves.

Adding a firmware-backed executor legitimately: its route to the device must
carry authority already recorded (the approval and in-force binding stored
with a Tier C approval, or the release-owned Tier D grant), through a signing
method that never names the confirmation query. Every signing and publishing
method is a sentinel here, so that route must be excluded from the egress
derivation by name, with the authority it carries. Register it in `start`,
name its leaf in `EXECUTOR_LEAVES`, classify its touches here, and these tests
then require it to reach the device with an unconfirmed epoch on the approved
Tier C and Tier D routes.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import contextlib
import contextvars
import functools
import gc
import importlib
import itertools
import json
import os
import re
import secrets
import sqlite3
import sys
import textwrap
import types
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.actions.alert_delivery import AlertSendReceipt
from ori.actions.alert_failover import AlertFailoverSender
from ori.actions.coap import CoAPAction, coap_backend_available
from ori.actions.commissioned_actuator import CommissionedActuator
from ori.actions.logger import LoggerAction
from ori.actions.process_manager import ProcessManagerAction
from ori.actions.relay import RelayAction
from ori.actions.sms import SMSAction
from ori.actions.system_control import SystemControlAction
from ori.gateway.firmware_commands import (
    FirmwareCommandService,
    MqttFirmwareCommandPublisher,
)
from ori.network.events import OriEvent, ReasoningResult, SensorReading
from ori.reasoning.action_registry import capability
from ori.reasoning.elevator import SkillContext
from ori.runtime import OriRuntime
from ori.security.commissioning.anchors import COMMISSIONING_ANCHOR_ENV
from ori.security.commissioning.loader import BINDING_RELATIVE_PATH
from ori.security.evidence.ingest_service import ConfirmedEpochReader
from ori.security.firmware.commands import FirmwareCommandSigner
from ori.security.firmware.confirmation import FirmwareConfirmationCoordinator
from ori.security.firmware.reconciliation import FirmwareConfirmationReconciler
from ori.state.store import StateStore
from tests.commissioning.signing import (
    EPHEMERAL_SEED,
    local_gpio_binding,
    public_key_b64,
    sign_envelope,
)
from tests.conftest import _mark_startup_complete

ROOT = Path(__file__).resolve().parents[1]

_LIMIT = (
    "Limit of these guards. They detect accidental and honest architectural "
    "regressions; code written to evade them is outside what they prove, and "
    "they do not by themselves prove the physical boundary. What passes both "
    "layers: (1) computed names to the "
    "command-service surface or to the tables the gate reads, on a "
    "configuration or input the probe does not build, such as a skill-config "
    "branch or database state it does not seed (an epoch status other than "
    "pending, quarantined, or approved with no obligation row); (2) work an action defers until after the runtime stops, since "
    "stop releases the command service, a task stop cancels never makes the "
    "call, and the teardown wait is bounded, and likewise a leaf act deferred "
    "past SETTLE_S within the test or past that wait; (3) a delay that no recorder "
    "observes and that stays below the timing bounds, either at most "
    "FIRMWARE_DELAY_BOUND_S longer for a firmware-sourced dispatch than for the "
    "same local one, or independent of firmware provenance and under "
    "DISPATCH_BOUND_S for every dispatch. What "
    "is not driven: the probe is one runtime (development profile, firmware "
    "command egress and CoAP on, one commissioned GPIO zone, no skills, the "
    "production confirmation coordinator and reconciler installed after "
    "startup with no evidence authority behind them), one probe context per "
    "executor, and ActionDispatcher.dispatch called directly; "
    "DispatchCoordinator, the safety registry's commander, skill hooks and "
    "remote commands are covered by source only, as is the code beneath the "
    "replaced leaf actions (CoAP, process, kernel, alert send). The relay is "
    "simulated: the coil witness is its simulated state, so a write to a real "
    "GPIO device beneath it, or a line taken at a state by acquire_at, is not "
    "observed. The stale-sensor watch is cancelled, since it alerts on wall "
    "time rather than on any action. A key derived again is seen only when it "
    "is read from the environment's store after start, by any reference to "
    "it; posix.environ, the process's own environment file, and a copy of the "
    "key taken during start outside the runtime's command-egress objects are "
    "not. The records the dispatcher writes about an act (the action_log, "
    "override and Tier C decision rows) are not compared across sources, and "
    "no status indicator is configured, so its calls are never made. The "
    "confirmation coordinator is installed after start, so the startup drain "
    "of pending confirmations returns early and anything derived from it at "
    "start is not driven. Leaf text is compared with the "
    "reading's sensor and source device, and clock times and weekdays, folded, "
    "so a firmware-only change confined to those tokens is not seen. The raw "
    "egress sentinels are the keys and client reachable from the runtime's "
    "command service, transport and liveness scheduler; a copy held anywhere "
    "else is not replaced. The Tier C route runs with comms availability "
    "stubbed on, _listen_for_response stubbed to reply only after a proposal "
    "was sent in the same dispatch, and _generate_proposal_id fixed, and "
    "attestation reaches a stub evidence attestor with no ledger. The "
    "engine recorder authorizes a connection opened other than through "
    "sqlite3.connect (a connect bound before the probe, or a Connection built "
    "directly) only at arming and at each window entry, so one opened and used "
    "entirely inside a single window, or a statement it prepared before then "
    "and reuses from its cache, is not recorded. Cross-action "
    "ordering is not proven here: the coordinator awaits each Tier D act of "
    "one event in turn, so a later act waits on an earlier act's attestation, "
    "including its confirmation read; that ordering belongs to the separate "
    "Tier D ordering fix, whose test drives DispatchCoordinator. Only runtime "
    "attributes prefixed _firmware are checked for holding firmware authority, "
    "and the whole-tree scan sees names, not aliases or values passed through a "
    "module that legitimately imports both sides. Directories "
    "left out "
    "of the import scan are ori/hal, "
    "ori/telemetry, ori/installer, ori/gateway, ori/state and ori/security "
    "other than remote_commands: none decides or executes an action, and a "
    "touch on the command surface from any of them is still caught by the "
    "whole-tree surface scan. Before firmware-backed actuation is wired, its "
    "executor needs an already-authorised route that never consults epoch "
    "confirmation on a Tier C or Tier D action (evidence-exchange/v1, "
    "Fail-closed and fail-open), and a behavioural test here proving it."
)

# ── What the gate is ────────────────────────────────────────────────────────

#: Modules the action path may not import: they sign, publish, or confirm
#: firmware authority. ``ori.security.firmware`` is the whole package because
#: the action path imports nothing from it today.
FIRMWARE_AUTHORITY_MODULES = (
    "ori.gateway.firmware_commands",
    "ori.security.firmware",
    "ori.firmware_provisioner",
)

#: Leaf spellings of those modules, for string constants in the action path
#: (``importlib.import_module(".firmware_commands", "ori.gateway")``).
FIRMWARE_MODULE_LEAVES = ("firmware_commands", "firmware_provisioner")

#: Names on the firmware command surface. Reaching any of these reaches the
#: confirmation gate or the signing behind it.
SURFACE_NAMES = (
    "publish_command",
    "sign_command",
    "sign_command_bytes",
    "_require_approved_device",
    "publish_provisioning_approval",
    "_firmware_command_service",
    "publish_firmware_command",
    "approve_firmware_commands",
    "get_firmware_confirmation_status",
    # The data the gate reads, by every name the store gives it: a refusal or
    # delay keyed on the table needs no call to the gate query itself.
    "firmware_confirmation_outbox",
    "_get_firmware_confirmation_status_sync",
    "list_pending_firmware_confirmations",
    "get_firmware_confirmation_summary",
    "record_firmware_confirmation_attempt",
    "resolve_firmware_confirmation",
    # The evidence side's record of which epoch a signed confirmation proved
    # active, by table and by every reader of it.
    "evidence_device_epochs",
    "confirmed_epoch",
    "active_anchor_epoch_id",
)

#: Runtime attributes holding a path to the runtime command key or the
#: command topic that does not pass the gate: the transport, and the liveness
#: scheduler over the liveness signer. Scanned everywhere; not followed through
#: the runtime, where reading the scheduler's health is not egress.
HOLDER_NAMES = (
    "_firmware_command_publisher",
    "_firmware_liveness_scheduler",
    # The operator provisioning server: the provisioner and CA keys, and the
    # provisioning service whose install consults the gate.
    "_firmware_mqtt_operator_server",
)

#: Firmware attributes of the runtime that hold no path to a key, a topic or
#: the gate. Every other ``self._firmware*`` attribute must be named above.
NOT_HOLDERS = {
    "_firmware_mqtt_operator_socket_path": "a filesystem path, holding no object",
    "_firmware_liveness_supervisor": (
        "the supervised-device table and its clock; it holds no key and "
        "publishes nothing"
    ),
}

#: Where the authority keys come from, and the builders that sign with them.
#: Code holding any of these can sign a command or a grant with no service at
#: all. Refused anywhere on the action path; inventoried in runtime.py.
KEY_SOURCE_NAMES = (
    "firmware_commands",
    "runtime_command_key_env",
    "provisioner_key_env",
    "build_provisioning_approval_bytes",
    "build_command_bytes",
)

#: Additional names the runtime.py inventory tracks: construction of the
#: service and the builders that return it.
RUNTIME_ONLY_NAMES = (
    "FirmwareCommandService",
    "FirmwareCommandSigner",
    "MqttFirmwareCommandPublisher",
    "_build_firmware_command_service",
    "_build_firmware_liveness_stack",
)

# ── Where the action path is ────────────────────────────────────────────────

#: Where physical authority is decided, approved, or executed. Each directory
#: is asserted non-empty on its own, so a rename cannot drop one silently.
ACTION_PATH = (
    "ori/reasoning",  # dispatcher, coordinator, rule engine, elevator
    "ori/actions",  # executors
    "ori/safety",  # Tier D safety registry and its commander
    "ori/network",  # approval-reply webhook ingress
    "ori/security/remote_commands",  # remote commands that mutate runtime state
    "ori/skills",  # skill loading and hooks
    "ori/hardware",  # relay and status outputs
    "ori/integration",  # rule evaluation shared with the dispatch path
    "ori/policy",  # device policy consulted at dispatch
    "skills",  # bundled skill hooks, run in-process
)

#: Modules that define the surface, scanned by neither the whole-tree check
#: nor the inventory: the definitions are the thing being guarded.
DEFINING_MODULES = (
    "ori/gateway/firmware_commands.py",
    "ori/security/firmware/commands.py",
    "ori/state/store.py",
    "ori/security/evidence/ledger.py",
    "ori/security/evidence/bound.py",
    "ori/security/evidence/ingest_service.py",
)

RUNTIME = "ori/runtime.py"

# ── Touches that exist, and why each is not on the action path ─────────────

#: Every touch on the surface outside runtime.py and the defining modules,
#: keyed ``path::qualified scope::name``. Stale entries fail.
SURFACE_TOUCHES: dict[str, str] = {
    "ori/security/firmware/confirmation.py::FirmwareConfirmationCoordinator"
    "._readback::active_anchor_epoch_id": (
        "grant side: the coordinator's evidence read-back for a newly approved epoch"
    ),
    "ori/security/firmware/mqtt_provisioning.py::_canonical_response_object"
    "::active_anchor_epoch_id": (
        "a wire field name in a provisioning response object, not a read"
    ),
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._firmware_source_confirmed"
    "::get_firmware_confirmation_status": (
        "evidence attestation of a firmware-sourced Tier C/D row, reached from "
        "_log_action after this action's executor has run; it decides whether "
        "the row is signed now or left pending, never whether this action runs. "
        "The behavioural guard asserts the read follows its own dispatch's "
        "execution, and does not prove it cannot delay a later act awaited "
        "after it in the same event"
    ),
    "ori/security/firmware/confirmation.py::FirmwareConfirmationCoordinator.confirm"
    "::get_firmware_confirmation_status": (
        "the grant side: drives evidence-store confirmation of a newly approved "
        "anchor epoch, which is where the gate belongs"
    ),
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._attest_action"
    "::_firmware_source_confirmed": (
        "attestation, reached from _log_action after this action's executor has "
        "run; the call site of the classified read above"
    ),
    "ori/security/firmware/confirmation.py::FirmwareConfirmationCoordinator._decide"
    "::resolve_firmware_confirmation": (
        "the grant side: records the evidence store's answer for a newly approved "
        "anchor epoch"
    ),
    "ori/security/firmware/confirmation.py::FirmwareConfirmationCoordinator"
    "._record_attempt::record_firmware_confirmation_attempt": (
        "the grant side: counts a confirmation attempt for a newly approved epoch"
    ),
    "ori/security/firmware/reconciliation.py::FirmwareConfirmationReconciler"
    "._pending_device_ids::list_pending_firmware_confirmations": (
        "the grant side: the reconciler retrying pending confirmations of new "
        "epochs, a background loop that decides no action"
    ),
    "ori/security/firmware/mqtt_provisioning.py::FirmwareMqttProvisioningService"
    "._eligible_anchor::get_firmware_confirmation_status": (
        "operator provisioning ingress: refuses to publish a provisioning grant "
        "for an unconfirmed epoch, which is the gate applied to a grant"
    ),
    "ori/security/firmware/ingest.py::FirmwareTelemetryGate.approve_device"
    "::approve_firmware_device": (
        "the grant: promotes a device's pending anchor to active, called by the "
        "operator provisioning CLI"
    ),
    "ori/security/firmware/mqtt_provisioning.py::FirmwareMqttProvisioningService"
    "._allocate_sequence::allocate_firmware_provision_seq": (
        "operator provisioning ingress: allocates the sequence of a provisioning "
        "grant it is about to sign"
    ),
    "ori/firmware_provisioner.py::_publish::publish_provisioning_approval": (
        "operator CLI, dry-run only: signs a provisioning approval, a grant, "
        "through a service it builds for itself"
    ),
}

#: Operator ingress that may call the grant surface. These are permissions,
#: not descriptions: none of them calls it today. Approval is the grant, and
#: the grant is exactly where the confirmation gate belongs. Nothing here may
#: sit on the action path, and nothing here may call the command half.
OPERATOR_INGRESS: dict[str, dict[str, str]] = {
    "ori/cli_bridge.py": {
        "approve_firmware_commands": (
            "the local operator bridge is the natural caller of the provisioning "
            "grant; a refusal there is the contract's fail-closed grant"
        ),
    },
}

#: Every touch in ori/runtime.py, keyed ``qualified scope|kind|name``. Each
#: lambda and nested function is its own scope, so an executor closure inside
#: ``start`` is never covered by ``start``'s entry.
RUNTIME_TOUCHES: dict[str, str] = {
    "<module>|import|FirmwareCommandService": "imported for annotations and the builder",
    "<module>|import|MqttFirmwareCommandPublisher": "imported for the builder",
    "OriRuntime.__init__|store|_firmware_command_service": (
        "declares the attribute absent; constructs nothing and signs nothing"
    ),
    "OriRuntime.__init__|load|FirmwareCommandService": "the service attribute's annotation",
    "OriRuntime.__init__|load|MqttFirmwareCommandPublisher": (
        "the publisher attribute's annotation"
    ),
    "OriRuntime.approve_firmware_commands|load|_firmware_command_service": (
        "the provisioning grant wrapper; no caller in ori/ today, and any "
        "caller must sit in OPERATOR_INGRESS"
    ),
    "OriRuntime.approve_firmware_commands|load|publish_provisioning_approval": (
        "the provisioning grant wrapper publishing the approval"
    ),
    "OriRuntime.publish_firmware_command|load|_firmware_command_service": (
        "the command wrapper; no caller in ori/ today, and nothing on the "
        "action path may call it"
    ),
    "OriRuntime.publish_firmware_command|load|publish_command": (
        "the command wrapper delegating to the service"
    ),
    "OriRuntime.start|store|_firmware_command_service": (
        "lifecycle: stores the service built by _build_firmware_liveness_stack; "
        "a load of the attribute in start is a different key and fails here, and "
        "the local it is stored from is held by test_start_holds_the_service_"
        "only_in_its_lifecycle_bindings"
    ),
    "OriRuntime.start|load|_build_firmware_liveness_stack": (
        "lifecycle: composes telemetry, command egress and liveness"
    ),
    "OriRuntime.stop|store|_firmware_command_service": (
        "lifecycle: releases the service at shutdown"
    ),
    "OriRuntime.start|load|firmware_commands": (
        "lifecycle: reads the command configuration to size the grant-side "
        "reconciler's retry interval"
    ),
    "OriRuntime._start_firmware_mqtt_operator_if_enabled|load|firmware_commands": (
        "operator provisioning service: reads whether command egress is enabled"
    ),
    "OriRuntime._start_firmware_mqtt_operator_if_enabled|str|firmware_commands": (
        "operator provisioning service: the configuration key it reads"
    ),
    "OriRuntime._start_firmware_mqtt_operator_if_enabled|str|provisioner_key_env": (
        "operator provisioning service: loads the provisioner key it signs "
        "provisioning grants with, the grant side"
    ),
    "_build_firmware_command_service|load|firmware_commands": (
        "the one construction site of the command service reads its configuration"
    ),
    "_build_firmware_command_service|str|firmware_commands": (
        "the configuration key the construction site reads"
    ),
    "_build_firmware_command_service|str|runtime_command_key_env": (
        "the construction site loads the runtime command key into the service"
    ),
    "_build_firmware_command_service|str|provisioner_key_env": (
        "the construction site loads the provisioner key into the service"
    ),
    "_build_firmware_liveness_stack|load|firmware_commands": (
        "composition root: reads whether command egress is enabled"
    ),
    "_build_firmware_liveness_stack|str|firmware_commands": (
        "composition root: the configuration key it reads"
    ),
    "OriRuntime.__init__|store|_firmware_mqtt_operator_server": (
        "declares the operator provisioning server absent"
    ),
    "OriRuntime._start_firmware_mqtt_operator_if_enabled|store"
    "|_firmware_mqtt_operator_server": (
        "operator provisioning ingress: holds the server it built; the grant side"
    ),
    "OriRuntime._build_health_snapshot|load|_firmware_mqtt_operator_server": (
        "health: reports whether the operator server is available; calls nothing"
    ),
    "OriRuntime.stop|load|_firmware_mqtt_operator_server": (
        "lifecycle: closes the operator server at shutdown"
    ),
    "OriRuntime.stop|store|_firmware_mqtt_operator_server": (
        "lifecycle: releases the operator server at shutdown"
    ),
    "OriRuntime.__init__|store|_firmware_command_publisher": (
        "declares the transport absent; connects nothing"
    ),
    "OriRuntime.__init__|store|_firmware_liveness_scheduler": (
        "declares the liveness scheduler absent"
    ),
    "OriRuntime.start|store|_firmware_command_publisher": (
        "lifecycle: holds the transport built by _build_firmware_liveness_stack"
    ),
    "OriRuntime.start|store|_firmware_liveness_scheduler": (
        "lifecycle: holds the liveness scheduler, which signs liveness only"
    ),
    "OriRuntime.stop|load|_firmware_command_publisher": (
        "lifecycle: closes the transport at shutdown"
    ),
    "OriRuntime.stop|store|_firmware_command_publisher": (
        "lifecycle: releases the transport at shutdown"
    ),
    "OriRuntime.stop|store|_firmware_liveness_scheduler": (
        "lifecycle: releases the liveness scheduler at shutdown"
    ),
    "OriRuntime._firmware_liveness_health|load|_firmware_liveness_scheduler": (
        "health: reads the scheduler's own health report; publishes nothing"
    ),
    "<module>|import|FirmwareConfirmationCoordinator": (
        "imported to build the grant-side confirmation coordinator"
    ),
    "<module>|import|FirmwareConfirmationReconciler": (
        "imported to build the grant-side confirmation reconciler"
    ),
    "OriRuntime.__init__|load|FirmwareConfirmationCoordinator": (
        "the coordinator attribute's annotation"
    ),
    "OriRuntime.__init__|load|FirmwareConfirmationReconciler": (
        "the reconciler attribute's annotation"
    ),
    "OriRuntime.__init__|store|_firmware_confirmation_coordinator": (
        "declares the coordinator absent until evidence is configured"
    ),
    "OriRuntime.__init__|store|_firmware_confirmation_reconciler": (
        "declares the reconciler absent until evidence is configured"
    ),
    "OriRuntime.start|load|FirmwareConfirmationCoordinator": (
        "lifecycle: builds the coordinator over the evidence confirmation "
        "backend when evidence is configured"
    ),
    "OriRuntime.start|load|FirmwareConfirmationReconciler": (
        "lifecycle: builds the reconciler that retries pending grant confirmations"
    ),
    "OriRuntime.start|store|_firmware_confirmation_coordinator": (
        "lifecycle: holds the coordinator for the grant side"
    ),
    "OriRuntime.start|store|_firmware_confirmation_reconciler": (
        "lifecycle: holds the reconciler for the grant side"
    ),
    "OriRuntime.start|load|_firmware_confirmation_reconciler": (
        "lifecycle: starts the reconciler's background retry loop, which "
        "confirms new epochs and decides no action"
    ),
    "OriRuntime.start|load|_drain_pending_firmware_confirmations": (
        "startup: drains pending grant confirmations once, before any event is "
        "dispatched"
    ),
    "OriRuntime.start|load|_reconcile_pending_attestations": (
        "startup: re-signs evidence rows of actions that already executed; a "
        "record of the past, never a precondition"
    ),
    "OriRuntime.start|load|_nudge_firmware_confirmations": (
        "lifecycle: hands the telemetry subscriber a callback that wakes the "
        "reconciler on reconnect"
    ),
    "OriRuntime._drain_pending_firmware_confirmations|load|FirmwareConfirmationReconciler": (
        "grant side: a transient reconciler when only a coordinator exists"
    ),
    "OriRuntime._drain_pending_firmware_confirmations|load|_firmware_confirmation_coordinator": (
        "grant side: the coordinator the drain confirms through"
    ),
    "OriRuntime._drain_pending_firmware_confirmations|load|_firmware_confirmation_reconciler": (
        "grant side: the reconciler the drain runs once"
    ),
    "OriRuntime._firmware_source_confirmed|load|_firmware_confirmation_coordinator": (
        "evidence reconciliation of already-executed rows, called only from "
        "_reconcile_pending_attestations"
    ),
    "OriRuntime._nudge_firmware_confirmations|load|_firmware_confirmation_reconciler": (
        "grant side: wakes the reconciler; decides no action"
    ),
    "OriRuntime._reconcile_pending_attestations|load|_firmware_source_confirmed": (
        "startup evidence repair of rows whose actions already executed"
    ),
    "_build_firmware_command_service|load|MqttFirmwareCommandPublisher": (
        "the one construction site of the command transport"
    ),
    "_build_firmware_command_service|load|FirmwareCommandService": (
        "the one construction site of the command service"
    ),
    "_build_firmware_liveness_stack|load|_build_firmware_command_service": (
        "composition root handing the one service to start and the liveness "
        "scheduler, which only signs liveness"
    ),
    "_build_firmware_liveness_stack|load|MqttFirmwareCommandPublisher": (
        "return annotation of the composition root"
    ),
    "_build_firmware_liveness_stack|load|FirmwareCommandService": (
        "return annotation of the composition root"
    ),
}

#: Keys in RUNTIME_TOUCHES that hold more than one touch, with how many. Every
#: other key holds exactly one, so a second touch under a classified key fails
#: until it is looked at.
RUNTIME_TOUCH_COUNTS: dict[str, int] = {
    "OriRuntime._start_firmware_mqtt_operator_if_enabled|str|provisioner_key_env": 2,
    "OriRuntime.approve_firmware_commands|load|_firmware_command_service": 2,
    "OriRuntime.publish_firmware_command|load|_firmware_command_service": 2,
    "OriRuntime.start|load|_firmware_confirmation_reconciler": 2,
    "OriRuntime.start|load|firmware_commands": 2,
    "OriRuntime.stop|load|_firmware_command_publisher": 2,
    "OriRuntime.stop|load|_firmware_mqtt_operator_server": 2,
    "_build_firmware_command_service|load|FirmwareCommandService": 2,
    "_build_firmware_command_service|load|MqttFirmwareCommandPublisher": 2,
}

#: What ``start`` may do with a local holding the command pair, the service,
#: its publisher or the liveness scheduler: hand it to one of these attributes,
#: call one of these lifecycle methods on it, or test it against None.
START_HOLDER_ATTRIBUTES = (
    "_firmware_command_service",
    "_firmware_command_publisher",
    "_firmware_liveness_scheduler",
)
START_LIFECYCLE_METHODS = ("connect", "serve_until")


#: How a reading says it came from firmware: the keys the telemetry gate sets on
#: an accepted reading, and the helpers that read them. A decision keyed on any
#: of these is keyed on provenance, which no dispatch may be.
PROVENANCE_MARKERS = (
    "firmware",
    "firmware_device_id",
    "attestation",
    "posture",
    "boot_id",
    "capability_hash",
    "device_uptime_ms",
    "device_emitted_at_ms",
)
PROVENANCE_HELPERS = ("_input_firmware_freshness", "_input_attestation_evidence")

#: Every touch on a provenance marker on the action path, keyed
#: ``path::qualified scope::marker``. Stale entries fail.
PROVENANCE_TOUCHES: dict[str, str] = {
    "ori/reasoning/action_dispatcher.py::_input_attestation_evidence::attestation": (
        "copies the reading's attestation grade into the evidence row"
    ),
    "ori/reasoning/action_dispatcher.py::_input_attestation_evidence::posture": (
        "copies the reading's posture into the evidence row"
    ),
    "ori/reasoning/action_dispatcher.py::_input_firmware_freshness::firmware": (
        "recognises a firmware reading to copy its freshness identity into the "
        "evidence row"
    ),
    "ori/reasoning/action_dispatcher.py::_input_firmware_freshness"
    "::firmware_device_id": "copies the source device into the evidence row",
    "ori/reasoning/action_dispatcher.py::_input_firmware_freshness::boot_id": (
        "copies the source boot into the evidence row"
    ),
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._log_action"
    "::_input_attestation_evidence": (
        "evidence row assembly, after this action's executor has run"
    ),
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._log_action"
    "::_input_firmware_freshness": (
        "evidence row assembly, after this action's executor has run"
    ),
}


# ── Source helpers ──────────────────────────────────────────────────────────


def _python_files(*relative: str) -> list[Path]:
    """Source under each directory, asserting every one of them is non-empty."""
    files: list[Path] = []
    for directory in relative:
        found = sorted((ROOT / directory).rglob("*.py"))
        assert found, (
            f"no Python source under {directory}; it was renamed or removed, and "
            "the scan would pass without looking at it. Update ACTION_PATH."
        )
        files.extend(found)
    return files


def _rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _module_name(path: Path) -> str:
    parts = list(path.relative_to(ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _package_of(path: Path) -> list[str]:
    parts = _module_name(path).split(".")
    return parts if path.name == "__init__.py" else parts[:-1]


def _docstring_ids(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(
            node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef
        ):
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                ids.add(id(body[0].value))
    return ids


def _scoped_nodes(tree: ast.AST) -> Iterator[tuple[str, ast.AST]]:
    """Every node with its qualified scope; each lambda is its own scope."""

    def walk(node: ast.AST, scope: list[str]) -> Iterator[tuple[str, ast.AST]]:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
                inner = [*scope, child.name]
            elif isinstance(child, ast.Lambda):
                inner = [*scope, "<lambda>"]
            else:
                inner = scope
            yield (".".join(inner) or "<module>"), child
            yield from walk(child, inner)

    yield from walk(tree, [])


def _word(name: str, text: str) -> bool:
    return (
        re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text)
        is not None
    )


def _surface_touches(
    tree: ast.AST, names: tuple[str, ...]
) -> Iterator[tuple[str, str, str, int]]:
    """(scope, kind, name, line) for every touch on *names*."""
    docstrings = _docstring_ids(tree)
    for scope, node in _scoped_nodes(tree):
        if isinstance(node, ast.Attribute) and node.attr in names:
            yield scope, type(node.ctx).__name__.lower(), node.attr, node.lineno
        elif isinstance(node, ast.Name) and node.id in names:
            yield scope, type(node.ctx).__name__.lower(), node.id, node.lineno
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in names:
                    yield scope, "import", alias.name, node.lineno
        elif (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and id(node) not in docstrings
        ):
            for name in names:
                if _word(name, node.value):
                    yield scope, "str", name, node.lineno


def _resolved_imports(tree: ast.AST, path: Path) -> Iterator[tuple[str, int]]:
    """Every module a file imports or reaches by dotted attribute, resolved."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    head = alias.name.split(".")[0]
                    aliases[head] = head
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                package = _package_of(path)
                base_parts = package[: len(package) - (node.level - 1)]
                base = ".".join([*base_parts, *([node.module] if node.module else [])])
            else:
                base = node.module or ""
            yield base, node.lineno
            for alias in node.names:
                yield f"{base}.{alias.name}", node.lineno
                aliases[alias.asname or alias.name] = f"{base}.{alias.name}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            chain: list[str] = []
            current: ast.AST = node
            while isinstance(current, ast.Attribute):
                chain.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name) and current.id in aliases:
                yield ".".join([aliases[current.id], *reversed(chain)]), node.lineno


def _defined_in(dotted: str) -> str | None:
    """Where the object an ``ori`` dotted name resolves to is defined.

    A name re-exported by another module (``from ori.runtime import
    FirmwareCommandService``) is judged by the object, not by the path.
    """
    if not dotted.startswith("ori."):
        return None
    parts = dotted.split(".")
    for cut in range(len(parts), 0, -1):
        try:
            value: Any = importlib.import_module(".".join(parts[:cut]))
        except ImportError:
            continue
        try:
            for attr in parts[cut:]:
                value = getattr(value, attr)
        except AttributeError:
            return None
        if isinstance(value, types.ModuleType):
            return value.__name__
        home = getattr(value, "__module__", None)
        return home if isinstance(home, str) else type(value).__module__
    return None


def _is_authority_module(module: str) -> bool:
    return any(
        module == target or module.startswith(f"{target}.")
        for target in FIRMWARE_AUTHORITY_MODULES
    )


# ── Behavioural guard ───────────────────────────────────────────────────────

DEVICE = "fw-boundary-runtime"
SENSOR = "cpu-sensor"
#: One approved firmware device per epoch state that is not confirmed, each
#: planted in the store before the runtime opens it: a pending obligation, a
#: quarantined one, and an approval with no obligation row at all. None of them
#: may change what any dispatch does.
FIRMWARE_DEVICES: dict[str, str | None] = {
    "ori-fw-pending": "confirmation_pending",
    "ori-fw-quarantined": "quarantined",
    "ori-fw-unrowed": None,
}

#: A dispatch's provenance: None for a local reading, else a firmware device.
SOURCES: tuple[str | None, ...] = (None, *FIRMWARE_DEVICES)
REPEATS = 3


def _epoch(device: str) -> str:
    return f"epoch-{device}"


PROPOSAL_ID = "FWB00001"
RUNTIME_KEY_ENV = "ORI_TEST_FWB_RUNTIME_COMMAND_SEED"
PROVISIONER_KEY_ENV = "ORI_TEST_FWB_PROVISIONER_SEED"

#: Where the gate lives, and the query that is the gate.
GATE_SOURCES = ("ori/security/firmware", "ori/gateway/firmware_commands.py")
GATE_QUERY = "get_firmware_confirmation_status"

#: Egress whose own body need not consult the gate: every function in the
#: gate's modules named for signing or publishing, derived from source. It
#: signs or publishes bytes it is handed, so reaching it from an action is a
#: firmware command that skipped the gate altogether. The liveness signer holds
#: the same runtime command key, so it signs command bytes as readily.
EGRESS_NAME = re.compile(r"^_?(sign|publish)")

#: Egress the derivation must find, so it cannot pass while empty.
KNOWN_EGRESS = {
    ("ori.security.firmware.commands", "FirmwareCommandSigner", "sign_command_bytes"),
    ("ori.security.firmware.liveness", "FirmwareLivenessSigner", "sign_liveness_bytes"),
    ("ori.security.firmware.liveness", "FirmwareLivenessSigner", "sign_liveness"),
    ("ori.gateway.firmware_commands", "MqttFirmwareCommandPublisher", "_publish"),
    ("ori.security.firmware.commands", None, "build_provisioning_approval_bytes"),
    (
        "ori.gateway.firmware_commands",
        "MqttFirmwareCommandPublisher",
        "publish_runtime_liveness",
    ),
    (
        "ori.gateway.firmware_commands",
        "MqttFirmwareCommandPublisher",
        "publish_command",
    ),
    (
        "ori.gateway.firmware_commands",
        "MqttFirmwareCommandPublisher",
        "publish_provisioning_approval",
    ),
}

#: Entry points the derivation must find, so it cannot pass while empty.
KNOWN_GATE_ENTRIES = {
    ("ori.security.firmware.commands", "FirmwareCommandSigner", "sign_command"),
    ("ori.gateway.firmware_commands", "FirmwareCommandService", "publish_command"),
    (
        "ori.gateway.firmware_commands",
        "FirmwareCommandService",
        "publish_provisioning_approval",
    ),
    (
        "ori.gateway.firmware_commands",
        "FirmwareCommandService",
        "_require_approved_device",
    ),
}

#: Where each registered executor ends. An executor that returns before its
#: leaf never ran the code a gate call could sit behind, so reaching the leaf
#: is what makes "no sentinel fired" mean something. A new executor fails
#: until it names its leaf here.
EXECUTOR_LEAVES: dict[str, str] = {
    "alert_sms": "AlertFailoverSender.send",
    "alert_whatsapp": "AlertFailoverSender.send",
    "coap_command": "CoAPAction.execute_command",
    "terminate_process": "ProcessManagerAction.terminate_process",
    "reset_kernel_subsystem": "SystemControlAction.reset_kernel_subsystem",
    "log_to_dashboard": "LoggerAction.log_override",
    "trip_relay": "CommissionedActuator.command",
    "release_relay": "CommissionedActuator.command",
    "close_gas_valve": "CommissionedActuator.command",
}

#: The commissioned outcome each relay action must drive: an act reported
#: executed is held to having driven its own outcome, observed at the leaf.
OUTCOME_LEAVES: dict[str, str] = {
    "trip_relay": "CommissionedActuator.command(open_protected_circuit)",
    "close_gas_valve": "CommissionedActuator.command(open_protected_circuit)",
    "release_relay": "CommissionedActuator.command(close_protected_circuit)",
}


#: The coil itself, beneath the actuator: every relay act must reach it.
COIL_LEAF = "RelayAction.coil("


def _is_ask(leaf: str) -> bool:
    """Whether a leaf record carries what the leaf was asked to do."""
    return leaf.endswith(("]", ")"))


COAP_COMMAND = "boundary_probe"
APPROVAL_INTENT = "'tier_c_approval'"
LATE_WORK_TIMEOUT_S = 10.0
#: Timing bounds on one dispatch: how much slower a firmware-sourced dispatch
#: may be than the same dispatch from a local reading, and how long any may
#: take. Both sit two orders of magnitude above the measured cost.
FIRMWARE_DELAY_BOUND_S = 0.25
DISPATCH_BOUND_S = 0.75
OUTSIDE = "outside any probe window"
LATE = "after its window closed"
#: How long a test waits, after its last dispatch, for an act handed to a
#: later task to land before asserting none did.
SETTLE_S = 0.5

#: Set while an executor or a dispatch under test runs, to label what a
#: sentinel records. Recording never depends on it: work handed to a task
#: started elsewhere is recorded under OUTSIDE.
_WINDOW: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "firmware_boundary_window", default=None
)


class _GateReachedError(Exception):
    """Raised by a sentinel; recorded before it is raised, so a caller that
    swallows it is still seen."""


def _names_in(node: ast.AST) -> set[str]:
    return {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(node) if isinstance(n, ast.Name)
    }


def _gate_methods() -> list[tuple[str, str | None, str]]:
    """Every function in the gate's modules that reaches the gate query."""
    return _reaching(GATE_SOURCES, GATE_QUERY)


def _egress_methods() -> list[tuple[str, str | None, str]]:
    """Every function in the gate's modules named for signing or publishing,
    or that calls a ``sign`` method itself."""
    return sorted(
        (
            (module, owner, name)
            for module, owner, name, used in _functions(GATE_SOURCES)
            if EGRESS_NAME.match(name) or "sign" in used
        ),
        key=str,
    )


#: The evidence side of the gate's question: which epoch a signed
#: confirmation proved active. The production coordinator's chain is this.
EVIDENCE_SOURCES = ("ori/security/evidence",)
EVIDENCE_QUERY = "active_anchor_epoch_id"
EVIDENCE_TABLE = "evidence_device_epochs"
EVIDENCE_LEDGER = ("ori/security/evidence/ledger.py", "EvidenceDeliveryLedger")


def _evidence_reader_methods() -> list[tuple[str, str | None, str]]:
    """Every evidence function over the confirmed-epoch record.

    By the query's name and, since a second reader need not share it, by the
    table: every ledger method whose SQL names it, or that calls one.
    """
    relative, owner = EVIDENCE_LEDGER
    module = _module_name(ROOT / relative)
    by_table = {
        (module, owner, name)
        for name in _table_methods(relative, owner, EVIDENCE_TABLE, keep=frozenset())
    }
    return sorted({*_reaching(EVIDENCE_SOURCES, EVIDENCE_QUERY), *by_table}, key=str)


def _functions(
    sources: tuple[str, ...],
) -> list[tuple[str, str | None, str, set[str]]]:
    """(module, class, name, names used) for every function in *sources*."""
    paths: list[Path] = []
    for source in sources:
        path = ROOT / source
        paths.extend(sorted(path.rglob("*.py")) if path.is_dir() else [path])
    functions: list[tuple[str, str | None, str, set[str]]] = []
    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        module = _module_name(path)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                functions.extend(
                    (module, node.name, item.name, _names_in(item))
                    for item in node.body
                    if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
                )
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                functions.append((module, None, node.name, _names_in(node)))
    return functions


def _reaching(
    sources: tuple[str, ...], query: str
) -> list[tuple[str, str | None, str]]:
    """Functions in *sources* named *query* or reaching it, by name, to a fixpoint.

    A function is in if it is the query, or its body names the query or any
    function already in. Matching by name over-approximates, which is the safe
    direction for a sentinel.
    """
    functions = _functions(sources)
    reaching = {query}
    found: set[tuple[str, str | None, str]] = set()
    changed = True
    while changed:
        changed = False
        for module, owner, name, names in functions:
            if (module, owner, name) not in found and (
                name == query or names & reaching
            ):
                found.add((module, owner, name))
                reaching.add(name)
                changed = True
    return sorted(found, key=str)


#: The table the gate reads, and the store methods over it that run while the
#: store opens, before any action can exist.
OUTBOX_TABLE = "firmware_confirmation_outbox"
OUTBOX_OPEN_METHODS = frozenset(
    {
        "open",
        "_open_sync",
        "_migrate_sync",
        "_backfill_firmware_confirmation_obligations_on_conn",
    }
)


def _outbox_methods() -> list[str]:
    """Every StateStore method that reads or writes the gate's table.

    The store's open path is left real, and the gate query itself has its own
    recorder that tells a read after execution from one before it.
    """
    found = _table_methods("ori/state/store.py", "StateStore", OUTBOX_TABLE)
    return sorted(found - OUTBOX_OPEN_METHODS - {GATE_QUERY})


def _table_methods(
    relative: str, owner: str, table: str, *, keep: frozenset[str] = OUTBOX_OPEN_METHODS
) -> set[str]:
    """Methods of *owner* whose SQL names *table*, or that call one, to a fixpoint.

    Methods in *keep* are neither included nor followed.
    """
    methods = _class_methods(relative, owner)
    found = {
        name
        for name, method in methods.items()
        if name not in keep
        and any(
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and table in node.value
            for node in ast.walk(method)
        )
    }
    changed = True
    while changed:
        changed = False
        for name, method in methods.items():
            if name not in found and name not in keep and _names_in(method) & found:
                found.add(name)
                changed = True
    return found


#: The production confirmation objects the runtime holds when evidence is
#: configured, by attribute and by class.
CONFIRMATION_OBJECTS = (
    "_firmware_confirmation_coordinator",
    "_firmware_confirmation_reconciler",
    "FirmwareConfirmationCoordinator",
    "FirmwareConfirmationReconciler",
)

#: Lifecycle names too generic to propagate reach by name; each is classified
#: in RUNTIME_TOUCHES instead.
LIFECYCLE_METHODS = frozenset({"__init__", "start", "stop"})


def _class_methods(relative: str, owner: str) -> dict[str, ast.AST]:
    tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
    return {
        item.name: item
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == owner
        for item in node.body
        if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
    }


def _runtime_gate_names() -> tuple[str, ...]:
    """Runtime and dispatcher methods that reach the surface or the gate.

    OriRuntime is followed to a fixpoint from the surface and the confirmation
    objects, lifecycle methods excepted. ActionDispatcher is taken one level
    deep, the methods naming the gate query: its fixpoint is the whole dispatch
    path, whose post-execution attestation read is held by ordering instead.
    """
    methods = _class_methods(RUNTIME, "OriRuntime")
    reaching = {*SURFACE_NAMES, *CONFIRMATION_OBJECTS}
    found: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, method in methods.items():
            if (
                name not in found
                and name not in LIFECYCLE_METHODS
                and _names_in(method) & reaching
            ):
                found.add(name)
                reaching.add(name)
                changed = True
    dispatcher = _class_methods(
        "ori/reasoning/action_dispatcher.py", "ActionDispatcher"
    )
    found.update(
        name for name, method in dispatcher.items() if GATE_QUERY in _names_in(method)
    )
    return tuple(sorted(found - set(SURFACE_NAMES)))


def _all_surface_names() -> tuple[str, ...]:
    return (
        *SURFACE_NAMES,
        *HOLDER_NAMES,
        *CONFIRMATION_OBJECTS,
        *_runtime_gate_names(),
        # The store and evidence methods over the gate's tables, derived, so a
        # new one is scanned the day it is written.
        *_outbox_methods(),
        *(name for _, _, name in _evidence_reader_methods()),
    )


def _write_runtime(tmp_path: Path) -> Path:
    cfg = tmp_path / "ori.yaml"
    cfg.write_text(
        textwrap.dedent(f"""\
            device:
              id: {DEVICE}
              name: Firmware boundary
              location: Test Lab
              deployment_profile: development
            sensors:
              - id: {SENSOR}
                type: cpu_percent
                protocol: psutil
                poll_interval_ms: 100
            skills: []
            reasoning:
              default_tier: rule
            gateway:
              enabled: true
              broker_url: mqtt://127.0.0.1:1
              node_heartbeat:
                enabled: false
              reasoning:
                enabled: false
              firmware_commands:
                enabled: true
                runtime_command_key_env: {RUNTIME_KEY_ENV}
                provisioner_key_env: {PROVISIONER_KEY_ENV}
            actions:
              primary_alert_channel: sms
              operator_contact: "+2348000000001"
              whatsapp:
                enabled: false
              sms:
                enabled: false
              relay:
                enabled: true
                gpio_pin: 26
              coap:
                enabled: true
                allowed_hosts: ["192.0.2.10"]
                commands:
                  {COAP_COMMAND}:
                    uri: "coap://192.0.2.10/probe"
                    method: POST
                    payload: "{{}}"
            database:
              path: {tmp_path / "ori_state.db"}
            logging:
              file: {tmp_path / "ori.log"}
        """),
        encoding="utf-8",
    )
    binding = local_gpio_binding(
        device_id=DEVICE,
        sensor_id=SENSOR,
        gpio_pin=26,
        active_high=False,
        proof_method="actuate_and_observe",
        control_proof_method="commanded_and_observed",
    )
    target = tmp_path / BINDING_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(sign_envelope(binding, EPHEMERAL_SEED)))
    return cfg


_CONTEXTS = itertools.count(1)


def _context(runtime: OriRuntime, *, source: str | None, approval: bool) -> Any:
    """A context every registered executor resolves a target from.

    *source* is None for a local reading, else the firmware device it came from.
    """
    serial = next(_CONTEXTS)
    metadata: dict[str, Any] = {"coap_command": COAP_COMMAND}
    sensor_id = SENSOR
    if source is not None:
        # The keys and sensor id FirmwareTelemetryGate.ingest_telemetry gives
        # an accepted reading, so a check keyed on any of them sees one.
        sensor_id = f"{source}:0"
        metadata |= {
            "source": "firmware",
            "attestation": "attested",
            "posture": "sealed_flash",
            "firmware_device_id": source,
            "boot_id": 1,
            "seq": serial,
            "capability_hash": "sha256:" + "0" * 64,
            "device_uptime_ms": 1_000,
            "device_emitted_at_ms": None,
        }
    reading = SensorReading(
        sensor_id=sensor_id,
        sensor_type="cpu_percent",
        value=99.0,
        unit="percent",
        # Distinct per context, so an alert is never deduplicated before its
        # send and a resource hold never spans two probes.
        timestamp=1_790_000_000_000 + serial,
        quality=1.0,
        metadata=metadata,
    )
    event = OriEvent.from_reading(reading, DEVICE)
    event.event_id = str(uuid.uuid4())
    event.context = {
        "terminate_process": {"pid": 40_000 + serial, "name": "boundary-probe"},
        "reset_kernel_subsystem": "boundary-probe",
    }
    skill = type(
        "_BoundarySkill",
        (),
        {
            "name": "firmware-boundary",
            "config": {"requires_approval": approval},
            "triggers": [],
            "actions": {},
            "first_party": True,
        },
    )()
    return SkillContext(
        skill=skill,
        event=event,
        state_store=runtime._state_store,
        trigger_name="firmware_boundary",
    )


def _result() -> ReasoningResult:
    return ReasoningResult(
        text="boundary probe",
        tier="rule",
        model="",
        tokens_used=0,
        latency_ms=0,
    )


def _unwrap(executor: Any) -> Iterator[Any]:
    """The executor and everything it wraps or closes over, bounded."""
    seen: set[int] = set()
    pending = [executor]
    while pending and len(seen) < 64:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        if isinstance(current, functools.partial):
            pending.extend([current.func, *current.args, *current.keywords.values()])
        wrapped = getattr(current, "__wrapped__", None)
        if wrapped is not None:
            pending.append(wrapped)
        function = getattr(current, "__func__", None)
        if function is not None:
            pending.append(function)
        for cell in getattr(current, "__closure__", None) or ():
            try:
                pending.append(cell.cell_contents)
            except ValueError:
                continue


def _is_firmware_surface(value: Any, runtime: OriRuntime) -> bool:
    if isinstance(
        value,
        FirmwareCommandService | FirmwareCommandSigner | MqttFirmwareCommandPublisher,
    ):
        return True
    owner = getattr(value, "__self__", None)
    name = getattr(getattr(value, "__func__", None), "__name__", "")
    if owner is runtime and name in _all_surface_names():
        return True
    return isinstance(
        owner,
        FirmwareCommandService | FirmwareCommandSigner | MqttFirmwareCommandPublisher,
    )


def _code_names(value: Any) -> set[str]:
    """Names and string constants in a function's code, nested code included."""
    code = getattr(value, "__code__", None)
    names: set[str] = set()
    pending = [code] if isinstance(code, types.CodeType) else []
    while pending:
        current = pending.pop()
        names.update(current.co_names)
        for constant in current.co_consts:
            if isinstance(constant, types.CodeType):
                pending.append(constant)
            elif isinstance(constant, str):
                names.add(constant)
    return names


@dataclass
class _Probe:
    runtime: OriRuntime
    reached: list[str]
    confirmation_reads: list[tuple[str, frozenset[str]]]
    leaf_hits: list[tuple[str, str]] = field(default_factory=list)


@pytest.fixture
async def probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    """A runtime after a real start, with the firmware command service built.

    The sentinels go in before the runtime is constructed, so nothing start
    captures (a bound method, a worker task) can hold the original.
    """
    reached, confirmation_reads = _install_sentinels(monkeypatch)
    engine = _install_engine_recorder(monkeypatch, confirmation_reads)
    cfg = _write_runtime(tmp_path)
    # Every probe epoch is unconfirmed in the store before the runtime opens
    # it, one per state, so a refusal keyed on the table diverges, including
    # one that snapshots the table during startup.
    seed = StateStore(db_path=str(tmp_path / "ori_state.db"))
    await seed.open()
    await seed.close()
    with contextlib.closing(sqlite3.connect(tmp_path / "ori_state.db")) as conn:
        for device, status in FIRMWARE_DEVICES.items():
            if status is None:
                continue
            conn.execute(
                f"INSERT INTO {OUTBOX_TABLE} "
                "(device_id, anchor_epoch_id, status, created_at_ms) "
                "VALUES (?, ?, ?, 1)",
                (device, _epoch(device), status),
            )
        conn.commit()
    monkeypatch.setenv(COMMISSIONING_ANCHOR_ENV, public_key_b64(EPHEMERAL_SEED))
    monkeypatch.setenv(
        RUNTIME_KEY_ENV, base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    )
    monkeypatch.setenv(
        PROVISIONER_KEY_ENV, base64.b64encode(secrets.token_bytes(32)).decode("ascii")
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(MqttFirmwareCommandPublisher, "connect", AsyncMock())
    monkeypatch.setattr(MqttFirmwareCommandPublisher, "close", AsyncMock())

    _withhold_hardware(monkeypatch)
    runtime = OriRuntime(config_path=str(cfg))
    probe_ = _Probe(runtime, reached, confirmation_reads)
    complete = _mark_startup_complete(runtime)
    task = asyncio.ensure_future(runtime.start())
    during = (0, 0)
    try:
        await asyncio.wait_for(asyncio.shield(complete.wait()), timeout=30.0)
        await _drain()
        startup = [*reached, *(label for label, _ in confirmation_reads)]
        assert not startup, (
            f"startup itself reached the firmware gate: {startup}; the probe "
            "cannot tell an action's reach from the runtime's own"
        )
        _assert_simulated_relays(runtime)
        _install_raw_egress_sentinels(runtime, monkeypatch, reached)
        store = os.environ._data  # type: ignore[attr-defined]
        watched = tuple(
            os.environ.encodekey(name)  # type: ignore[attr-defined]
            for name in (RUNTIME_KEY_ENV, PROVISIONER_KEY_ENV)
        )
        monkeypatch.setattr(os.environ, "_data", _EnvWitness(store, watched, reached))
        # The stale-sensor watch alerts on wall-clock time, not on any action;
        # left running it lands an alert in whichever test runs long enough.
        staleness = [
            task
            for task in runtime._background_tasks
            if task.get_name() == "sensor-staleness"
        ]
        assert len(staleness) == 1, "the probe no longer finds the staleness watch"
        staleness[0].cancel()
        engine.arm()
        # The confirmation objects production builds when evidence is
        # configured, so a path through them reaches their sentinels instead
        # of returning early on None. Startup already ran without them.
        coordinator = FirmwareConfirmationCoordinator(
            store=runtime._state_store, chain=ConfirmedEpochReader(cast(Any, None))
        )
        monkeypatch.setattr(runtime, "_firmware_confirmation_coordinator", coordinator)
        monkeypatch.setattr(
            runtime,
            "_firmware_confirmation_reconciler",
            FirmwareConfirmationReconciler(
                store=runtime._state_store, coordinator=coordinator
            ),
        )
        yield probe_
        during = (len(reached), len(confirmation_reads))
    finally:
        await runtime.stop()
        await asyncio.wait_for(task, timeout=30.0)
    # Work an action handed elsewhere may still be running; let it finish, up
    # to a bound, and hold it to the same rule.
    current = asyncio.current_task()
    leftover = [t for t in asyncio.all_tasks() if t is not current and not t.done()]
    if leftover:
        await asyncio.wait(leftover, timeout=LATE_WORK_TIMEOUT_S)
    await _drain()
    late = [*reached[during[0] :], *(r for r, _ in confirmation_reads[during[1] :])]
    assert not late, (
        f"work handed off by an action reached the firmware gate after the test "
        f"body ended: {late}. " + _LIMIT
    )
    acted = [leaf for window, leaf in probe_.leaf_hits if window == LATE]
    assert not acted, (
        f"work handed off by a dispatch acted after it returned: {acted}. What an "
        "act does after its dispatch is never compared across sources. " + _LIMIT
    )


#: Every GPIO backend the runtime or its libraries can load. The probe drives
#: trip and release through every route, so on a host that has one it would
#: move a real pin.
GPIO_BACKENDS = ("gpiozero", "lgpio", "RPi", "RPi.GPIO", "pigpio", "gpiod")


def _is_backend(module: str) -> bool:
    return any(
        module == name or module.startswith(f"{name}.") for name in GPIO_BACKENDS
    )


def _withhold_hardware(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run on no hardware, on every platform, and prove it before start.

    The GPIO backends are withheld and CoAP's backend is reported absent, so
    the relay and CoAP take their simulated paths. What is proven is that no
    backend can load, not that none happens to be installed.
    """
    # By package, not by name: a submodule already loaded (gpiozero's own
    # __init__ loads gpiozero.output_devices) imports on its own.
    for name in {*GPIO_BACKENDS, *(key for key in sys.modules if _is_backend(key))}:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setattr("ori.actions.coap._aiocoap", None)
    monkeypatch.setattr("ori.actions.coap._AIOCOAP_AVAILABLE", False)
    loadable = []
    for name in GPIO_BACKENDS:
        try:
            importlib.import_module(name)
        except ImportError:
            continue
        loadable.append(name)
    loaded = [key for key, module in sys.modules.items() if _is_backend(key) and module]
    assert not loadable and not loaded, (
        f"GPIO backends still load: {loadable or loaded}; the probe would drive "
        "real pins"
    )
    assert not coap_backend_available(), "the CoAP backend is still available"


def _assert_simulated_relays(runtime: OriRuntime) -> None:
    """Before any action path runs: every relay in the process is simulated."""
    actuator = runtime._commissioned_actuator
    relays = [value for value in gc.get_objects() if isinstance(value, RelayAction)]
    real = [
        relay for relay in relays if not relay.is_simulated or relay._device is not None
    ]
    assert actuator is not None and relays and not real, (
        f"a relay holds a hardware device ({len(real)} of {len(relays)}), or the "
        "commissioned relay was not built; no action path may run"
    )
    assert any(actuator._driver is relay for relay in relays), (
        "the commissioned actuator does not drive a relay this probe verified"
    )


class _EnvWitness(dict):  # type: ignore[type-arg]
    """os.environ's own store, recording every read of an authority key.

    Installed as ``os.environ._data``, which ``os.environb`` shares on POSIX, so
    a reference bound before the probe, ``os.getenv``, iteration and copies
    all read through it. The keys are loaded at start; a later read is code
    deriving the key again, which signs with no service at all."""

    def __init__(
        self, real: dict, watched: tuple[object, ...], reached: list[str]
    ) -> None:  # type: ignore[type-arg]
        super().__init__(real)
        self._watched = watched
        self._reached = reached

    def _seen(self, key: object) -> None:
        if key in self._watched:
            window = _WINDOW.get()
            self._reached.append(
                f"{window['label'] if window else OUTSIDE}: environment {key!r}"
            )

    def __getitem__(self, key: object) -> Any:
        self._seen(key)
        return super().__getitem__(key)

    def get(self, key: object, default: Any = None) -> Any:
        self._seen(key)
        return super().get(key, default)

    def copy(self) -> dict:  # type: ignore[type-arg]
        for key in self._watched:
            self._seen(key)
        return dict(super().items())


class _RawEgressSentinel:
    """Stands in for a signing key or the transport's client: any use records."""

    def __init__(self, where: str, reached: list[str]) -> None:
        self._where = where
        self._reached = reached

    def __getattr__(self, name: str) -> Any:
        window = _WINDOW.get()
        self._reached.append(
            f"{window['label'] if window else OUTSIDE}: {self._where}.{name}"
        )
        raise _GateReachedError(f"{self._where}.{name}")


def _install_raw_egress_sentinels(
    runtime: OriRuntime, monkeypatch: pytest.MonkeyPatch, reached: list[str]
) -> None:
    """Replace the keys and the client beneath the named egress methods.

    Found by walking the objects the runtime holds for command egress, so a
    signature made with the key itself, or a publish on the client, records.
    """
    roots = [
        getattr(runtime, name, None)
        for name in (*HOLDER_NAMES, "_firmware_command_service")
    ]
    seen: set[int] = set()
    pending = [root for root in roots if root is not None]
    keys = clients = 0
    while pending:
        current = pending.pop()
        if id(current) in seen or not type(current).__module__.startswith("ori."):
            continue
        seen.add(id(current))
        for name, value in list(vars(current).items()):
            where = f"{type(current).__name__}.{name}"
            if isinstance(value, Ed25519PrivateKey):
                monkeypatch.setattr(current, name, _RawEgressSentinel(where, reached))
                keys += 1
            elif (
                isinstance(current, MqttFirmwareCommandPublisher) and name == "_client"
            ):
                monkeypatch.setattr(current, name, _RawEgressSentinel(where, reached))
                clients += 1
            elif type(value).__module__.startswith("ori."):
                pending.append(value)
    assert keys and clients, (
        f"found {keys} signing keys and {clients} transport clients under the "
        "runtime's command egress; the walk no longer reaches them"
    )


def _install_sentinels(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[str], list[tuple[str, frozenset[str]]]]:
    """Replace every gate entry point and egress with a recording sentinel."""
    reached: list[str] = []
    confirmation_reads: list[tuple[str, frozenset[str]]] = []

    for module, owner_name, name in [
        *_gate_methods(),
        *_evidence_reader_methods(),
        *_egress_methods(),
    ]:
        owner: Any = importlib.import_module(module)
        if owner_name is not None:
            owner = getattr(owner, owner_name)
        where = f"{module}.{owner_name}.{name}" if owner_name else f"{module}.{name}"

        def _sentinel(*_: Any, _where: str = where, **__: Any) -> Any:
            window = _WINDOW.get()
            reached.append(f"{window['label'] if window else OUTSIDE}: {_where}")
            raise _GateReachedError(_where)

        monkeypatch.setattr(owner, name, _sentinel)

    for name in _outbox_methods():

        def _table_sentinel(
            *_: Any, _where: str = f"StateStore.{name}", **__: Any
        ) -> Any:
            window = _WINDOW.get()
            reached.append(f"{window['label'] if window else OUTSIDE}: {_where}")
            raise _GateReachedError(_where)

        monkeypatch.setattr(StateStore, name, _table_sentinel)

    async def _confirmation_status(
        _self: Any, device_id: str = "", *_: Any, **__: Any
    ) -> str | None:
        window = _WINDOW.get()
        confirmation_reads.append(
            (window["label"], window["executed"]) if window else (OUTSIDE, frozenset())
        )
        # Answer with the seeded state rather than raise, so code that keeps or
        # acts on the answer (a cache, a later refusal) is driven by it.
        return FIRMWARE_DEVICES.get(str(device_id))

    monkeypatch.setattr(
        StateStore, "get_firmware_confirmation_status", _confirmation_status
    )

    real_get_device = StateStore.get_firmware_device

    async def _get_device(self: StateStore, device_id: str) -> dict | None:
        if device_id in FIRMWARE_DEVICES:
            return {
                "device_id": device_id,
                "anchor_epoch_id": _epoch(device_id),
                "approved": True,
                "revoked": False,
            }
        return await real_get_device(self, device_id)

    monkeypatch.setattr(StateStore, "get_firmware_device", _get_device)
    return reached, confirmation_reads


#: Tables whose reads the engine recorder reports: the gate's, and the
#: evidence side's record of confirmed epochs.
ENGINE_TABLES = frozenset({OUTBOX_TABLE, EVIDENCE_TABLE})


class _EngineRecorder:
    """Reads of the confirmation tables, recorded by SQLite's authorizer.

    A view, a helper, or a table name built at runtime all resolve to the base
    table here, whatever the SQL is called from.
    """

    def __init__(self, reads: list[tuple[str, frozenset[str]]]) -> None:
        self.reads = reads
        self.armed = False
        # Strong references: a Connection takes no weak reference, and the
        # authorizer cannot be set inside the audit hook that reports it.
        self.connections: list[sqlite3.Connection] = []

    def authorize(self, action: int, table: str | None, *_: str | None) -> int:
        if self.armed and action == sqlite3.SQLITE_READ and table in ENGINE_TABLES:
            window = _WINDOW.get()
            self.reads.append(
                (f"{window['label']} (engine)", window["executed"])
                if window
                else (f"{OUTSIDE} (engine)", frozenset())
            )
        return sqlite3.SQLITE_OK

    def adopt(self) -> None:
        """Authorize every connection the audit hook has seen open."""
        for conn in self.connections:
            try:
                conn.set_authorizer(self.authorize)
            except sqlite3.ProgrammingError:
                continue  # closed, or owned by another thread

    def arm(self) -> None:
        self.armed = True
        self.adopt()


#: The recorder the process-wide audit hook feeds. Audit hooks cannot be
#: removed, so the hook is installed once and does nothing while this is None.
_ENGINE: dict[str, _EngineRecorder | None] = {"active": None}
_ENGINE_HOOK_INSTALLED: list[bool] = []


def _engine_audit(event: str, args: tuple[Any, ...]) -> None:
    recorder = _ENGINE["active"]
    if recorder is not None and event == "sqlite3.connect/handle" and args:
        recorder.connections.append(args[0])


def _install_engine_recorder(
    monkeypatch: pytest.MonkeyPatch, reads: list[tuple[str, frozenset[str]]]
) -> _EngineRecorder:
    """Record every read of the confirmation tables at the SQLite engine.

    A connection opened through ``sqlite3.connect`` gets the authorizer at once
    and has statement caching off, so every execution is authorized, not only
    the first prepare. One opened any other way (a ``connect`` bound before
    this, or a Connection constructed directly) is reported by the audit hook
    and authorized at arming and at every window entry.
    """
    recorder = _EngineRecorder(reads)
    if not _ENGINE_HOOK_INSTALLED:
        sys.addaudithook(_engine_audit)
        _ENGINE_HOOK_INSTALLED.append(True)
    monkeypatch.setitem(_ENGINE, "active", recorder)
    real_connect = sqlite3.connect

    def _connect(*args: Any, **kwargs: Any) -> sqlite3.Connection:
        kwargs["cached_statements"] = 0
        conn = real_connect(*args, **kwargs)
        conn.set_authorizer(recorder.authorize)
        return conn

    monkeypatch.setattr(sqlite3, "connect", _connect)
    return recorder


def _open_window(label: str) -> contextvars.Token[dict[str, Any] | None]:
    """Enter a probe window, authorizing any connection opened since the last."""
    recorder = _ENGINE["active"]
    if recorder is not None and recorder.armed:
        recorder.adopt()
    # "executed" names every action whose executor has returned in this
    # window, so a read is ordered against the act it could delay, not
    # against whatever ran first.
    return _WINDOW.set({"label": label, "executed": frozenset()})


def _close_window(token: contextvars.Token[dict[str, Any] | None]) -> None:
    """Leave a probe window. Work it handed to another task still carries it,
    now closed, so a leaf that task reaches records as LATE."""
    window = _WINDOW.get()
    if window is not None:
        window["closed"] = True
    _WINDOW.reset(token)


async def _drain() -> None:
    """Let work handed to other tasks run before anything is asserted."""
    for _ in range(50):
        await asyncio.sleep(0)


def _fold(text: str) -> str:
    """A leaf's text with what legitimately differs between probe contexts
    replaced: the reading's sensor and source device, and the runtime's clock."""
    for device in FIRMWARE_DEVICES:
        text = text.replace(f"{device}:0", "<sensor>").replace(device, "<source>")
    text = text.replace(SENSOR, "<sensor>")
    text = re.sub(r"\b\d{1,2}:\d{2}\b", "<hh:mm>", text)
    return re.sub(r"\b(Mon|Tues|Wednes|Thurs|Fri|Satur|Sun)day\b", "<day>", text)


class _InstanceTags:
    """A stable tag per leaf object, in first-seen order, so a record says which
    relay, actuator or sender was asked, not only what. Holds each object, so
    an id is never reused for another."""

    def __init__(self) -> None:
        self._held: dict[int, tuple[int, Any]] = {}

    def __call__(self, leaf_object: Any) -> str:
        entry = self._held.setdefault(
            id(leaf_object), (len(self._held) + 1, leaf_object)
        )
        return f"#{entry[0]}"


class _CoilWitness:
    """The simulated relay's coil state, recording every write.

    Installed on RelayAction, beneath every actuator method and driver call, so
    a coil driven by any route records which relay was driven, and to what."""

    def __init__(self, record: Any, tag: _InstanceTags) -> None:
        self._record = record
        self._tag = tag

    def __get__(self, relay: Any, owner: type | None = None) -> Any:
        if relay is None:
            return self
        state = vars(relay)
        return state.get("_witnessed_sim_state", state.get("_sim_state", False))

    def __set__(self, relay: Any, value: bool) -> None:
        state = "energised" if value else "de_energised"
        self._record(f"RelayAction.coil({self._tag(relay)}, {state})")
        vars(relay)["_witnessed_sim_state"] = value


def _install_leaves(
    monkeypatch: pytest.MonkeyPatch, probe: _Probe
) -> list[tuple[str, str]]:
    """Record where each executor ends, and what it asked; nothing leaves the host.

    Leaves that would act on the host or a network are replaced; the relay and
    the dashboard log keep their real bodies, since both are simulated here. A
    record made after its window closed is labelled LATE: an act nothing
    compared.
    """
    hits = probe.leaf_hits
    tag = _InstanceTags()

    def _record(leaf: str) -> None:
        window = _WINDOW.get()
        if window is None:
            hits.append((OUTSIDE, leaf))
        elif window.get("closed"):
            hits.append((LATE, f"after {window['label']}: {leaf}"))
        else:
            hits.append((window["label"], leaf))

    async def _send(self: Any, *args: Any, **kwargs: Any) -> AlertSendReceipt:
        _record("AlertFailoverSender.send")
        named = dict(zip(("alert", "to_number"), args, strict=False)) | kwargs
        alert = named.get("alert")
        _record(
            "AlertFailoverSender.send"
            + _fold(
                repr(
                    [
                        tag(self),
                        getattr(getattr(alert, "intent", None), "value", None),
                        getattr(alert, "sms_body", None),
                        getattr(alert, "template_variables", None),
                        sorted((k, v) for k, v in named.items() if k != "alert"),
                    ]
                )
            )
        )
        channel = str(kwargs.get("preferred_channel") or kwargs.get("channel") or "sms")
        return AlertSendReceipt.accepted_without_provider_receipt(channel=channel)

    async def _accept(_self: Any, *args: Any, _leaf: str, **kwargs: Any) -> bool:
        _record(_leaf)
        # What the leaf was asked to do, positional and named, with the
        # per-context pid folded, so the same route from two sources must ask
        # for the same act.
        asked = sorted(
            [(f"#{index}", value) for index, value in enumerate(args)]
            + [
                (key, "probe-pid" if key == "pid" else value)
                for key, value in kwargs.items()
            ]
        )
        _record(f"{_leaf}@{tag(_self)}{asked}")
        return True

    async def _sms(self: Any, *args: Any, **kwargs: Any) -> bool:
        # The dispatcher's emergency SMS, sent directly rather than through
        # the failover sender.
        _record("SMSAction.send")
        named = dict(zip(("message", "to_number"), args, strict=False)) | kwargs
        _record(f"SMSAction.send@{tag(self)}{_fold(repr(sorted(named.items())))}")
        return True

    monkeypatch.setattr(AlertFailoverSender, "send", _send)
    monkeypatch.setattr(AlertFailoverSender, "send_exact", _send)
    monkeypatch.setattr(SMSAction, "send", _sms)
    for owner, name in (
        (CoAPAction, "execute_command"),
        (ProcessManagerAction, "terminate_process"),
        (SystemControlAction, "reset_kernel_subsystem"),
    ):
        monkeypatch.setattr(
            owner,
            name,
            functools.partialmethod(_accept, _leaf=f"{owner.__name__}.{name}"),
        )

    real_command = CommissionedActuator.command
    real_log = LoggerAction.log_override

    async def _command(self: CommissionedActuator, outcome: str) -> bool:
        _record("CommissionedActuator.command")
        _record(f"CommissionedActuator.command({outcome})")
        _record(f"CommissionedActuator.command@{tag(self)}({outcome})")
        return await real_command(self, outcome)

    def _log(self: LoggerAction, *args: Any, **kwargs: Any) -> Any:
        _record("LoggerAction.log_override")
        _record(
            f"LoggerAction.log_override@{tag(self)}"
            f"{sorted([*enumerate(args), *kwargs.items()], key=str)}"
        )
        return real_log(self, *args, **kwargs)

    monkeypatch.setattr(CommissionedActuator, "command", _command)
    monkeypatch.setattr(LoggerAction, "log_override", _log)
    monkeypatch.setattr(
        RelayAction, "_sim_state", _CoilWitness(_record, tag), raising=False
    )
    return hits


def _late(hits: list[tuple[str, str]]) -> list[str]:
    """Leaf records made after their window closed, or outside any window."""
    return [leaf for window, leaf in hits if window in (LATE, OUTSIDE)]


def test_the_gate_derivation_finds_the_known_entry_points() -> None:
    """The sentinel set is derived, so it must at least hold what is known."""
    derived = set(_gate_methods())
    missing = sorted(KNOWN_GATE_ENTRIES - derived, key=str)
    assert not missing, (
        f"the gate derivation lost known entry points: {missing}; the sentinels "
        "would leave them unwatched"
    )
    table = set(_outbox_methods())
    expected = {
        "_get_firmware_confirmation_status_sync",
        "list_pending_firmware_confirmations",
        "get_firmware_confirmation_summary",
        "record_firmware_confirmation_attempt",
        "resolve_firmware_confirmation",
    }
    assert expected <= table, (
        f"the store's methods over {OUTBOX_TABLE} were not all derived: "
        f"{sorted(expected - table)}"
    )
    assert not table & OUTBOX_OPEN_METHODS
    for name in table:
        assert callable(getattr(StateStore, name, None)), f"StateStore.{name}"
    egress = set(_egress_methods())
    lost = sorted(KNOWN_EGRESS - egress, key=str)
    assert not lost, (
        f"the egress derivation lost known signing or publishing methods: {lost}"
    )
    for module, owner_name, name in sorted(derived | egress, key=str):
        owner: Any = importlib.import_module(module)
        if owner_name is not None:
            owner = getattr(owner, owner_name)
        assert callable(getattr(owner, name, None)), f"{module}.{owner_name}.{name}"


async def test_the_engine_recorder_sees_every_spelling_of_the_read(
    probe: _Probe,
) -> None:
    """A view, an aggregate, an existence test and a built name all register."""
    path = str(probe.runtime._state_store._db_path)  # type: ignore[union-attr]
    table = "_".join(["firmware", "confirmation", "outbox"])
    statements = {
        "view": (
            f"CREATE TEMP VIEW probe_view AS SELECT * FROM {table}",
            "SELECT status FROM probe_view",
        ),
        "count": ("", f"SELECT count(*) FROM {table}"),
        "exists": ("", f"SELECT EXISTS (SELECT 1 FROM {table})"),
        "select 1": ("", f"SELECT 1 FROM {table} WHERE device_id = 'x'"),
    }
    missed: list[str] = []
    for spelling, (setup, query) in statements.items():
        label = f"engine self-check {spelling}"
        before = len(probe.confirmation_reads)
        token = _open_window(label)
        try:
            with contextlib.closing(sqlite3.connect(path)) as conn:
                if setup:
                    conn.execute(setup)
                conn.execute(query).fetchall()
        finally:
            _WINDOW.reset(token)
        if (f"{label} (engine)", frozenset()) not in probe.confirmation_reads[before:]:
            missed.append(spelling)
    # A connection that never went through sqlite3.connect: constructed
    # directly, opened before the window, used inside it.
    for table_name in sorted(ENGINE_TABLES):
        label = f"engine self-check direct Connection {table_name}"
        before = len(probe.confirmation_reads)
        with contextlib.closing(sqlite3.Connection(path)) as conn:
            if table_name == EVIDENCE_TABLE:
                conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {EVIDENCE_TABLE} (device_id TEXT)"
                )
            token = _open_window(label)
            try:
                conn.execute(f"SELECT count(*) FROM {table_name}").fetchall()
            finally:
                _WINDOW.reset(token)
        if (f"{label} (engine)", frozenset()) not in probe.confirmation_reads[before:]:
            missed.append(f"direct Connection {table_name}")
    del probe.confirmation_reads[:]
    assert not missed, f"the engine recorder did not see: {missed}"


async def test_no_registered_executor_is_the_firmware_command_surface(
    probe: _Probe,
) -> None:
    """Identity and code, not reach: covers branches no input here takes."""
    runtime = probe.runtime
    assert runtime._firmware_command_service is not None, (
        "the firmware command service was not built, so this guard would pass "
        "while checking nothing"
    )
    dispatcher = runtime._dispatcher
    assert dispatcher is not None
    assert "trip_relay" in dispatcher._executors, (
        "the commissioned relay executors were not registered; the physical "
        "executors are the ones this guard exists for"
    )
    offenders = [
        f"{action} -> {value!r}"
        for action, executor in sorted(dispatcher._executors.items())
        for value in _unwrap(executor)
        if _is_firmware_surface(value, runtime)
    ]
    assert not offenders, (
        "a registered executor is, wraps, or closes over the firmware command "
        f"surface: {offenders}. An executor reaching it would put the epoch "
        "confirmation gate on an approved Tier C or a Tier D action. " + _LIMIT
    )
    surface = set(_all_surface_names())
    named = sorted(
        f"{action} names {sorted(_code_names(value) & surface)}"
        for action, executor in dispatcher._executors.items()
        for value in _unwrap(executor)
        if _code_names(value) & surface
    )
    assert not named, (
        "a registered executor's code names the firmware command surface, on "
        f"some branch whether or not this test takes it: {named}. " + _LIMIT
    )


async def test_registered_executors_never_reach_the_confirmation_gate(
    probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every executor the runtime registered, invoked through to its leaf."""
    runtime = probe.runtime
    reached, confirmation_reads = probe.reached, probe.confirmation_reads
    assert runtime._firmware_command_service is not None
    dispatcher = runtime._dispatcher
    assert dispatcher is not None
    unmapped = sorted(set(dispatcher._executors) - set(EXECUTOR_LEAVES))
    assert not unmapped, (
        f"registered executors with no leaf in EXECUTOR_LEAVES: {unmapped}. Name "
        "where each one ends, or this test cannot tell that it ran."
    )
    hits = _install_leaves(monkeypatch, probe)

    short: list[str] = []
    asked: dict[str, dict[str | None, list[str]]] = {}
    for action, executor in sorted(dispatcher._executors.items()):
        for source in SOURCES:
            label = f"executor {action} source={source or 'local'}"
            token = _open_window(label)
            try:
                outcome = executor(
                    action, _context(runtime, source=source, approval=False)
                )
                if asyncio.iscoroutine(outcome) or isinstance(outcome, asyncio.Future):
                    await outcome
            except Exception:
                # A sentinel raises; it recorded first, and that is asserted below.
                pass
            finally:
                _close_window(token)
            for leaf in (EXECUTOR_LEAVES[action], OUTCOME_LEAVES.get(action)):
                if leaf is not None and (label, leaf) not in hits:
                    short.append(f"{label} (expected {leaf})")
            asked.setdefault(action, {})[source] = sorted(
                leaf for window, leaf in hits if window == label and _is_ask(leaf)
            )
    await asyncio.sleep(SETTLE_S)
    await _drain()
    changed_act = sorted(
        f"{action} source={source}: {asks[source]} (local {asks[None]})"
        for action, asks in asked.items()
        for source in FIRMWARE_DEVICES
        if asks[source] != asks[None]
    )

    assert not reached, (
        "a registered executor reached firmware command signing or the epoch "
        f"confirmation gate: {reached}. Evidence must not block, delay or gate a "
        "Tier C/D action. " + _LIMIT
    )
    assert not confirmation_reads, (
        "a registered executor read firmware epoch confirmation status: "
        f"{confirmation_reads}. " + _LIMIT
    )
    assert not short, (
        "these executors returned before their leaf, or drove an outcome not "
        "their own, so the absence of a sentinel says nothing about the code "
        f"behind it: {short}. Give the probe context what they resolve a "
        "target from."
    )
    assert not changed_act, (
        "an unconfirmed firmware epoch changed what an executor asked its leaf "
        f"to do: {changed_act}. " + _LIMIT
    )
    assert not _late(hits), (
        "a leaf acted after its executor returned, or outside any executor: "
        f"{_late(hits)}. " + _LIMIT
    )


async def test_every_dispatch_route_leaves_the_gate_alone(
    probe: _Probe, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every registered action through every tier route the dispatcher has."""
    runtime = probe.runtime
    reached, confirmation_reads = probe.reached, probe.confirmation_reads
    assert runtime._firmware_command_service is not None
    dispatcher = runtime._dispatcher
    assert dispatcher is not None
    hits = _install_leaves(monkeypatch, probe)

    class _Attestor:
        """Present so firmware-sourced Tier C/D rows reach attestation."""

        available = True
        public_key_hex = ""
        artifact_version = ""
        protocol_version = ""
        action_event_type = "ACTION_EXECUTED"
        atomic_freshness_available = False

        async def attest_action(self, row: dict) -> int:
            return 1

    monkeypatch.setattr(dispatcher, "_evidence_attestor", _Attestor())
    monkeypatch.setattr(
        "ori.reasoning.action_dispatcher._generate_proposal_id", lambda *_: PROPOSAL_ID
    )
    replies: dict[str, str] = {}

    async def _listen(*args: Any, **kwargs: Any) -> str:
        # What the operator is listened for is part of the act; a reply exists
        # only where a proposal was sent to them in this dispatch.
        window = _WINDOW.get()
        label = window["label"] if window else ""
        hits.append(
            (label, f"listen{sorted([*enumerate(args), *kwargs.items()], key=str)}")
        )
        proposed = any(
            seen == label and APPROVAL_INTENT in leaf
            for seen, leaf in hits
            if leaf.startswith("AlertFailoverSender.send[")
        )
        return replies.get(label, "") if proposed else ""

    monkeypatch.setattr(dispatcher, "_listen_for_response", _listen)
    # Comms available, so a Tier C proposal is sent rather than skipped, and
    # its delivery is compared across sources like any other leaf.
    monkeypatch.setattr(dispatcher, "_tier_c_comms_available", lambda: True)

    for action, executor in list(dispatcher._executors.items()):

        async def _recording(
            name: str, context: Any, _inner: Any = executor, _own: str = action
        ) -> Any:
            try:
                outcome = _inner(name, context)
                if asyncio.iscoroutine(outcome) or isinstance(outcome, asyncio.Future):
                    outcome = await outcome
                return outcome
            finally:
                # The action this executor is registered for, never the name
                # it was called with: a caller cannot relabel the act.
                window = _WINDOW.get()
                if window is not None:
                    window["executed"] = window["executed"] | {_own}

        monkeypatch.setitem(dispatcher._executors, action, _recording)

    routes = (
        ("A", False, None),
        ("B", False, None),
        ("B", True, f"YES-{PROPOSAL_ID}"),
        ("C", False, f"YES-{PROPOSAL_ID}"),
        ("C", False, f"NO-{PROPOSAL_ID}"),
        ("D", False, None),
    )
    executed: list[str] = []
    not_driven: list[str] = []
    read_before: list[str] = []
    # Per route and source, one entry per repeat.
    outcomes: dict[str, dict[str | None, list[tuple[bool, str]]]] = {}
    asked: dict[str, dict[str | None, list[list[str]]]] = {}
    durations: dict[str, dict[str | None, list[float]]] = {}
    clock = asyncio.get_running_loop().time
    for action in sorted(dispatcher._executors):
        for tier, approval, reply in routes:
            route = f"{action} tier={tier} approval={approval} reply={reply}"
            # Local and every firmware source interleaved, repeatedly, so a
            # timing comparison is between neighbours, not between phases.
            for repeat in range(REPEATS):
                for source in SOURCES:
                    label = f"{route} source={source or 'local'} repeat={repeat}"
                    if reply is not None:
                        replies[label] = reply
                    token = _open_window(label)
                    started = clock()
                    try:
                        result = await dispatcher.dispatch(
                            action,
                            tier,
                            _context(runtime, source=source, approval=approval),
                            _result(),
                            approval_timeout_seconds=5,
                        )
                        # The act's record is written after it, off its path;
                        # it belongs to this window, so it lands before the
                        # window closes and before the next one arms the
                        # engine recorder against a connection mid-statement.
                        await dispatcher.drain_records()
                    finally:
                        _close_window(token)
                    spent = clock() - started
                    durations.setdefault(route, {}).setdefault(source, []).append(spent)
                    outcomes.setdefault(route, {}).setdefault(source, []).append(
                        (result.executed, result.action_taken)
                    )
                    asked.setdefault(route, {}).setdefault(source, []).append(
                        sorted(
                            leaf
                            for window, leaf in hits
                            if window == label and _is_ask(leaf)
                        )
                    )
                    if result.executed and result.action_taken in EXECUTOR_LEAVES:
                        # Reported executed is a claim; the leaf is the witness.
                        taken = result.action_taken
                        leaf = OUTCOME_LEAVES.get(taken, EXECUTOR_LEAVES[taken])
                        if (label, leaf) not in hits:
                            not_driven.append(f"{label} (expected {leaf})")
                        if taken in OUTCOME_LEAVES and not any(
                            window == label and hit.startswith(COIL_LEAF)
                            for window, hit in hits
                        ):
                            not_driven.append(f"{label} (expected {COIL_LEAF}...)")
                    if result.executed and result.action_taken == action:
                        executed.append(f"{action}@{result.tier}")
                    if result.executed:
                        read_before.extend(
                            read
                            for read, done in confirmation_reads
                            if read in (label, f"{label} (engine)")
                            and result.action_taken not in done
                        )

    await asyncio.sleep(SETTLE_S)
    await _drain()

    physical = sorted(
        action
        for action in dispatcher._executors
        if (entry := capability(action)) is not None and entry.physical
    )
    assert "trip_relay" in physical
    unexercised = [
        f"{action}@{tier}"
        for action in physical
        for tier in ("C", "D")
        if f"{action}@{tier}" not in executed
    ]
    assert not unexercised, (
        f"{unexercised} never executed, so the approved Tier C and Tier D routes "
        f"were not exercised for them and this guard proves nothing about them: "
        f"{executed}"
    )
    assert not reached, (
        "a dispatch route reached firmware command signing or the epoch "
        f"confirmation gate: {reached}. The gate belongs on granting authority; "
        "evidence must not block, delay or gate a Tier C/D action. " + _LIMIT
    )
    assert not not_driven, (
        "a dispatch reported its action executed without that action's own "
        f"leaf observing it: {not_driven}. " + _LIMIT
    )
    assert not _late(hits), (
        "a leaf acted after its dispatch returned, or outside any dispatch: "
        f"{_late(hits)}. " + _LIMIT
    )
    diverged = sorted(
        f"{route} source={source}: {by_source[source]} (local {by_source[None]})"
        for route, by_source in outcomes.items()
        for source in FIRMWARE_DEVICES
        if by_source[source] != by_source[None]
    )
    assert not diverged, (
        "an unconfirmed firmware epoch changed what a dispatch did: "
        f"{diverged}. Evidence must not block, delay or gate a Tier C/D action. "
        + _LIMIT
    )
    changed_act = sorted(
        f"{route} source={source}: {by_source[source]} (local {by_source[None]})"
        for route, by_source in asked.items()
        for source in FIRMWARE_DEVICES
        if by_source[source] != by_source[None]
    )
    assert not changed_act, (
        "an unconfirmed firmware epoch changed what a leaf was asked to do: "
        f"{changed_act}. " + _LIMIT
    )
    # A delay needs no observable read: it is measured, on the fastest of the
    # interleaved repeats so one scheduling hiccup is not a finding. The bounds
    # sit far above what a dispatch costs on a loaded runner, and the messages
    # print what was measured.
    fastest = {
        route: {source: min(spent) for source, spent in by_source.items()}
        for route, by_source in durations.items()
    }
    gaps = {
        (route, source): by_source[source] - by_source[None]
        for route, by_source in fastest.items()
        for source in FIRMWARE_DEVICES
    }
    widest = max(gaps.values())
    longest = max(max(by_source.values()) for by_source in fastest.values())
    slower = sorted(
        f"{route} source={source}: +{gap:.3f}s"
        for (route, source), gap in gaps.items()
        if gap > FIRMWARE_DELAY_BOUND_S
    )
    assert not slower, (
        "an unconfirmed firmware epoch made a dispatch slower than the same "
        f"dispatch from a local reading by more than {FIRMWARE_DELAY_BOUND_S}s "
        f"(fastest of {REPEATS}): {slower} (widest {widest:.4f}s). " + _LIMIT
    )
    overdue = sorted(
        f"{route} source={source or 'local'}: {spent:.3f}s"
        for route, by_source in fastest.items()
        for source, spent in by_source.items()
        if spent > DISPATCH_BOUND_S
    )
    assert not overdue, (
        f"a dispatch took longer than {DISPATCH_BOUND_S}s on every one of "
        f"{REPEATS} repeats: {overdue} (longest {longest:.4f}s). " + _LIMIT
    )
    assert any(done for _, done in confirmation_reads), (
        "no firmware-sourced dispatch reached evidence attestation after "
        "executing, so the ordering assertion below would pass while observing "
        "nothing"
    )
    assert not read_before, (
        "epoch confirmation status was read before an action that then "
        f"executed: {read_before}. Evidence must not delay a Tier C/D "
        "action. " + _LIMIT
    )
    early = sorted(
        read
        for read, done in confirmation_reads
        if read.startswith(OUTSIDE) or (read.endswith("(engine)") and not done)
    )
    assert not early, (
        f"the gate's table was read before execution, or by work outside any "
        f"dispatch: {early}. " + _LIMIT
    )


# ── Static guards ───────────────────────────────────────────────────────────


def test_the_action_path_does_not_import_firmware_authority() -> None:
    """Imports resolved: relative, aliased, dotted, re-exported, and by string."""
    offenders: list[str] = []
    for path in _python_files(*ACTION_PATH):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for module, line in _resolved_imports(tree, path):
            if _is_authority_module(module):
                offenders.append(f"{_rel(path)}:{line} reaches {module}")
            elif (home := _defined_in(module)) and _is_authority_module(home):
                offenders.append(f"{_rel(path)}:{line} reaches {module}, from {home}")
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and any(
                alias.name == "*" for alias in node.names
            ):
                # A star import names nothing this scan can resolve.
                offenders.append(
                    f"{_rel(path)}:{node.lineno} star-imports {node.module}"
                )
        for scope, _kind, name, line in _surface_touches(
            tree, (*RUNTIME_ONLY_NAMES, *KEY_SOURCE_NAMES)
        ):
            offenders.append(f"{_rel(path)}:{line} {scope} touches {name}")
        docstrings = _docstring_ids(tree)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
            ):
                named = [
                    target
                    for target in (*FIRMWARE_AUTHORITY_MODULES, *FIRMWARE_MODULE_LEAVES)
                    if target in node.value
                ]
                if named:
                    offenders.append(
                        f"{_rel(path)}:{node.lineno} names {named} in a string"
                    )

    assert not offenders, (
        "the action path reaches a module that signs, publishes or confirms "
        f"firmware authority: {offenders}. " + _LIMIT
    )


def _whole_tree_touches() -> dict[str, list[str]]:
    """Every surface touch in ori/ outside runtime.py and the definitions."""
    found: dict[str, list[str]] = {}
    skip = {RUNTIME, *DEFINING_MODULES}
    surface = _all_surface_names()
    for path in _python_files("ori", "skills"):
        rel = _rel(path)
        if rel in skip:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for scope, kind, name, line in _surface_touches(tree, surface):
            found.setdefault(f"{rel}::{scope}::{name}", []).append(f"{kind}@{line}")
    return found


def _on_action_path(rel: str) -> bool:
    return any(rel.startswith(f"{directory}/") for directory in ACTION_PATH)


def test_every_touch_on_the_firmware_surface_is_classified() -> None:
    """Outside runtime.py: classified by exact scope, or permitted operator ingress."""
    unclassified: list[str] = []
    for key, where in sorted(_whole_tree_touches().items()):
        if key in SURFACE_TOUCHES:
            continue
        rel, _scope, name = key.split("::")
        if not _on_action_path(rel) and name in OPERATOR_INGRESS.get(rel, {}):
            continue
        unclassified.append(f"{key} {where}")

    assert not unclassified, (
        "code touches the firmware command surface where nothing classifies it: "
        f"{unclassified}. Every path to it passes the epoch confirmation gate, "
        "which must never sit on a Tier C or Tier D action. "
        "A grant made by an operator belongs in OPERATOR_INGRESS with a reason. "
        + _LIMIT
    )


def _provenance_touches() -> dict[str, list[int]]:
    """Every touch on a provenance marker or helper on the action path."""
    found: dict[str, list[int]] = {}
    for path in _python_files(*ACTION_PATH):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docstrings = _docstring_ids(tree)
        for scope, node in _scoped_nodes(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
                and node.value in PROVENANCE_MARKERS
            ):
                marker = node.value
            elif isinstance(node, ast.Name) and node.id in PROVENANCE_HELPERS:
                marker = node.id
            elif isinstance(node, ast.Attribute) and node.attr in PROVENANCE_HELPERS:
                marker = node.attr
            else:
                continue
            found.setdefault(f"{_rel(path)}::{scope}::{marker}", []).append(node.lineno)
    return found


def test_no_decision_on_the_action_path_is_keyed_on_provenance() -> None:
    """Coordinator, rule engine, safety, hooks: provenance is read only for evidence."""
    found = _provenance_touches()
    unclassified = sorted(
        f"{key} lines {lines}"
        for key, lines in found.items()
        if key not in PROVENANCE_TOUCHES
    )
    assert not unclassified, (
        "code on the action path reads how a reading says it came from firmware, "
        f"where nothing classifies it: {unclassified}. A dispatch keyed on "
        "firmware provenance is what evidence state must never become. Provenance "
        "keyed on the shape of a sensor id, or on any key not in "
        "PROVENANCE_MARKERS, is not seen. " + _LIMIT
    )
    stale = sorted(set(PROVENANCE_TOUCHES) - set(found))
    assert not stale, f"classified provenance touches that no longer exist: {stale}"


def test_the_surface_classification_describes_touches_that_exist() -> None:
    """A classification that outlives its call site hides the next one."""
    stale = sorted(set(SURFACE_TOUCHES) - set(_whole_tree_touches()))
    assert not stale, (
        f"classified touches that no longer exist: {stale}. Remove them, or the "
        "table stops describing the code and starts excusing it."
    )


def test_operator_ingress_is_off_the_action_path_and_grant_only() -> None:
    """The permission covers the grant, from operator ingress, and nothing else."""
    grant = {"approve_firmware_commands", "publish_provisioning_approval"}
    wrong = [
        f"{rel}: {sorted(names)}"
        for rel, names in OPERATOR_INGRESS.items()
        if _on_action_path(rel) or rel == RUNTIME or not set(names) <= grant
    ]
    missing = [rel for rel in OPERATOR_INGRESS if not (ROOT / rel).is_file()]
    assert not wrong, (
        f"operator ingress may call only the grant, off the action path: {wrong}"
    )
    assert not missing, f"operator ingress names modules that do not exist: {missing}"


def _runtime_touches() -> dict[str, list[int]]:
    tree = ast.parse((ROOT / RUNTIME).read_text(encoding="utf-8"))
    found: dict[str, list[int]] = {}
    for scope, kind, name, line in _surface_touches(
        tree, (*_all_surface_names(), *RUNTIME_ONLY_NAMES, *KEY_SOURCE_NAMES)
    ):
        found.setdefault(f"{scope}|{kind}|{name}", []).append(line)
    return found


def test_every_runtime_touch_on_the_firmware_surface_is_classified() -> None:
    """Keyed by qualified scope, so an executor closure is never ``start``."""
    found = _runtime_touches()
    assert found, (
        f"no touch on the firmware command surface was found in {RUNTIME}; the "
        "scan is broken or the service moved, and the inventory enforces nothing"
    )
    unclassified = sorted(
        f"{key} lines {found[key]}" for key in set(found) - set(RUNTIME_TOUCHES)
    )
    assert not unclassified, (
        f"{RUNTIME} touches the firmware command surface where nothing "
        f"classifies it: {unclassified}. An executor closure or a lambda "
        "registered in start is its own scope and is never covered by start. " + _LIMIT
    )
    # A classification covers the touches that exist, not every later one in
    # the same scope.
    recounted = sorted(
        f"{key}: {len(lines)} touches (classified {RUNTIME_TOUCH_COUNTS.get(key, 1)}) "
        f"lines {lines}"
        for key, lines in found.items()
        if key in RUNTIME_TOUCHES and len(lines) != RUNTIME_TOUCH_COUNTS.get(key, 1)
    )
    assert not recounted, (
        f"{RUNTIME} touches the firmware command surface more or less often than "
        f"classified: {recounted}. Classify the new touch, then update "
        "RUNTIME_TOUCH_COUNTS. " + _LIMIT
    )


def test_the_runtime_classification_describes_touches_that_exist() -> None:
    stale = sorted(set(RUNTIME_TOUCHES) - set(_runtime_touches()))
    assert not stale, (
        f"classified runtime touches that no longer exist: {stale}. Remove them, "
        "or the table stops describing the code and starts excusing it."
    )


def _start_function() -> ast.AsyncFunctionDef:
    tree = ast.parse((ROOT / RUNTIME).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "OriRuntime":
            for item in node.body:
                if isinstance(item, ast.AsyncFunctionDef) and item.name == "start":
                    return item
    raise AssertionError(f"OriRuntime.start not found in {RUNTIME}")


def test_every_firmware_attribute_of_the_runtime_is_named() -> None:
    """A new holder of firmware authority is scanned the day it is added."""
    tree = ast.parse((ROOT / RUNTIME).read_text(encoding="utf-8"))
    stored = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.ctx, ast.Store)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
        and node.attr.startswith("_firmware")
    }
    named = {*SURFACE_NAMES, *HOLDER_NAMES, *CONFIRMATION_OBJECTS, *NOT_HOLDERS}
    assert stored, f"no self._firmware* attribute is stored in {RUNTIME}"
    unnamed = sorted(stored - named)
    assert not unnamed, (
        f"runtime attributes with no classification: {unnamed}. Name each in "
        "HOLDER_NAMES if it can reach a key, a command topic or the gate, else in "
        "NOT_HOLDERS with why. An attribute not prefixed _firmware is outside this "
        "check. " + _LIMIT
    )
    stale = sorted(set(NOT_HOLDERS) - stored)
    assert not stale, f"NOT_HOLDERS names attributes that no longer exist: {stale}"


def test_start_holds_the_service_only_in_its_lifecycle_bindings() -> None:
    """A local holding the service may be stored, connected, or None-tested."""
    start = _start_function()
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(start):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node

    holders: set[str] = set()
    for node in ast.walk(start):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Name)
            and node.value.func.id == "_build_firmware_liveness_stack"
        ):
            for target in node.targets:
                elements = target.elts if isinstance(target, ast.Tuple) else [target]
                holders.update(e.id for e in elements if isinstance(e, ast.Name))
    assert holders, (
        "start no longer unpacks _build_firmware_liveness_stack into locals, so "
        "this guard would pass while tracking nothing"
    )
    changed = True
    while changed:
        changed = False
        for node in ast.walk(start):
            if (
                isinstance(node, ast.Assign)
                and isinstance(node.value, ast.Name)
                and node.value.id in holders
            ):
                for target in node.targets:
                    elements = (
                        target.elts if isinstance(target, ast.Tuple) else [target]
                    )
                    for element in elements:
                        if isinstance(element, ast.Name) and element.id not in holders:
                            holders.add(element.id)
                            changed = True

    def nested(node: ast.AST) -> bool:
        current = parents.get(id(node))
        while current is not None and current is not start:
            if isinstance(current, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
                return True
            current = parents.get(id(current))
        return False

    def permitted(node: ast.Name) -> bool:
        parent = parents.get(id(node))
        if isinstance(parent, ast.Compare):
            return (
                parent.left is node
                and len(parent.ops) == 1
                and isinstance(parent.ops[0], ast.IsNot)
                and isinstance(parent.comparators[0], ast.Constant)
                and parent.comparators[0].value is None
            )
        if isinstance(parent, ast.Assign) and parent.value is node:
            return all(
                (
                    isinstance(target, ast.Attribute)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                    and target.attr in START_HOLDER_ATTRIBUTES
                )
                or (
                    isinstance(target, ast.Tuple)
                    and all(isinstance(element, ast.Name) for element in target.elts)
                )
                for target in parent.targets
            )
        if isinstance(parent, ast.Attribute) and parent.value is node:
            call = parents.get(id(parent))
            return (
                parent.attr in START_LIFECYCLE_METHODS
                and isinstance(call, ast.Call)
                and call.func is parent
            )
        return False

    offenders = [
        f"{node.id} at line {node.lineno}"
        + (" inside a nested scope" if nested(node) else "")
        for node in ast.walk(start)
        if isinstance(node, ast.Name)
        and node.id in holders
        and isinstance(node.ctx, ast.Load)
        and (nested(node) or not permitted(node))
    ]
    assert not offenders, (
        "start uses a local holding the firmware command service outside its "
        f"lifecycle bindings: {offenders}. Handing it to an executor, the "
        "dispatcher or a closure puts the epoch confirmation gate within reach "
        "of the action path. " + _LIMIT
    )
