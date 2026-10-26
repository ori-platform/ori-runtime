# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""`OriRuntime.start()` runs ordered stages, and the order is held as data.

Three guards, as `docs/STARTUP_STAGES.md` designs them:

- the order: every constraint names stages that exist and holds in the tuple,
  the safety constraints are the ones the design names, and the checkpoints
  are exactly the four the stop protocol has;
- the context: what each stage declares it reads from the `StartupContext`
  is set by an earlier stage, every field has a later reader, and each
  declaration is what the stage's body does;
- the surface: each stage's context reads, runtime reads, runtime writes and
  runtime calls, closures included, match the inventory below in both
  directions.
"""

from __future__ import annotations

import ast
from collections.abc import Awaitable, Callable

from ori.runtime import OriRuntime
from ori.startup_stages import (
    STARTUP_CHECKPOINTS,
    STARTUP_CONSTRAINTS,
    STARTUP_STAGES,
    StartupContext,
)
from tests.package_layout import runtime_methods

#: The safety orderings between stages, as (later, earlier). Dropping one from
#: the table fails here, so an ordering changes only by editing both.
SAFETY_ORDERINGS = {
    ("safety_envelope", "configuration"),
    ("evidence", "safety_envelope"),
    ("dispatcher", "safety_envelope"),
    ("skills", "dispatcher"),
    ("tier_c_recovery", "dispatcher"),
    ("sensors", "tier_c_recovery"),
    ("sensors", "safety_envelope"),
}

CHECKPOINTS = {"loops", "services", "operator_services", "health_and_reconciliation"}

#: Each stage's runtime surface: (reads, writes, calls). `<self>` is the
#: runtime itself handed to something the stage builds.
SURFACE: dict[str, tuple[set[str], set[str], set[str]]] = {
    "configuration": (
        {"_config_path", "_dotenv_variables"},
        {
            "_config",
            "_config_env_placeholders",
            "_device_id",
            "_device_location",
            "_device_policy_enabled",
            "_device_timezone",
            "_remote_command_lockout_config",
            "_runtime_started_at_ms",
            "_status_indicator",
        },
        set(),
    ),
    "store": (
        {"_state_store"},
        {"_state_store"},
        {"_load_remote_command_lockout_state"},
    ),
    "actions": (
        {"_handle_remote_command", "_handle_remote_command_incident", "_state_store"},
        {"_sms_action"},
        set(),
    ),
    "safety_envelope": (
        {
            "<self>",
            "_commissioning_state",
            "_safety_alert_sink",
            "_safety_commander",
            "_safety_registry",
            "_state_store",
        },
        {
            "_commissioned_actuator",
            "_safety_alert_sink",
            "_safety_commander",
            "_safety_registry",
            "_shipped_profile_digest",
        },
        {"_load_commissioning"},
    ),
    "alerting": (
        {"_safety_alert_sink"},
        {
            "_alert_sender",
            "_operator_contact",
            "_primary_alert_channel",
            "_safety_alert_sink",
            "_secondary_contact",
            "_tier_c_deployment_inputs",
        },
        {"_configure_alert_outbox"},
    ),
    "evidence": (
        {"_evidence_posture_problems", "_state_store"},
        {
            "_evidence_attestor",
            "_evidence_posture_problems",
            "_firmware_confirmation_coordinator",
            "_firmware_confirmation_reconciler",
        },
        set(),
    ),
    "dispatcher": (
        {
            "_binding_seq_in_force",
            "_commissioned_actuator",
            "_firmware_reading_age",
            "_state_store",
            "_tier_c_authority_facts",
        },
        {"_dispatcher", "_firmware_reading_age"},
        {
            "_load_cached_device_policy",
            "_maybe_refresh_remote_device_policy_once",
            "_send_or_queue_alert",
        },
    ),
    "reasoning": (
        {"_config_path", "_firmware_reading_age", "_gateway_ingress"},
        {"_capability_posture_tracker", "_gateway_envelope_state"},
        set(),
    ),
    "event_path": (
        set(),
        {"_deduplicator", "_elevator", "_event_bus", "_skill_reload_lock"},
        set(),
    ),
    "skills": (
        {"_config_path", "_loaded_skills", "_state_store"},
        {"_dispatch_coordinator", "_skill_loader", "_skill_selection", "_skills_dir"},
        {"_binding_view", "reload_skills"},
    ),
    "signals": (
        {"_request_stop"},
        set(),
        {"reload_skills"},
    ),
    "sensor_state": (
        set(),
        {
            "_configured_sensors",
            "_connected_sensor_ids",
            "_last_alert_timestamps_by_channel",
            "_last_alert_timestamps_by_trigger",
            "_measurement_refusal_reason",
            "_measurement_refusals",
            "_measurement_valid_streak",
            "_read_failure_logged_at",
            "_retrying_sensors_announced",
            "_sensor_last_seen_ms",
            "_sensor_poll_interval_ms",
            "_stale_sensor_active",
            "_unconnected_sensors",
        },
        {"_restore_measurement_state"},
    ),
    "tier_c_recovery": (
        {"_state_store"},
        set(),
        set(),
    ),
    "sensors": (
        {
            "_adapters",
            "_background_tasks",
            "_connected_sensor_ids",
            "_retrying_sensors_announced",
            "_safety_registry",
            "_unconnected_sensors",
        },
        {"_sensor_last_seen_ms", "_sensor_poll_interval_ms"},
        {"_connect_when_available", "_safety_notice_sender", "_start_polling"},
    ),
    "loops": (
        {"_background_tasks", "_deduplicator", "_sensor_poll_interval_ms"},
        set(),
        {
            "_alert_delivery_loop",
            "_capability_posture_loop",
            "_compaction_loop",
            "_device_policy_refresh_loop",
            "_external_watchdog_loop",
            "_heartbeat_loop",
            "_sensor_staleness_loop",
            "_status_signaling_loop",
            "_watchdog_loop",
        },
    ),
    "services": (
        {
            "_background_tasks",
            "_deduplicator",
            "_firmware_alarm_tracker",
            "_firmware_profile_library",
            "_firmware_reading_age",
            "_gateway_ingress",
            "_nudge_firmware_confirmations",
            "_shutdown_event",
            "_state_store",
        },
        {
            "_evidence_inbound_subscriber",
            "_firmware_alarm_tracker",
            "_firmware_command_publisher",
            "_firmware_command_service",
            "_firmware_liveness_scheduler",
            "_firmware_liveness_supervisor",
            "_firmware_profile_library",
        },
        {
            "_evidence_registration_loop",
            "_start_evidence_outbound",
            "_start_gateway_export_responder_if_enabled",
            "_start_sms_webhook_if_enabled",
            "_start_telemetry_export_if_enabled",
        },
    ),
    "operator_services": (
        {"_background_tasks", "_build_health_snapshot", "_shutdown_event"},
        {"_runtime_node_heartbeat_publisher"},
        {"_start_firmware_mqtt_operator_if_enabled"},
    ),
    "health_and_reconciliation": (
        {"_background_tasks", "_firmware_confirmation_reconciler", "_shutdown_event"},
        set(),
        {
            "_drain_pending_firmware_confirmations",
            "_reconcile_pending_attestations",
            "_start_health_socket_if_enabled",
            "_start_operator_socket",
        },
    ),
    "announce": (
        {"_background_tasks", "_safety_registry", "_shutdown_event"},
        set(),
        {"_complete_startup", "_send_setup_success_notifications", "stop"},
    ),
}

_INVENTORY_LIMIT = (
    "This is an inventory, not a proof of isolation: it sees what a stage's own "
    "body touches, closures included, and not what a method it calls reaches. "
    "Update the inventory when a stage's surface changes on purpose."
)


def _stage_methods() -> dict[str, ast.AsyncFunctionDef]:
    """Every `_stage_*` method, read from whichever domain class defines it.

    A stage that is not a coroutine is not a stage `start()` can await, so it
    is refused rather than skipped.
    """
    stages = {
        name: node
        for name, node in runtime_methods().items()
        if name.startswith("_stage_")
    }
    for name, node in stages.items():
        assert isinstance(node, ast.AsyncFunctionDef), f"{name} is not async"
    return {
        name.removeprefix("_stage_"): node
        for name, node in stages.items()
        if isinstance(node, ast.AsyncFunctionDef)
    }


def _parents(root: ast.AST) -> dict[int, ast.AST]:
    parents: dict[int, ast.AST] = {}
    for node in ast.walk(root):
        for child in ast.iter_child_nodes(node):
            parents[id(child)] = node
    return parents


def _assigned(node: ast.AST, parents: dict[int, ast.AST]) -> bool:
    """Whether `node` is assigned, or is the root of an assigned chain."""
    current: ast.AST = node
    while True:
        if isinstance(current, (ast.Attribute, ast.Subscript)) and isinstance(
            current.ctx, (ast.Store, ast.Del)
        ):
            return True
        parent = parents.get(id(current))
        if (
            isinstance(parent, (ast.Attribute, ast.Subscript))
            and parent.value is current
        ):
            current = parent
            continue
        return False


def _surface(method: ast.AsyncFunctionDef) -> tuple[set[str], set[str], set[str]]:
    parents = _parents(method)
    reads: set[str] = set()
    writes: set[str] = set()
    calls: set[str] = set()
    for statement in method.body:
        for node in ast.walk(statement):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
                if node.value.id != "self":
                    continue
                parent = parents.get(id(node))
                if isinstance(parent, ast.Call) and parent.func is node:
                    calls.add(node.attr)
                elif _assigned(node, parents):
                    writes.add(node.attr)
                else:
                    reads.add(node.attr)
            elif isinstance(node, ast.Name) and node.id == "self":
                parent = parents.get(id(node))
                if not (isinstance(parent, ast.Attribute) and parent.value is node):
                    reads.add("<self>")
    return reads, writes, calls


def _context_uses(
    method: ast.AsyncFunctionDef | ast.FunctionDef, seen: set[str] | None = None
) -> tuple[set[str], set[str]]:
    """The context fields a stage loads and stores, in its body and in every
    runtime method it hands its context to."""
    methods = runtime_methods()
    seen = set() if seen is None else seen
    loads: set[str] = set()
    stores: set[str] = set()
    for node in ast.walk(method):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "context"
        ):
            (stores if isinstance(node.ctx, ast.Store) else loads).add(node.attr)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "self"
            and node.func.attr in methods
            and node.func.attr not in seen
            and any(
                isinstance(arg, ast.Name) and arg.id == "context"
                for arg in [*node.args, *(kw.value for kw in node.keywords)]
            )
        ):
            seen.add(node.func.attr)
            more_loads, more_stores = _context_uses(methods[node.func.attr], seen)
            loads |= more_loads
            stores |= more_stores
    return loads, stores


def _names() -> list[str]:
    return [stage.name for stage in STARTUP_STAGES]


# ── The order ───────────────────────────────────────────────────────────────


def test_every_stage_is_a_method_and_every_method_a_stage() -> None:
    names = _names()
    assert len(names) == len(set(names)), f"a stage is listed twice: {names}"
    assert set(_stage_methods()) == set(names), (
        "the stage tuple and OriRuntime's _stage_* methods disagree: "
        f"tuple only {sorted(set(names) - set(_stage_methods()))}, "
        f"method only {sorted(set(_stage_methods()) - set(names))}"
    )
    for name in names:
        assert callable(getattr(OriRuntime, f"_stage_{name}"))


def test_every_constraint_names_existing_stages_and_holds() -> None:
    position = {name: index for index, name in enumerate(_names())}
    broken = []
    for constraint in STARTUP_CONSTRAINTS:
        assert constraint.later in position, f"unknown stage in {constraint}"
        assert constraint.earlier in position, f"unknown stage in {constraint}"
        assert constraint.reason.strip(), f"a constraint has no reason: {constraint}"
        if position[constraint.earlier] >= position[constraint.later]:
            broken.append(
                f"{constraint.later} must run after {constraint.earlier}: "
                f"{constraint.reason}"
            )
    assert not broken, "\n".join(broken)


def test_the_safety_orderings_are_the_designed_ones() -> None:
    declared = {(c.later, c.earlier) for c in STARTUP_CONSTRAINTS if c.safety}
    assert declared == SAFETY_ORDERINGS, (
        "the safety orderings in ori/startup_stages.py differ from the design: "
        f"added {sorted(declared - SAFETY_ORDERINGS)}, "
        f"missing {sorted(SAFETY_ORDERINGS - declared)}. Change both, with the "
        "reason, in docs/STARTUP_STAGES.md."
    )


def test_the_checkpoints_are_the_four_the_stop_protocol_has() -> None:
    assert set(STARTUP_CHECKPOINTS) == CHECKPOINTS
    assert set(STARTUP_CHECKPOINTS) <= set(_names())


def test_no_stage_checks_for_a_stop_itself() -> None:
    """Checkpoints live in the tuple, so moving one is a visible edit."""
    for name, method in _stage_methods().items():
        _, _, calls = _surface(method)
        assert "_stop_if_requested_during_startup" not in calls, (
            f"_stage_{name} checks for a stop itself; name it in "
            "STARTUP_CHECKPOINTS instead"
        )


# ── The context ─────────────────────────────────────────────────────────────


def test_every_context_read_is_set_by_an_earlier_stage() -> None:
    set_so_far: set[str] = set()
    for stage in STARTUP_STAGES:
        unset = stage.reads - set_so_far
        assert not unset, f"{stage.name} reads {sorted(unset)} before any stage sets it"
        set_so_far |= stage.sets


def test_every_context_field_is_set_and_read_later() -> None:
    fields = set(StartupContext.__slots__)
    names = _names()
    for field in sorted(fields):
        setters = [i for i, s in enumerate(STARTUP_STAGES) if field in s.sets]
        assert setters, f"no stage sets the context field {field}"
        readers = [i for i, s in enumerate(STARTUP_STAGES) if field in s.reads]
        assert any(i > setters[0] for i in readers), (
            f"{field} is set by {names[setters[0]]} and read by no later stage; "
            "a value no later stage reads is a local, not a context field"
        )
    declared = set().union(*(s.reads | s.sets for s in STARTUP_STAGES))
    assert declared <= fields, f"declared but not on the context: {declared - fields}"


def test_each_stage_declares_the_context_its_body_uses() -> None:
    """A load is a read when an earlier stage may have set the field."""
    methods = _stage_methods()
    set_earlier: set[str] = set()
    for stage in STARTUP_STAGES:
        loads, stores = _context_uses(methods[stage.name])
        unset = loads - set_earlier - stores
        assert not unset, (
            f"_stage_{stage.name} reads {sorted(unset)}, which no earlier stage sets"
        )
        assert loads & set_earlier == stage.reads, (
            f"_stage_{stage.name} context reads: body "
            f"{sorted(loads & set_earlier)}, declared {sorted(stage.reads)}"
        )
        assert stores == stage.sets, (
            f"_stage_{stage.name} context sets: body {sorted(stores)}, "
            f"declared {sorted(stage.sets)}"
        )
        set_earlier |= stores


def test_a_context_field_is_unset_until_a_stage_sets_it() -> None:
    context = StartupContext()
    try:
        context.config  # noqa: B018
    except AttributeError:
        pass
    else:
        raise AssertionError("a fresh StartupContext must not hold a config")


# ── The surface ─────────────────────────────────────────────────────────────


def test_each_stage_s_runtime_surface_matches_its_inventory() -> None:
    methods = _stage_methods()
    assert set(SURFACE) == set(methods), (
        "the surface inventory and the stages disagree: "
        f"{sorted(set(SURFACE) ^ set(methods))}. " + _INVENTORY_LIMIT
    )
    problems = []
    for name, method in methods.items():
        found = _surface(method)
        for label, have, declared in zip(
            ("runtime reads", "runtime writes", "runtime calls"),
            found,
            SURFACE[name],
            strict=True,
        ):
            if have - declared:
                problems.append(
                    f"_stage_{name} {label} not in the inventory: "
                    f"{sorted(have - declared)}"
                )
            if declared - have:
                problems.append(
                    f"_stage_{name} {label} in the inventory but not in the body: "
                    f"{sorted(declared - have)}"
                )
    assert not problems, "\n".join(problems) + "\n" + _INVENTORY_LIMIT


# ── The run ─────────────────────────────────────────────────────────────────


async def test_start_runs_the_stages_in_order_and_stops_at_a_checkpoint() -> None:
    """Driven through `start()` with each stage replaced by a recorder."""
    runtime = object.__new__(OriRuntime)
    ran: list[str] = []
    contexts: set[int] = set()

    def recorder(name: str) -> Callable[[StartupContext], Awaitable[None]]:
        async def stage(context: StartupContext) -> None:
            contexts.add(id(context))
            ran.append(name)

        return stage

    for name in _names():
        setattr(runtime, f"_stage_{name}", recorder(name))

    async def checkpoint() -> bool:
        ran.append("?")
        return ran[-2] == "operator_services"

    runtime._stop_if_requested_during_startup = checkpoint  # type: ignore[method-assign]
    await runtime.start()

    expected: list[str] = []
    for name in _names():
        expected.append(name)
        if name in CHECKPOINTS:
            expected.append("?")
        if name == "operator_services":
            break
    assert ran == expected
    assert len(contexts) == 1, "every stage must receive the one context"
