# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""No function under ori/ grows past a size a reviewer can follow as a unit.

Built as `tests/test_module_size.py` is: new code that would push a function
over the limit goes into a function of its own. The functions already over it
are held at their current size and may only shrink; when one does, its ceiling
comes down with it, so the room is not spent again.

A function is measured from its first decorator to its last line, from the AST,
nested functions and classes included, so moving a block into a nested def does
not shrink its enclosing function. Two definitions with one qualified name, such
as a property's getter and setter, are held by the larger.
"""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_FUNCTION_LINES = 150
#: Stated in each failure, because the message is what the next reader meets.
LIMIT = (
    "a function is measured from its first decorator to its last line, nested "
    "definitions included; a lambda, a class body outside its methods and a "
    "module-level block are not functions and are held only by the module size "
    "limit"
)

OVERSIZE_CEILINGS: dict[str, int] = {
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._run_approval_workflow": 541,
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._run_governed_workflow": 485,
    "ori/config/_config.py::Config._interpret": 397,
    "ori/config/_gateway.py::parse_gateway": 343,
    "ori/reasoning/elevator.py::IntelligenceElevator.reason_and_dispatch": 336,
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._admit_and_run": 280,
    "ori/runtime/_startup_foundation.py::StartupFoundation._stage_dispatcher": 268,
    "ori/reasoning/action_dispatcher.py::ActionDispatcher.dispatch": 250,
    "ori/config/_actions.py::parse_actions": 249,
    "ori/gateway/reasoning.py::MqttGatewayReasoner._round_trip": 246,
    "ori/reasoning/rule_engine.py::RuleEngine.evaluate_all": 226,
    "ori/runtime/_alerts.py::AlertDelivery._send_or_queue_alert": 212,
    "ori/state/_migrations.py::StoreMigrations._migrate_sync": 209,
    "ori/installer/linux.py::provision_runtime_config": 198,
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._execute_immediately": 196,
    "ori/state/_firmware.py::FirmwareStore._upsert_firmware_device_anchor_sync": 196,
    "ori/security/commissioning/proof_operation.py::ProofOperation._command": 194,
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._governed_approval_workflow": 193,
    "ori/config/_posture.py::validate_production_security_posture": 187,
    "ori/runtime/_startup_foundation.py::StartupFoundation._stage_safety_envelope": 187,
    "ori/reasoning/elevator.py::IntelligenceElevator._reason_with_rule_result": 186,
    "ori/runtime/_health.py::HealthSnapshot._build_health_snapshot": 184,
    "ori/state/_history.py::HistoryStore._compact_sync": 184,
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._log_action": 178,
    "ori/runtime/_shutdown.py::Shutdown.stop": 174,
    "ori/config/_hal.py::parse_hal": 168,
    "ori/state/_firmware.py::FirmwareStore._approve_firmware_device_sync": 168,
    "ori/installer/cli.py::_install": 166,
    "ori/runtime/_remote_commands.py::RemoteCommands._execute_remote_command": 165,
    "ori/security/firmware/telemetry.py::verify_fault_message": 159,
    "ori/config/_firmware_mqtt_provisioning.py::parse_firmware_mqtt_provisioning": 158,
    "ori/runtime/_alerts.py::AlertDelivery._alert_delivery_loop": 155,
    "ori/installer/linux.py::collect_installer_config": 154,
    "ori/reasoning/action_dispatcher.py::ActionDispatcher._dispatch_admitted": 154,
    "ori/security/offline_tokens.py::OfflineTierCTokenVerifier.verify_token": 154,
    "ori/state/_migrations.py::StoreMigrations._complete_backfilled_activation_history_on_conn": 153,
    "ori/state/_migrations.py::StoreMigrations._backfill_firmware_anchor_epochs_on_conn": 152,
}


def _function_lines() -> dict[str, int]:
    sizes: dict[str, int] = {}

    def walk(path: str, node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                name = f"{prefix}{child.name}"
                key = f"{path}::{name}"
                lines = (child.end_lineno or child.lineno) - start + 1
                sizes[key] = max(lines, sizes.get(key, 0))
                walk(path, child, f"{name}.")
            elif isinstance(child, ast.ClassDef):
                walk(path, child, f"{prefix}{child.name}.")
            else:
                walk(path, child, prefix)

    for path in sorted((ROOT / "ori").rglob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        walk(relative, ast.parse(path.read_text(encoding="utf-8")), "")
    return sizes


def test_no_function_grows_past_the_limit() -> None:
    sizes = _function_lines()
    assert len(sizes) > 2000, "the scan found too few functions to be reading ori/"
    over = {
        name: lines
        for name, lines in sizes.items()
        if lines > MAX_FUNCTION_LINES and name not in OVERSIZE_CEILINGS
    }
    assert not over, (
        f"functions over {MAX_FUNCTION_LINES} lines: {over}. Move the new code into "
        f"a function of its own rather than raising the limit ({LIMIT})."
    )


def test_an_oversize_function_never_grows() -> None:
    sizes = _function_lines()
    grown = {
        name: (sizes[name], ceiling)
        for name, ceiling in OVERSIZE_CEILINGS.items()
        if sizes.get(name, 0) > ceiling
    }
    assert not grown, (
        f"oversize functions grew (lines, ceiling): {grown}. Extract code into a "
        f"function of its own until each is back at or under its ceiling ({LIMIT})."
    )


def test_each_ceiling_is_the_function_s_current_size() -> None:
    sizes = _function_lines()
    stale = {
        name: (sizes.get(name), ceiling)
        for name, ceiling in OVERSIZE_CEILINGS.items()
        if sizes.get(name, 0) < ceiling
    }
    assert not stale, (
        f"oversize functions shrank, moved or were removed (lines, ceiling): "
        f"{stale}. Lower each ceiling to the current size, and drop an entry once "
        f"the function is within {MAX_FUNCTION_LINES} lines or no longer exists."
    )
    assert all(ceiling > MAX_FUNCTION_LINES for ceiling in OVERSIZE_CEILINGS.values())
