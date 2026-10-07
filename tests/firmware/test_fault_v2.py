# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""firmware-telemetry/v2 fault events and the firmware-commands/v2 refusal.

The corpus is ori-specs' own, vendored under tests/vectors/firmware_telemetry.
Every case goes through the gate the MQTT subscriber calls, against a real
store, so acceptance and refusal are observed where they are recorded.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from ori.gateway.firmware_commands import FirmwareCommandService
from ori.security.firmware.ingest import FirmwareTelemetryGate
from ori.security.firmware.liveness import FirmwareLivenessSupervisor
from ori.security.firmware.telemetry import (
    CLOSED_FAULT_DETAILS,
    CLOSED_FAULT_DETAILS_V2,
    verify_fault_message,
)
from ori.state.store import StateStore
from tests.firmware.test_command_authority import _last_cmd_seq
from tests.firmware.test_command_egress import (
    PROVISIONER_SEED,
    RUNTIME_SEED,
    _FakePublisher,
    _register_device,
)
from tests.firmware.test_telemetry import (
    PUBLIC_KEY_B64,
    SEALED_DEVICE,
    SEALED_HASH,
    provision_and_approve,
)

CORPUS = json.loads(
    (
        Path(__file__).parent.parent
        / "vectors"
        / "firmware_telemetry"
        / "fault-vectors-v2.json"
    ).read_text()
)
CASES = {case["name"]: case for case in CORPUS["cases"]}
REJECTS = {case["name"]: case for case in CORPUS["reject_cases"]}

# What each declared reason looks like at this verifier's boundary.
REASON_DETAIL = {
    "unsupported_version": "unsupported fault version",
    "detail_not_in_closed_set": " detail ",
}


def message(case: dict[str, Any]) -> dict[str, Any]:
    return json.loads(bytes.fromhex(case["message_hex"]))


@pytest.fixture
async def store(tmp_path: Path):
    s = StateStore(db_path=str(tmp_path / "state.db"))
    await s.open()
    try:
        yield s
    finally:
        await s.close()


@pytest.fixture
async def gate(store: StateStore) -> FirmwareTelemetryGate:
    gate = FirmwareTelemetryGate(store)
    await provision_and_approve(gate, "manifest_full_sealed")
    return gate


def _other_tasks() -> set[asyncio.Task[Any]]:
    return asyncio.all_tasks() - {asyncio.current_task()}  # type: ignore[operator]


async def _rows(store: StateStore, table: str) -> list[tuple[Any, ...]]:
    def read(conn: Any) -> list[tuple[Any, ...]]:
        return [tuple(r) for r in conn.execute(f"SELECT * FROM {table}").fetchall()]

    return await store._run_read(read)


def test_the_corpus_is_signed_by_the_shared_test_key_for_the_sealed_device() -> None:
    context = CORPUS["verifier_context"]
    assert CORPUS["public_key_b64"] == context["public_key_b64"] == PUBLIC_KEY_B64
    assert context["device_id"] == SEALED_DEVICE
    assert context["capability_hash"] == SEALED_HASH


@pytest.mark.parametrize("name", sorted(CASES))
async def test_every_case_is_accepted_and_recorded(
    gate: FirmwareTelemetryGate, store: StateStore, name: str
) -> None:
    case = CASES[name]
    verification = await gate.ingest_fault(message(case), received_at_ms=1)

    assert verification.accepted, verification.error_detail
    assert verification.version == case["input"]["v"]
    assert (verification.code, verification.detail) == (
        case["input"]["code"],
        case["input"]["detail"],
    )
    faults = await _rows(store, "firmware_fault_events")
    assert len(faults) == 1
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None and row["last_seq"] == case["input"]["seq"]


@pytest.mark.parametrize("name", sorted(REJECTS))
async def test_every_refusal_is_refused_for_its_reason_and_consumes_nothing(
    gate: FirmwareTelemetryGate, store: StateStore, name: str
) -> None:
    case = REJECTS[name]
    verification = await gate.ingest_fault(message(case), received_at_ms=1)

    assert not verification.accepted
    assert verification.error_code == "invalid_envelope"
    assert REASON_DETAIL[case["reason"]] in verification.error_detail
    assert await _rows(store, "firmware_fault_events") == []
    row = await store.get_firmware_device(SEALED_DEVICE)
    assert row is not None and row["last_seq"] == 0


def test_the_v2_closed_sets_are_the_contracts() -> None:
    # Transcribed from firmware-telemetry/v2.md, not derived from the code.
    assert CLOSED_FAULT_DETAILS_V2 == {
        "command_rejected": frozenset(
            {
                "malformed",
                "wrong_device",
                "bad_signature",
                "replayed",
                "capability_mismatch",
                "unknown_action",
                "rate_limited",
                "storage_failure",
            }
        ),
        "ingress_degraded": frozenset(
            {
                "inbound_overflow",
                "subscribe_failed",
                "anchor_persist_failed",
                "mqtt_provision_epoch_failed",
                "provisioning_serial_io_failed",
                "provisioning_serial_overflow",
                "liveness_authority_failed",
            }
        ),
        "storage_degraded": frozenset({"buffer_write_failed", "buffer_mount_failed"}),
    }
    assert "rate_limited" not in CLOSED_FAULT_DETAILS["command_rejected"]


@pytest.mark.parametrize(
    "version",
    [2.0, True, None, "2", 3, 0, -1, 2**53 - 1, [2], {"v": 2}],
    ids=repr,
)
def test_a_fault_version_other_than_the_integer_one_or_two_is_refused(
    version: Any,
) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ori.security.firmware.telemetry import canonical_json_bytes

    fault = dict(CASES["v2_command_rejected_replayed"]["input"], v=version)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(CORPUS["test_seed_hex"]))
    signature = "ed25519:" + base64.b64encode(
        key.sign(canonical_json_bytes(fault))
    ).decode("ascii")
    result = verify_fault_message(
        {"fault": fault, "signature": signature},
        anchor_device_id=SEALED_DEVICE,
        anchor_public_key_b64=PUBLIC_KEY_B64,
        anchor_posture="sealed_flash",
        accepted_manifest_hash=SEALED_HASH,
        last_boot_id=0,
        last_seq=0,
        last_uptime_ms=None,
    )
    assert not result.accepted
    assert result.error_detail == "unsupported fault version"


async def test_a_rate_limited_refusal_is_recorded_and_nothing_is_reissued(
    tmp_path: Path,
) -> None:
    """firmware-commands/v2: a refusal is never an execution and never retried."""
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        device_id = await _register_device(store)
        publisher = _FakePublisher()
        service = FirmwareCommandService(
            store=store,
            publisher=publisher,  # type: ignore[arg-type]
            runtime_command_key_bytes=RUNTIME_SEED,
            provisioner_key_bytes=PROVISIONER_SEED,
            liveness_supervisor=FirmwareLivenessSupervisor(),
        )
        before = _other_tasks()
        await service.publish_command(
            device_id=device_id, action="relay_open", channel="relay0"
        )
        refusal = CASES["v2_command_rejected_rate_limited"]
        verification = await FirmwareTelemetryGate(store).ingest_fault(
            message(refusal), received_at_ms=1
        )
        await asyncio.sleep(0.05)

        assert verification.accepted and verification.detail == "rate_limited"
        # Nothing left running could publish later: a delayed retry is a task.
        assert _other_tasks() <= before
        assert len(publisher.commands) == 1
        assert _last_cmd_seq(store, device_id) == 1
        assert await _rows(store, "action_log") == []
        assert [r for r in await _rows(store, "firmware_fault_events")] != []
    finally:
        await store.close()


async def test_a_failed_command_publish_is_not_retried(tmp_path: Path) -> None:
    """An unresolved command stays unresolved: one attempt, one sequence."""
    store = StateStore(db_path=str(tmp_path / "state.db"))
    await store.open()
    try:
        device_id = await _register_device(store)

        class _Failing(_FakePublisher):
            async def publish_command(self, device_id: str, message: bytes) -> None:
                await super().publish_command(device_id, message)
                raise ConnectionError("broker gone")

        publisher = _Failing()
        service = FirmwareCommandService(
            store=store,
            publisher=publisher,  # type: ignore[arg-type]
            runtime_command_key_bytes=RUNTIME_SEED,
            provisioner_key_bytes=PROVISIONER_SEED,
            liveness_supervisor=FirmwareLivenessSupervisor(),
        )
        before = _other_tasks()
        with pytest.raises(ConnectionError):
            await service.publish_command(
                device_id=device_id, action="relay_open", channel="relay0"
            )
        await asyncio.sleep(0.05)

        assert _other_tasks() <= before
        assert len(publisher.commands) == 1
        assert _last_cmd_seq(store, device_id) == 1
    finally:
        await store.close()


#: Every production call into command signing or publication, counted per
#: (module, enclosing scope, callee). A retry, a scheduler or a second caller,
#: even a second call inside a known scope, changes a count.
COMMAND_EGRESS_CALLS = Counter(
    {
        (
            "ori/gateway/firmware_commands.py",
            "FirmwareCommandService.publish_command",
            "sign_command",
        ): 1,
        (
            "ori/gateway/firmware_commands.py",
            "FirmwareCommandService.publish_command",
            "publish_command",
        ): 1,
        ("ori/runtime.py", "OriRuntime.publish_firmware_command", "publish_command"): 1,
        (
            "ori/security/firmware/commands.py",
            "FirmwareCommandSigner.sign_command",
            "sign_command_bytes",
        ): 1,
    }
)
_EGRESS_NAMES = {c for _, _, c in COMMAND_EGRESS_CALLS} | {"publish_firmware_command"}

#: Every way the egress modules defer or detach work, counted per scope. These
#: are the publisher's transport plumbing; a new one is where a delayed retry
#: would live.
EGRESS_MODULES = (
    "ori/gateway/firmware_commands.py",
    "ori/security/firmware/commands.py",
)
EGRESS_SCHEDULING = Counter(
    {
        (
            "ori/gateway/firmware_commands.py",
            "MqttFirmwareCommandPublisher._connect_locked",
            "to_thread",
        ): 2,
        (
            "ori/gateway/firmware_commands.py",
            "MqttFirmwareCommandPublisher._retire",
            "run_in_executor",
        ): 1,
        (
            "ori/gateway/firmware_commands.py",
            "MqttFirmwareCommandPublisher._retire",
            "add_done_callback",
        ): 1,
        (
            "ori/gateway/firmware_commands.py",
            "MqttFirmwareCommandPublisher._publish",
            "to_thread",
        ): 2,
        ("ori/gateway/firmware_commands.py", "_stop_client", "to_thread"): 2,
    }
)
_SCHEDULING_NAMES = {
    "call_later",
    "call_at",
    "call_soon",
    "call_soon_threadsafe",
    "create_task",
    "ensure_future",
    "run_in_executor",
    "run_coroutine_threadsafe",
    "to_thread",
    "Thread",
    "Timer",
    "TaskGroup",
    "gather",
    "add_done_callback",
}


def _calls(paths: list[Path], root: Path, names: set[str]) -> tuple[Counter, set]:
    found: Counter = Counter()
    named: set[tuple[str, str]] = set()
    for path in paths:
        rel = path.relative_to(root).as_posix()
        scopes: list[str] = []

        def visit(node: ast.AST) -> None:
            scoped = isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            if scoped:
                scopes.append(node.name)  # type: ignore[attr-defined]
            if isinstance(node, ast.Call):
                func = node.func
                callee = (
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else func.id
                    if isinstance(func, ast.Name)
                    else None
                )
                if callee in names:
                    found[(rel, ".".join(scopes), callee)] += 1
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and node.value in names
            ):
                named.add((rel, node.value))
            for child in ast.iter_child_nodes(node):
                visit(child)
            if scoped:
                scopes.pop()

        visit(ast.parse(path.read_text()))
    return found, named


_ROOT = Path(__file__).resolve().parents[2]
_LIMIT = (
    "This guard sees direct calls and string names only, not a callee reached "
    "through an alias, a stored bound method or functools.partial."
)


def test_command_egress_has_exactly_its_known_callers() -> None:
    found, named = _calls(sorted((_ROOT / "ori").rglob("*.py")), _ROOT, _EGRESS_NAMES)
    assert found == COMMAND_EGRESS_CALLS, (
        "command egress gained or lost a call site; firmware-commands/v2 forbids "
        "any automatic reissue, so a new one must be shown not to retry. "
        f"{_LIMIT} Difference: {sorted((found - COMMAND_EGRESS_CALLS).items())} "
        f"added, {sorted((COMMAND_EGRESS_CALLS - found).items())} removed"
    )
    assert named == set(), (
        f"command egress named as a string, e.g. for getattr: {sorted(named)}"
    )


#: Every callee name the two egress modules call. A thread pool, a raw client
#: publish or any other new way to put bytes on the wire is a new name.
EGRESS_CALLEES = frozenset(
    {
        "Client",
        "FirmwareCommandError",
        "FirmwareCommandPublishError",
        "FirmwareCommandSigner",
        "FirmwareLivenessSigner",
        "Lock",
        "RuntimeError",
        "ValueError",
        "_build_approval_object_bytes",
        "_client_factory",
        "_connect_locked",
        "_manifest_authorizes",
        "_publish",
        "_refuse_published_seed",
        "_require_approved_device",
        "_require_canonical_b64_32",
        "_require_fleet_id",
        "_retire",
        "_shut_socket",
        "_stop_client",
        "_topic",
        "_validate_command_fields",
        "add_done_callback",
        "allocate_firmware_command_seq",
        "any",
        "apply_tls_context",
        "b64decode",
        "b64encode",
        "build_command_bytes",
        "build_provisioning_approval_bytes",
        "callable",
        "cancelled",
        "cast",
        "compile",
        "debug",
        "decode",
        "disconnect",
        "encode",
        "exception",
        "firmware_command_authority_holds",
        "float",
        "from_private_bytes",
        "frozenset",
        "get",
        "getLogger",
        "get_firmware_confirmation_status",
        "get_firmware_device",
        "get_running_loop",
        "getattr",
        "hasattr",
        "int",
        "is_connected",
        "is_published",
        "is_published_seed",
        "isfinite",
        "isinstance",
        "len",
        "loop_stop",
        "match",
        "monotonic",
        "parse_gateway_broker_url",
        "public_bytes",
        "public_key",
        "public_key_bytes",
        "publish_command",
        "publish_provisioning_approval",
        "publish_runtime_liveness",
        "refused_public_key_clause",
        "run_in_executor",
        "setdefault",
        "shutdown",
        "sign",
        "sign_command",
        "sign_command_bytes",
        "sign_liveness",
        "sleep",
        "sock_of",
        "str",
        "strip",
        "supervised_devices",
        "to_thread",
        "username_pw_set",
    }
)


def test_the_egress_modules_call_nothing_new() -> None:
    names: set[str] = set()
    client_reads: set[tuple[str, str]] = set()
    for module in EGRESS_MODULES:
        scopes: list[str] = []

        def visit(node: ast.AST) -> None:
            scoped = isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )
            if scoped:
                scopes.append(node.name)  # type: ignore[attr-defined]
            if isinstance(node, ast.Call):
                func = node.func
                names.add(
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else func.id
                    if isinstance(func, ast.Name)
                    else "<computed>"
                )
            if (
                isinstance(node, ast.Attribute)
                and node.attr == "_client"
                and (not scopes or scopes[0] != "MqttFirmwareCommandPublisher")
            ):
                client_reads.add((module, ".".join(scopes)))
            for child in ast.iter_child_nodes(node):
                visit(child)
            if scoped:
                scopes.pop()

        visit(ast.parse((_ROOT / module).read_text()))
    assert names <= EGRESS_CALLEES, (
        "the command egress modules call something new; firmware-commands/v2 "
        "forbids any automatic reissue, so a new callee must be shown not to "
        f"publish. {_LIMIT} New: {sorted(names - EGRESS_CALLEES)}"
    )
    assert client_reads == set(), (
        "only MqttFirmwareCommandPublisher may touch its MQTT client; a "
        f"publication from elsewhere bypasses its retirement rules: {sorted(client_reads)}"
    )


def test_the_egress_modules_defer_nothing_new() -> None:
    found, _ = _calls([_ROOT / m for m in EGRESS_MODULES], _ROOT, _SCHEDULING_NAMES)
    assert found == EGRESS_SCHEDULING, (
        "the command egress modules gained or lost a timer, task, thread or "
        "callback; a delayed reissue would need one, so a new one must be shown "
        f"not to publish. {_LIMIT} Difference: "
        f"{sorted((found - EGRESS_SCHEDULING).items())} added, "
        f"{sorted((EGRESS_SCHEDULING - found).items())} removed"
    )


def test_v1_keeps_its_ingress_set_without_liveness_authority_failed() -> None:
    """The v 2 set lists the token; v1's classification awaits its audit."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ori.security.firmware.telemetry import canonical_json_bytes

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(CORPUS["test_seed_hex"]))
    base = CASES["v2_ingress_degraded_liveness_authority_failed"]["input"]
    verdicts = {}
    for version in (1, 2):
        fault = dict(base, v=version)
        signature = "ed25519:" + base64.b64encode(
            key.sign(canonical_json_bytes(fault))
        ).decode("ascii")
        verdicts[version] = verify_fault_message(
            {"fault": fault, "signature": signature},
            anchor_device_id=SEALED_DEVICE,
            anchor_public_key_b64=PUBLIC_KEY_B64,
            anchor_posture="sealed_flash",
            accepted_manifest_hash=SEALED_HASH,
            last_boot_id=0,
            last_seq=0,
            last_uptime_ms=None,
        )
    assert verdicts[2].accepted
    assert not verdicts[1].accepted
    assert "ingress_degraded detail" in verdicts[1].error_detail
