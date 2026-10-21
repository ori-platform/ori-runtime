# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""No JSON reader in the runtime keeps the last of two repeated members unless
it says why that is safe.

Every `json.loads` or `json.load` under `ori/` passes `unique_members` as its
`object_pairs_hook`, or is listed in `EXEMPT` with its reason and the number of
such calls in that function. A gateway receiver reads through
`ori.security.payload_members` instead.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "ori"

#: A local hook allowed in place of `unique_members`, and why.
OWN_HOOKS = {
    ("security/commissioning/binding.py", "_pairs_without_duplicates"): (
        "refuses a repeat and checks each value's spelling in one pass, so a "
        "document with both keeps the error it met first"
    ),
}

_OWN_ROWS = "the runtime's own store row, written by its own encoder"
_LOCAL_TOOL = "a local process's output, read by this one reader and unsigned"
_ONE_READER = "unsigned input with one reader, so no other reader sees another document"

#: (module, enclosing function) -> (calls exempt there, why).
EXEMPT: dict[tuple[str, str], tuple[int, str]] = {
    ("security/payload_members.py", "admitted_object"): (
        1,
        "parses only bytes the Payload Member Rule admitted, which hold no repeat",
    ),
    ("security/approvers/requests.py", "parse"): (
        1,
        "its hook records every repeated member, which the parse refuses in "
        "operator-socket/v3's order: as the request's fault, or as a "
        "revocation document's",
    ),
    ("cli_bridge.py", "_read_health_snapshot"): (1, _LOCAL_TOOL),
    ("doctor.py", "_error_detail"): (1, _LOCAL_TOOL),
    ("doctor.py", "_health_payload"): (1, _LOCAL_TOOL),
    ("doctor.py", "_gateway_posture_from_config"): (1, _LOCAL_TOOL),
    ("installer/activation.py", "run_installed_doctor"): (1, _LOCAL_TOOL),
    ("installer/linux.py", "_valid_config_response"): (1, _LOCAL_TOOL),
    ("installer/linux.py", "_health_bridge_response"): (1, _LOCAL_TOOL),
    ("installer/upgrade.py", "_payload"): (1, _LOCAL_TOOL),
    ("hal/smart_adapter.py", "SmartAdapter._run_smartctl_json"): (1, _LOCAL_TOOL),
    ("security/aws_kms_release_signer.py", "AwsKmsReleaseSigner._invoke"): (
        1,
        _LOCAL_TOOL,
    ),
    ("utils/termux.py", "parse_termux_usb_output"): (1, _LOCAL_TOOL),
    ("skills/os_sandbox.py", "OSSandboxHookRunner._invoke_child"): (1, _ONE_READER),
    ("skills/os_sandbox.py", "_child_rpc_call"): (1, _ONE_READER),
    ("skills/os_sandbox.py", "_run_child"): (1, _ONE_READER),
    ("hal/coap_adapter.py", "CoapAdapter._decode_payload"): (1, _ONE_READER),
    ("hal/mqtt_base.py", "load_json_payload"): (1, _ONE_READER),
    ("firmware_provisioner.py", "golden_selfcheck"): (
        1,
        "the shipped golden vectors, compared byte for byte",
    ),
    ("firmware_provisioner.py", "cmd_selfcheck"): (
        1,
        "the shipped golden vectors, compared byte for byte",
    ),
    (
        "gateway/firmware_commands.py",
        "FirmwareCommandService.publish_runtime_liveness",
    ): (
        1,
        "the runtime's own outbound message, checked before it leaves",
    ),
    ("runtime.py", "OriRuntime._record_preference_disabled_alert"): (1, _OWN_ROWS),
    ("security/commissioning/loader.py", "accepted_from_row"): (1, _OWN_ROWS),
    ("security/commissioning/proof_operation.py", "export_observations"): (
        1,
        _OWN_ROWS,
    ),
    ("security/evidence/chain.py", "EvidenceChain.verify_chain"): (1, _OWN_ROWS),
    ("security/evidence/first_party.py", "_authority_snapshot"): (1, _OWN_ROWS),
    ("security/evidence/ledger.py", "_sealed_digests"): (1, _OWN_ROWS),
    ("security/evidence/ledger.py", "EvidenceDeliveryLedger.queue_artifact"): (
        1,
        _OWN_ROWS,
    ),
    (
        "security/evidence/ledger.py",
        "EvidenceDeliveryLedger._require_intact_obligations",
    ): (1, _OWN_ROWS),
    ("security/evidence/ledger.py", "EvidenceDeliveryLedger.sealed_artifact"): (
        1,
        _OWN_ROWS,
    ),
    ("security/evidence/ledger.py", "EvidenceDeliveryLedger._verify_chain_row"): (
        2,
        _OWN_ROWS,
    ),
    ("security/evidence/ledger.py", "EvidenceDeliveryLedger._reconcile_reseal"): (
        1,
        _OWN_ROWS,
    ),
    ("security/evidence/ledger.py", "EvidenceDeliveryLedger.verify_sequence"): (
        1,
        _OWN_ROWS,
    ),
    ("security/firmware/ingest.py", "FirmwareTelemetryGate.approve_device"): (
        1,
        _OWN_ROWS,
    ),
    ("state/_history.py", "_stored_reading"): (1, _OWN_ROWS),
    ("state/_actions.py", "ActionLogStore._get_actions_needing_attestation_sync"): (
        1,
        _OWN_ROWS,
    ),
    ("state/_tier_c.py", "TierCStore._decode_tier_c_decision_row"): (3, _OWN_ROWS),
    ("state/_alerts.py", "AlertOutboxStore._get_retryable_alerts_sync"): (1, _OWN_ROWS),
    ("state/_firmware.py", "FirmwareStore._list_firmware_device_manifests_sync"): (
        1,
        _OWN_ROWS,
    ),
    ("state/_firmware.py", "FirmwareStore._get_firmware_device_sync"): (2, _OWN_ROWS),
    (
        "state/_commissioning.py",
        "CommissioningStore._retain_commissioned_binding_sync",
    ): (
        1,
        _OWN_ROWS,
    ),
}

#: Gateway receivers: each reads through the Payload Member Rule.
GATEWAY_RECEIVERS = (
    "gateway/evidence_inbound.py",
    "gateway/evidence_outbound.py",
    "gateway/export.py",
    "gateway/heartbeat.py",
    "gateway/reasoning.py",
    "security/gateway_messages.py",
)

_LIMIT = (
    "This guard sees `json.loads`, `json.load` and `json.JSONDecoder` called "
    "through the `json` module name, and refuses every other way of reaching a "
    "decoder it can see: another import of them or of `json.decoder`, an "
    "uncalled reference, `getattr` on `json`, or importing `json` by string. It "
    "does not follow a decoder handed in as a parameter."
)

_DECODERS = frozenset({"loads", "load", "JSONDecoder"})


def _modules() -> list[tuple[str, ast.AST]]:
    return [
        (str(path.relative_to(ROOT)), ast.parse(path.read_text(), filename=str(path)))
        for path in sorted(ROOT.rglob("*.py"))
    ]


def _decodes(tree: ast.AST) -> list[tuple[str, ast.Call]]:
    """Every json decode call, with the dotted name of its enclosing function."""
    found: list[tuple[str, ast.Call]] = []

    def visit(node: ast.AST, scope: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = f"{scope}.{child.name}" if scope else child.name
            if isinstance(child, ast.Call):
                func = child.func
                if (
                    isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "json"
                    and func.attr in ("loads", "load", "JSONDecoder")
                ):
                    found.append((inner, child))
            visit(child, inner)

    visit(tree, "")
    return found


def _refuses_repeats(relative: str, call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg != "object_pairs_hook":
            continue
        hook = keyword.value
        if (
            isinstance(hook, ast.Call)
            and isinstance(hook.func, ast.Name)
            and hook.func.id == "unique_members"
        ):
            return True
        return isinstance(hook, ast.Name) and (relative, hook.id) in OWN_HOOKS
    return False


def test_every_json_reader_refuses_a_repeated_member_or_says_why_not():
    offenders = []
    for relative, tree in _modules():
        unguarded = Counter(
            scope
            for scope, call in _decodes(tree)
            if not _refuses_repeats(relative, call)
        )
        for scope, count in unguarded.items():
            allowed = EXEMPT.get((relative, scope), (0, ""))[0]
            if count > allowed:
                offenders.append(f"{relative}:{scope} ({count} > {allowed})")
    assert not offenders, (
        "json.loads keeps the last of two repeated members. Pass "
        "object_pairs_hook=unique_members() from ori.utils.strict_json, read a "
        "gateway payload through ori.security.payload_members, or list the "
        f"call in EXEMPT with why a repeat is harmless there. {_LIMIT} "
        f"{offenders}"
    )


def test_every_exemption_is_still_used():
    """A stale entry would silently cover the next call written there."""
    used: Counter[tuple[str, str]] = Counter()
    for relative, tree in _modules():
        for scope, call in _decodes(tree):
            if not _refuses_repeats(relative, call):
                used[(relative, scope)] += 1
    stale = [
        f"{key} allows {allowed}, has {used[key]}"
        for key, (allowed, _) in EXEMPT.items()
        if used[key] != allowed
    ]
    assert not stale, stale


def _indirect_decoders(tree: ast.AST) -> list[int]:
    """Lines reaching a JSON decoder other than by calling it on `json`."""
    called = {id(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            if node.module == "json.decoder" or (
                node.module == "json"
                and {a.name for a in node.names} & (_DECODERS | {"*", "decoder"})
            ):
                lines.append(node.lineno)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "json.decoder" or (
                    alias.name == "json" and alias.asname not in (None, "json")
                ):
                    lines.append(node.lineno)
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "json"
            and (
                node.attr == "decoder"
                or (node.attr in _DECODERS and id(node) not in called)
            )
        ):
            lines.append(node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            first = node.args[0] if node.args else None
            if (
                node.func.id == "getattr"
                and isinstance(first, ast.Name)
                and first.id == "json"
            ):
                lines.append(node.lineno)
            if (
                node.func.id == "__import__"
                and isinstance(first, ast.Constant)
                and str(first.value).split(".")[0] == "json"
            ):
                lines.append(node.lineno)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and str(node.args[0].value).split(".")[0] == "json"
        ):
            lines.append(node.lineno)
    return lines


def test_json_decoding_is_reached_only_by_calling_it_on_the_json_module():
    indirect = [
        f"{relative}:{line}"
        for relative, tree in _modules()
        for line in _indirect_decoders(tree)
    ]
    assert not indirect, f"{_LIMIT} {indirect}"


@pytest.mark.parametrize(
    "source",
    [
        "from json import loads",
        "from json import *",
        "import json as j",
        "import json.decoder",
        "from json.decoder import JSONDecoder",
        "import json\njson.decoder.JSONDecoder()",
        "import json\nL = json.loads",
        "import functools, json\nfunctools.partial(json.loads)",
        "import json\ngetattr(json, 'loads')",
        "import importlib\nimportlib.import_module('json').loads",
        "__import__('json').loads",
    ],
)
def test_the_guard_sees_each_indirect_route(source):
    assert _indirect_decoders(ast.parse(source))


def test_the_guard_passes_a_plain_hooked_call():
    tree = ast.parse("import json\njson.loads(b, object_pairs_hook=unique_members())")
    assert _indirect_decoders(tree) == []
    assert all(_refuses_repeats("x.py", call) for _, call in _decodes(tree))


def test_the_gateway_receivers_read_through_the_member_rule():
    trees = dict(_modules())
    for relative in GATEWAY_RECEIVERS:
        called = {
            node.func.id
            for node in ast.walk(trees[relative])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert called & {"admitted_text", "admitted_object"}, relative
        assert not [call for _, call in _decodes(trees[relative])], (
            f"{relative} decodes JSON outside the Payload Member Rule"
        )


# -- the readers refuse a repeat, nested or not, in their own terms ----------

_NESTED_REPEAT = '{"v":1,"inner":{"a":1,"a":2}}'


def test_unique_members_refuses_a_repeat_at_any_depth_as_unparseable_json():
    import json

    import pytest

    from ori.utils.strict_json import unique_members

    for text in ('{"a":1,"a":2}', _NESTED_REPEAT, '[{"a":1},{"b":1,"b":1}]'):
        with pytest.raises(json.JSONDecodeError, match="duplicate member"):
            json.loads(text, object_pairs_hook=unique_members())
    assert json.loads('{"a":{"a":1}}', object_pairs_hook=unique_members()) == {
        "a": {"a": 1}
    }


def test_a_remote_command_with_a_repeat_is_not_a_command():
    from ori.security.remote_commands.commands import extract_remote_command_payload

    payload = {"text": "ORI_COMMAND " + _NESTED_REPEAT}
    assert extract_remote_command_payload(payload, channel="sms") is None


def test_a_webhook_json_body_with_a_repeat_carries_nothing():
    from ori.network.sms_webhook import SMSWebhookServer

    server = SMSWebhookServer.__new__(SMSWebhookServer)
    headers = {"content-type": "application/json"}
    assert server._decode_payload(headers, _NESTED_REPEAT.encode()) == {}


def test_a_policy_body_with_a_repeat_is_an_invalid_payload():
    import pytest

    from ori.policy.remote_fetch import RemotePolicyFetchError, _decode_json_body

    with pytest.raises(RemotePolicyFetchError) as refused:
        _decode_json_body(_NESTED_REPEAT.encode())
    assert refused.value.code == "invalid_payload"


def test_a_profile_set_with_a_repeat_is_malformed(tmp_path):
    import pytest

    from ori.security.commissioning.profiles import (
        ProfileSetError,
        load_shipped_profile_set,
    )

    path = tmp_path / "profiles.json"
    path.write_text('{"profiles":[],"profiles":[]}')
    with pytest.raises(ProfileSetError, match="malformed_profile"):
        load_shipped_profile_set(path)


def test_operator_files_with_a_repeat_are_refused(tmp_path):
    import pytest

    from ori.firmware_provisioner import ProvisionerError, _load_manifest_message
    from ori.inverter_profile_doctor import InverterProfileError, _read_evidence_bundle

    path = tmp_path / "doc.json"
    path.write_text(_NESTED_REPEAT)
    with pytest.raises(ProvisionerError, match="duplicate member"):
        _load_manifest_message(str(path))
    with pytest.raises(InverterProfileError, match="duplicate member"):
        _read_evidence_bundle(path)
