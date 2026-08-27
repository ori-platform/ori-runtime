# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for the configuration surface extractor.

Two successive versions of this extractor produced inventories that were
plausible, reproducible, and semantically false. The first counted every
dictionary access inside a parse function, so signature-block fields appeared as
settings an operator could write. The second tracked receivers but not loops, so
every key under `sensors` and `skills` vanished while the total stayed
confident.

Neither failure was visible in the output. Both are visible here.
"""

from __future__ import annotations

import ast

import pytest

from tests.golden.build_config_surface_inventory import SectionWalker


def walk(source: str, base: str = "section", param: str = "data") -> dict[str, dict]:
    """Run the walker over a synthetic function body."""
    tree = ast.parse(source)
    fn = tree.body[0]
    assert isinstance(fn, ast.FunctionDef)
    walker = SectionWalker(base, param, fn.name)
    for statement in fn.body:
        walker.visit(statement)
    return walker.rows


def paths(source: str, **kw) -> set[str]:
    return set(walk(source, **kw))


def test_loop_item_carries_provenance_for_sensors() -> None:
    """`for item in data:` binds an element, not a new namespace.

    This is the defect that removed the entire list-of-object surface: sensors
    and skills are parsed by iterating, so their keys were invisible while the
    inventory reported a total that looked complete.
    """
    got = paths(
        """
def _parse_sensors(data):
    for item in data:
        sensor_id = item.get("id")
        poll = item.get("poll_interval_ms", 1000)
""",
        base="sensors",
    )
    assert got == {"sensors[].id", "sensors[].poll_interval_ms"}


def test_enumerate_loop_binds_the_item_not_the_index() -> None:
    """`for i, item in enumerate(data)` is how config.py actually iterates."""
    got = paths(
        """
def _parse_sensors(data):
    for i, item in enumerate(data):
        kind = item.get("type")
""",
        base="sensors",
    )
    assert got == {"sensors[].type"}


def test_nested_subsection_alias_extends_the_path() -> None:
    """A sub-section binding extends the path rather than starting a new one."""
    got = paths(
        """
def _parse_actions(data):
    sms = data.get("sms") or {}
    webhook = sms.get("incoming_webhook") or {}
    signature = webhook.get("signature") or {}
    mode = signature.get("mode", "token_only")
""",
        base="actions",
    )
    assert "actions.sms.incoming_webhook.signature.mode" in got


def test_unrelated_dictionaries_are_excluded() -> None:
    """A key nobody can trace back to the parsed document is not a setting.

    `verified` and `signed_at_ms` belong to a signature block the loader builds
    for itself. The first extractor reported them as configuration paths.
    """
    got = paths(
        """
def _parse_security(data):
    require = data.get("require_signed", False)
    result = {}
    verified = result.get("verified")
    stamp = result.get("signed_at_ms")
""",
        base="security",
    )
    assert got == {"security.require_signed"}


def test_reassignment_to_something_unrelated_clears_provenance() -> None:
    got = paths("""
def _parse_thing(data):
    first = data.get("kept")
    data = compute_something_else()
    second = data.get("not_configuration")
""")
    assert got == {"section.kept"}


def test_normalising_an_absent_section_keeps_provenance() -> None:
    """`if data is None: data = {}` is the same section, empty.

    Treating it as a rebind emptied the environment on the first statement of
    several parse functions and silently dropped every key beneath them.
    """
    got = paths(
        """
def _parse_security(data):
    if data is None:
        data = {}
    out = dict(data)
    enabled = out.get("enforce_production_posture", False)
""",
        base="security",
    )
    assert got == {"security.enforce_production_posture"}


def test_a_wrapped_read_does_not_clear_provenance() -> None:
    """`x = str(data.get(...))` derives from configuration."""
    got = paths(
        """
def _parse_device(data):
    profile = str(data.get("deployment_profile", "development")).lower()
    other = data.get("timezone")
""",
        base="device",
    )
    assert got == {"device.deployment_profile", "device.timezone"}


def test_required_reads_are_marked_required() -> None:
    rows = walk(
        """
def _parse_device(data):
    device_id = _require_str(data, "id", "device")
    name = data.get("name")
""",
        base="device",
    )
    assert rows["device.id"]["presence"] == "required"
    assert rows["device.name"]["presence"] == "optional"


def test_literal_defaults_are_captured() -> None:
    rows = walk(
        """
def _parse_actions(data):
    size = data.get("batch_size", 50)
    interval = data.get("retry_interval_minutes", 0.5)
""",
        base="actions",
    )
    assert rows["actions.batch_size"]["default"] == 50
    assert rows["actions.retry_interval_minutes"]["default"] == 0.5


@pytest.mark.parametrize(
    "path, example, expected",
    [
        ("actions.sms.enabled", {"actions.sms.enabled"}, True),
        # Suffix matching credited every `enabled` to whichever section had one.
        ("actions.sms.enabled", {"gateway.enabled"}, False),
        ("hal.status_signaling.gpio_pin", {"hal.external_watchdog.gpio_pin"}, False),
        ("sensors[].port", {"sensors[].port"}, True),
        ("device.id", {"device.id.nested"}, False),
    ],
)
def test_example_membership_is_an_exact_path_match(
    path: str, example: set[str], expected: bool
) -> None:
    from tests.golden.build_config_surface_inventory import in_example_exact

    assert in_example_exact(path, example) is expected


def test_adapter_correlation_is_confined_to_sensors() -> None:
    """Sharing a leaf name with an unrelated adapter is not evidence.

    `actions.coap.timeout_s` and `actions.sms.gsm.port` were credited to sensor
    adapters that merely read `timeout_s` and `port`.
    """
    from tests.golden.build_config_surface_inventory import coverage

    entries = [{"path": "actions.sms.gsm.port"}]
    result = coverage(entries, {"actions.sms.gsm.port", "actions.coap.timeout_s"})
    correlated = {item["path"] for item in result["sensor_metadata"]}
    assert "actions.coap.timeout_s" not in correlated
    assert all(p.startswith("sensors[]") for p in correlated)


# --------------------------------------------------------------------------
# Production seam
# --------------------------------------------------------------------------
#
# Everything above drives SectionWalker with synthetic functions. All of it
# would still pass if someone dropped `_parse_sensors` from ENTRY_POINTS, and
# sensors would vanish from the real inventory exactly as they did before.
#
# This crosses the whole join: generator -> the real ori/config.py -> the real
# adapters -> the classification that lands in the artifact. Components tested
# and their join untested is the false-green shape these tests exist to catch.


@pytest.fixture(scope="module")
def real_entries() -> set[str]:
    from tests.golden.build_config_surface_inventory import CONFIG, collect

    return {row["path"] for row in collect(ast.parse(CONFIG.read_text()))}


@pytest.mark.parametrize(
    "path",
    [
        "sensors[].id",
        "sensors[].type",
        "sensors[].protocol",
        "sensors[].poll_interval_ms",
        "sensors[].calibration",
        "skills[].name",
        "skills[].version",
        "skills[].config",
    ],
)
def test_real_tree_carries_the_list_of_object_surface(
    real_entries: set[str], path: str
) -> None:
    """The whole of sensors and skills once vanished while the total stayed 169."""
    assert path in real_entries


@pytest.mark.parametrize(
    "path",
    [
        "security.config_signature.trust_anchor_env",
        "security.remote_commands.hmac_secret_env",
        "gateway.broker_posture.acl_policy",
        "actions.alert_outbox.batch_size",
        "state.encryption.mode",
    ],
)
def test_real_tree_reaches_nested_paths(real_entries: set[str], path: str) -> None:
    """Two separate bugs emptied whole sections; these are the deepest survivors."""
    assert path in real_entries


@pytest.mark.parametrize(
    "noise", ["verified", "signed_at_ms", "AT_API_KEY", "required"]
)
def test_real_tree_excludes_intermediate_dictionary_fields(
    real_entries: set[str], noise: str
) -> None:
    """These are not settings an operator can write.

    The first extractor reported them as configuration paths because it counted
    every dictionary access inside a parse function.
    """
    assert not any(path.rsplit(".", 1)[-1] == noise for path in real_entries)


@pytest.fixture(scope="module")
def real_coverage() -> dict:
    from tests.golden.build_config_surface_inventory import (
        CONFIG,
        collect,
        coverage,
        example_paths,
    )

    entries = collect(ast.parse(CONFIG.read_text()))
    return coverage(entries, example_paths())


def test_real_coverage_maps_baud_rate_to_the_usb_adapter_only(
    real_coverage: dict,
) -> None:
    """The defect in ori-runtime #411, shown through the real adapters.

    The shipped example sets `baud_rate` on a *serial* sensor, and only
    `UsbSerialAdapter` reads that spelling.
    """
    rows = {item["path"]: item for item in real_coverage["sensor_metadata"]}
    assert "sensors[].baud_rate" in rows
    assert rows["sensors[].baud_rate"]["read_by_adapters"] == ["UsbSerialAdapter"]


def test_real_coverage_credits_no_action_path_to_a_sensor_adapter(
    real_coverage: dict,
) -> None:
    """`actions.coap.timeout_s` and `actions.sms.gsm.port` were once credited here."""
    correlated = {item["path"] for item in real_coverage["sensor_metadata"]}
    assert not any(path.startswith("actions.") for path in correlated)
    assert all(path.startswith("sensors[]") for path in correlated)
