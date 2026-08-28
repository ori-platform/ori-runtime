# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Tests for the sensor configuration schema validator.

Cases are taken from the vector list in
`ori-specs/sensor-configuration/v1.md`, so coverage traces to the contract
rather than to whatever the implementation happened to make easy. The corpus
itself does not exist yet; when it does, these become the runtime's consumption
of it rather than a parallel set.

Schemas here are synthetic. No adapter declares one yet, and nothing in the
runtime calls this validator — the behaviour change lands atomically with the
declarations, so a validator and the surface it validates can never disagree
about which exists.
"""

from __future__ import annotations

import contextlib
import json
import logging
import random
from pathlib import Path
from typing import Any

import pytest

from ori.hal.config_schema import (
    DocumentError,
    SchemaError,
    ValidatedSchema,
    validate_document,
    validate_schema,
)

VECTORS = Path(__file__).parent / "vectors" / "sensor_configuration"
SCHEMA_LOAD_VECTORS = json.loads((VECTORS / "schema-load.json").read_text())["cases"]
PROTOCOL_CONFIG_VECTORS = json.loads((VECTORS / "protocol-config.json").read_text())[
    "cases"
]


def _ok(schema: dict) -> Any:
    """Validate a declaration and return the validated form.

    `validate_document` accepts only that, never a raw mapping.
    """
    return validate_schema(schema, name="test")


@pytest.mark.parametrize("case", SCHEMA_LOAD_VECTORS, ids=lambda case: case["name"])
def test_schema_load_conforms_to_the_vendored_contract_vectors(case: dict) -> None:
    """The hand-authored corpus, rather than a parallel runtime fixture, is authority."""
    schema = case.get("schema")
    if schema is None:
        schema = json.loads(case["schema_text"])
    if case["expect"] == "accepted":
        assert isinstance(validate_schema(schema, name="vector"), ValidatedSchema)
        return

    with pytest.raises(SchemaError) as excinfo:
        validate_schema(schema, name="vector")
    message = str(excinfo.value)
    for name in case["must_name"]:
        assert name in message


@pytest.mark.parametrize("case", PROTOCOL_CONFIG_VECTORS, ids=lambda case: case["name"])
def test_protocol_config_conforms_to_the_vendored_contract_vectors(
    case: dict, caplog: pytest.LogCaptureFixture
) -> None:
    """Accepted vectors also prove the exact mapping an adapter would receive."""
    schema = validate_schema(case["schema"], name=case["protocol"])
    with caplog.at_level(logging.WARNING):
        if case["expect"] == "accepted":
            assert (
                validate_document(
                    case["document"],
                    schema,
                    context=case["protocol"],
                    external=case.get("external"),
                )
                == case["resolved"]
            )
            for name in case.get("warns", []):
                assert name in caplog.text
            return

        with pytest.raises(DocumentError) as excinfo:
            validate_document(
                case["document"],
                schema,
                context=case["protocol"],
                external=case.get("external"),
            )
    message = str(excinfo.value)
    for name in case["must_name"]:
        assert name in message


# ── Schema load: the declaration is refused on its own terms ────────────────


@pytest.mark.parametrize(
    "schema, fragment",
    [
        ({"a": {}}, "'type' is required"),
        ({"a": {"type": "str"}}, "'type' is required"),
        ({"a": "not a mapping"}, "must be a mapping"),
        ({"a": {"type": "string", "nonsense": 1}}, "unknown descriptor"),
        ({"a": {"type": "object"}}, "must declare 'properties'"),
        ({"a": {"type": "array"}}, "must declare 'items'"),
        ({"a": {"type": "string", "properties": {}}}, "only valid on 'type: object'"),
        (
            {"a": {"type": "string", "items": {"type": "string"}}},
            "only valid on 'type: array'",
        ),
        ({"a": {"type": "string", "minimum": 1}}, "only valid on a numeric type"),
        ({"a": {"type": "integer", "minimum": 5, "maximum": 1}}, "exceeds maximum"),
        ({"a": {"type": "string", "enum": []}}, "non-empty list"),
        (
            {"a": {"type": "integer", "required": True, "default": 1}},
            "mutually exclusive",
        ),
        ({"a": {"type": "string", "deprecated": True}}, "requires 'supersedes'"),
        ({"a": {"type": "string", "supersedes": "b"}}, "only valid on a deprecated"),
    ],
)
def test_an_invalid_declaration_is_refused_when_the_schema_loads(
    schema: dict, fragment: str
) -> None:
    with pytest.raises(SchemaError, match=fragment):
        validate_schema(schema, name="test")


def test_a_default_the_descriptor_would_reject_is_refused() -> None:
    """Otherwise the defect appears only for the operator who omits the key."""
    with pytest.raises(SchemaError, match="default"):
        validate_schema({"a": {"type": "integer", "default": "1500"}}, name="test")


def test_a_default_outside_its_own_bounds_is_refused() -> None:
    with pytest.raises(SchemaError, match="below the minimum"):
        validate_schema(
            {"a": {"type": "integer", "default": 0, "minimum": 1}}, name="test"
        )


def test_closure_is_checked_at_every_depth() -> None:
    """An object nested inside an object must declare its properties too."""
    with pytest.raises(SchemaError, match=r"test\.a\.inner"):
        validate_schema(
            {"a": {"type": "object", "properties": {"inner": {"type": "object"}}}},
            name="test",
        )


# ── Schema load: references and groups ──────────────────────────────────────


@pytest.mark.parametrize(
    "schema, fragment",
    [
        ({"a": {"type": "string"}, "exactly_one_of": []}, "non-empty list"),
        ({"a": {"type": "string"}, "exactly_one_of": [[]]}, "is empty"),
        ({"a": {"type": "string"}, "exactly_one_of": [["ghost"]]}, "does not declare"),
        (
            {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "exactly_one_of": [["a"], ["a", "b"]],
            },
            "more than one group",
        ),
        (
            {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "exactly_one_of": [["a"], ["a"]],
            },
            "more than one group",
        ),
    ],
)
def test_a_malformed_group_is_refused_when_the_schema_loads(
    schema: dict, fragment: str
) -> None:
    with pytest.raises(SchemaError, match=fragment):
        validate_schema(schema, name="test")


def test_identical_groups_are_refused() -> None:
    """Two identical groups make 'exactly one' meaningless."""
    with pytest.raises(SchemaError, match="identical|more than one group"):
        validate_schema(
            {
                "a": {"type": "string"},
                "b": {"type": "string"},
                "at_least_one_of": [["a"], ["a"]],
            },
            name="test",
        )


def test_required_unless_naming_an_undeclared_field_is_refused() -> None:
    """The condition could never fire, so it fails by being silent."""
    with pytest.raises(SchemaError, match="could never fire"):
        validate_schema(
            {"a": {"type": "string", "required_unless": {"ghost": True}}}, name="test"
        )


@pytest.mark.parametrize(
    "path, fragment",
    [
        ("sensors.something", "inside sensors"),
        ("sensors", "inside sensors"),
        ("", "non-empty"),
        ("actions..coap", "empty segment"),
    ],
)
def test_a_bad_fallback_path_is_refused_when_the_schema_loads(
    path: str, fragment: str
) -> None:
    with pytest.raises(SchemaError, match=fragment):
        validate_schema({"a": {"type": "string", "fallback_from": path}}, name="test")


def test_must_be_subset_of_requires_an_array_field() -> None:
    with pytest.raises(SchemaError, match="requires 'type: array'"):
        validate_schema(
            {
                "a": {
                    "type": "string",
                    "must_be_subset_of": "actions.coap.allowed_hosts",
                }
            },
            name="test",
        )


# ── Documents: unknown keys and types ───────────────────────────────────────


def test_an_undeclared_key_is_refused_naming_what_is_declared() -> None:
    schema = _ok({"port": {"type": "string"}})
    with pytest.raises(DocumentError, match="not declared by the schema"):
        validate_document({"prot": "/dev/ttyUSB0"}, schema, context="sensors[0]")


def test_an_undeclared_nested_key_is_refused_by_full_path() -> None:
    """A refusal naming only the leaf is unactionable in a nested document."""
    schema = _ok(
        {"tls": {"type": "object", "properties": {"enabled": {"type": "boolean"}}}}
    )
    with pytest.raises(DocumentError, match=r"sensors\[0\]\.tls\.verify"):
        validate_document({"tls": {"verify": False}}, schema, context="sensors[0]")


@pytest.mark.parametrize(
    "kind, value",
    [
        ("integer", "1500"),
        ("integer", 1500.0),
        ("integer", True),
        ("string", 123),
        ("number", True),
        ("boolean", 1),
    ],
)
def test_values_are_not_coerced(kind: str, value: Any) -> None:
    """`7.0` is not `7`, and a boolean is not an integer.

    Coercion turns a malformed document into a working one whose author
    believes something else.
    """
    schema = _ok({"a": {"type": kind}})
    with pytest.raises(DocumentError, match="not coerced|expected"):
        validate_document({"a": value}, schema, context="sensors[0]")


def test_bounds_and_enums_are_enforced() -> None:
    schema = _ok({"a": {"type": "integer", "minimum": 100, "maximum": 60000}})
    with pytest.raises(DocumentError, match="below the minimum"):
        validate_document({"a": 99}, schema, context="s")
    with pytest.raises(DocumentError, match="above the maximum"):
        validate_document({"a": 60001}, schema, context="s")

    schema = _ok({"a": {"type": "string", "enum": ["N", "E", "O"]}})
    with pytest.raises(DocumentError, match="is not one of"):
        validate_document({"a": "X"}, schema, context="s")


def test_declared_defaults_are_applied() -> None:
    schema = _ok({"a": {"type": "integer", "default": 9600}, "b": {"type": "string"}})
    assert validate_document({}, schema, context="s") == {"a": 9600}


def test_a_required_field_missing_is_refused() -> None:
    schema = _ok({"port": {"type": "string", "required": True}})
    with pytest.raises(DocumentError, match="required and missing"):
        validate_document({}, schema, context="s")


# ── Documents: conditionals ─────────────────────────────────────────────────


def test_required_unless_is_satisfied_by_the_named_sibling() -> None:
    schema = _ok(
        {
            "device_path": {"type": "string", "required_unless": {"auto_detect": True}},
            "auto_detect": {"type": "boolean", "default": False},
        }
    )
    assert (
        validate_document({"auto_detect": True}, schema, context="s")["auto_detect"]
        is True
    )
    with pytest.raises(DocumentError, match="required unless"):
        validate_document({"auto_detect": False}, schema, context="s")


def _network_or_serial() -> Any:
    return _ok(
        {
            "host": {"type": "string"},
            "port": {"type": "integer"},
            "serial": {"type": "string"},
            "exactly_one_of": [["host", "port"], ["serial"]],
        }
    )


def test_exactly_one_of_accepts_one_complete_group() -> None:
    resolved = validate_document(
        {"host": "h", "port": 502}, _network_or_serial(), context="s"
    )
    assert resolved["host"] == "h"


def test_exactly_one_of_refuses_neither_group() -> None:
    with pytest.raises(DocumentError, match="exactly one of"):
        validate_document({}, _network_or_serial(), context="s")


def test_exactly_one_of_refuses_both_groups_complete() -> None:
    """Two complete alternatives fail the count, before any stray check."""
    with pytest.raises(DocumentError, match="exactly one of"):
        validate_document(
            {"host": "h", "port": 502, "serial": "/dev/ttyUSB0"},
            _network_or_serial(),
            context="s",
        )


def test_exactly_one_of_refuses_a_stray_from_the_unchosen_group() -> None:
    """Configured ambiguously, not twice.

    The stray case needs a group that stays *incomplete*: with every group
    complete the count check fires first, which is a different refusal. An
    earlier version of this test supplied all three keys and passed against
    that other message while claiming to cover this one.
    """
    schema = _ok(
        {
            "host": {"type": "string"},
            "port": {"type": "integer"},
            "device": {"type": "string"},
            "baud": {"type": "integer"},
            "exactly_one_of": [["host", "port"], ["device", "baud"]],
        }
    )
    with pytest.raises(DocumentError, match="not chosen|ambiguously"):
        validate_document(
            {"host": "h", "port": 502, "device": "/dev/ttyUSB0"}, schema, context="s"
        )


def test_exactly_one_of_does_not_apply_defaults_from_the_unselected_group() -> None:
    schema = _ok(
        {
            "host": {"type": "string"},
            "port": {"type": "integer", "default": 8899},
            "serial": {"type": "string"},
            "exactly_one_of": [["host", "port"], ["serial"]],
        }
    )
    assert validate_document({"serial": "/dev/ttyUSB0"}, schema, context="s") == {
        "serial": "/dev/ttyUSB0"
    }


def test_at_least_one_of_permits_more_than_one() -> None:
    """It is the mechanism for 'any of these will do'."""
    schema = _ok(
        {
            "a": {"type": "string"},
            "b": {"type": "string"},
            "at_least_one_of": [["a"], ["b"]],
        }
    )
    assert validate_document({"a": "x", "b": "y"}, schema, context="s") == {
        "a": "x",
        "b": "y",
    }
    with pytest.raises(DocumentError, match="at least one of"):
        validate_document({}, schema, context="s")


# ── Documents: deprecation ──────────────────────────────────────────────────


def _with_alias() -> Any:
    return _ok(
        {
            "baud_rate": {"type": "integer", "default": 9600},
            "baudrate": {
                "type": "integer",
                "deprecated": True,
                "supersedes": "baud_rate",
            },
        }
    )


def test_a_deprecated_alias_is_accepted_with_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        resolved = validate_document({"baudrate": 19200}, _with_alias(), context="s")
    assert resolved == {"baud_rate": 19200}
    assert "deprecated" in caplog.text
    assert "baud_rate" in caplog.text


def test_an_alias_and_its_replacement_together_are_refused() -> None:
    """Refused even when the values agree."""
    with pytest.raises(DocumentError, match="deprecated alias"):
        validate_document(
            {"baud_rate": 9600, "baudrate": 9600}, _with_alias(), context="s"
        )


def test_an_alias_resolves_across_an_object_boundary() -> None:
    schema = _ok(
        {
            "mqtt": {
                "type": "object",
                "properties": {"username": {"type": "string"}},
            },
            "mqtt_username": {
                "type": "string",
                "deprecated": True,
                "supersedes": "mqtt.username",
            },
        }
    )
    assert validate_document({"mqtt_username": "operator"}, schema, context="s") == {
        "mqtt": {"username": "operator"}
    }


def test_a_cross_path_alias_conflicts_with_a_written_canonical_value() -> None:
    schema = _ok(
        {
            "mqtt": {
                "type": "object",
                "properties": {"username": {"type": "string"}},
            },
            "mqtt_username": {
                "type": "string",
                "deprecated": True,
                "supersedes": "mqtt.username",
            },
        }
    )
    with pytest.raises(DocumentError, match=r"mqtt\.username"):
        validate_document(
            {"mqtt": {"username": "canonical"}, "mqtt_username": "legacy"},
            schema,
            context="s",
        )


def test_two_aliases_for_one_target_are_refused_without_schema_order_precedence() -> (
    None
):
    schema = _ok(
        {
            "mqtt": {
                "type": "object",
                "properties": {"client_id": {"type": "string"}},
            },
            "mqtt_client_id": {
                "type": "string",
                "deprecated": True,
                "supersedes": "mqtt.client_id",
            },
            "client_id": {
                "type": "string",
                "deprecated": True,
                "supersedes": "mqtt.client_id",
            },
        }
    )
    with pytest.raises(DocumentError) as excinfo:
        validate_document(
            {"mqtt_client_id": "first", "client_id": "second"}, schema, context="s"
        )
    message = str(excinfo.value)
    assert "mqtt_client_id" in message
    assert "client_id" in message
    assert "mqtt.client_id" in message


def test_alias_resolution_does_not_mutate_or_change_the_callers_document() -> None:
    schema = _ok(
        {
            "mqtt": {
                "type": "object",
                "properties": {
                    "username": {"type": "string"},
                    "keepalive": {"type": "integer"},
                },
            },
            "mqtt_username": {
                "type": "string",
                "deprecated": True,
                "supersedes": "mqtt.username",
            },
        }
    )
    document = {"mqtt_username": "operator", "mqtt": {"keepalive": 90}}
    expected = {"mqtt": {"username": "operator", "keepalive": 90}}
    assert validate_document(document, schema, context="s") == expected
    assert document == {"mqtt_username": "operator", "mqtt": {"keepalive": 90}}
    assert validate_document(document, schema, context="s") == expected


def test_an_alias_path_cannot_descend_through_a_deprecated_object() -> None:
    with pytest.raises(SchemaError, match="not an object"):
        validate_schema(
            {
                "mqtt": {
                    "type": "object",
                    "properties": {"username": {"type": "string"}},
                },
                "broker": {
                    "type": "object",
                    "deprecated": True,
                    "supersedes": "mqtt",
                },
                "legacy_username": {
                    "type": "string",
                    "deprecated": True,
                    "supersedes": "broker.username",
                },
            },
            name="test",
        )


@pytest.mark.parametrize(
    "alias, target, fragment",
    [
        ("mqtt.username", {"type": "string"}, "not an object"),
        (
            "brokers.username",
            {"type": "array", "items": {"type": "string"}},
            "not an object",
        ),
    ],
)
def test_an_alias_path_must_descend_only_through_objects(
    alias: str, target: dict, fragment: str
) -> None:
    with pytest.raises(SchemaError, match=fragment):
        validate_schema(
            {
                alias.split(".")[0]: target,
                "legacy": {"type": "string", "deprecated": True, "supersedes": alias},
            },
            name="test",
        )


@pytest.mark.parametrize("kind", ["array", "object"])
def test_a_structural_alias_needs_no_duplicate_contents_declaration(kind: str) -> None:
    target: dict[str, Any] = {"type": kind}
    if kind == "array":
        target["items"] = {"type": "string"}
    else:
        target["properties"] = {"value": {"type": "string"}}
    assert isinstance(
        validate_schema(
            {
                "canonical": target,
                "legacy": {"type": kind, "deprecated": True, "supersedes": "canonical"},
            },
            name="test",
        ),
        ValidatedSchema,
    )


@pytest.mark.parametrize(
    "property_name, value",
    [
        ("default", 1),
        ("minimum", 1),
        ("enum", [1]),
        ("required", True),
        ("fallback_from", "x"),
    ],
)
def test_an_alias_cannot_declare_competing_value_semantics(
    property_name: str, value: Any
) -> None:
    with pytest.raises(SchemaError, match=property_name):
        validate_schema(
            {
                "canonical": {"type": "integer"},
                "legacy": {
                    "type": "integer",
                    "deprecated": True,
                    "supersedes": "canonical",
                    property_name: value,
                },
            },
            name="test",
        )


# ── Documents: fallbacks, resolved at configuration load ────────────────────


def _coap() -> Any:
    return _ok(
        {
            "allowed_hosts": {
                "type": "array",
                "items": {"type": "string"},
                "fallback_from": "actions.coap.allowed_hosts",
                "must_be_subset_of": "actions.coap.allowed_hosts",
            },
            "timeout_s": {
                "type": "number",
                "fallback_from": "actions.coap.timeout_s",
                "minimum": 0,
            },
        }
    )


def _external(hosts: Any = None, timeout: Any = 2.0) -> dict:
    return {
        "actions": {
            "coap": {"allowed_hosts": hosts or ["a.example"], "timeout_s": timeout}
        }
    }


def test_a_fallback_applies_only_where_the_sensor_is_silent() -> None:
    resolved = validate_document({}, _coap(), context="s", external=_external())
    assert resolved["allowed_hosts"] == ["a.example"]
    assert resolved["timeout_s"] == 2.0

    resolved = validate_document(
        {"timeout_s": 5.0}, _coap(), context="s", external=_external()
    )
    assert resolved["timeout_s"] == 5.0, "the operator's value wins"


def test_an_inherited_value_the_descriptor_rejects_is_refused() -> None:
    """Arriving by inheritance is not a licence to be malformed.

    The adapter cannot tell how the value got there.
    """
    with pytest.raises(DocumentError, match="inherited from"):
        validate_document({}, _coap(), context="s", external=_external(timeout=-1))


def test_a_fallback_path_the_configuration_lacks_is_refused() -> None:
    """Refused rather than treated as absent."""
    with pytest.raises(DocumentError, match="does not contain"):
        validate_document({}, _coap(), context="s", external={"actions": {}})


def test_a_sensor_may_narrow_a_bounded_list() -> None:
    resolved = validate_document(
        {"allowed_hosts": ["a.example"]},
        _coap(),
        context="s",
        external=_external(["a.example", "b.example"]),
    )
    assert resolved["allowed_hosts"] == ["a.example"]


def test_a_sensor_may_not_widen_a_bounded_list() -> None:
    with pytest.raises(DocumentError, match="never widen"):
        validate_document(
            {"allowed_hosts": ["evil.example"]},
            _coap(),
            context="s",
            external=_external(["a.example"]),
        )


def test_a_bound_resolving_to_a_non_array_is_refused() -> None:
    with pytest.raises(DocumentError, match="not an array"):
        validate_document(
            {"allowed_hosts": ["a.example"]},
            _coap(),
            context="s",
            external={
                "actions": {"coap": {"allowed_hosts": "a.example", "timeout_s": 2.0}}
            },
        )


# ── The validator is not wired in yet ───────────────────────────────────────


def test_nothing_in_the_runtime_calls_this_validator_yet() -> None:
    """Asserts the scope this PR claims, so the claim cannot quietly lapse.

    Activation is atomic with the adapter declarations. If a loader starts
    calling the validator before every protocol declares a schema, some
    protocols would be validated and others not — an authority that exists for
    part of the surface is worse than one that does not exist yet, because it
    reads as complete.
    """
    import pathlib

    root = pathlib.Path("ori")
    callers = [
        path
        for path in root.rglob("*.py")
        if path.name != "config_schema.py" and "config_schema" in path.read_text()
    ]
    assert not callers, f"unexpected callers before atomic activation: {callers}"


# ── Regressions found in review ─────────────────────────────────────────────


def test_a_nested_default_is_applied() -> None:
    """Resolution recurses.

    An earlier version validated nested values but resolved only the top level,
    so `{"tls": {}}` came back unchanged with the declared inner default
    silently absent — the adapter then used its own.
    """
    schema = _ok(
        {
            "tls": {
                "type": "object",
                "properties": {"verify": {"type": "boolean", "default": True}},
            }
        }
    )
    assert validate_document({"tls": {}}, schema, context="s") == {
        "tls": {"verify": True}
    }


def test_a_nested_conditional_is_enforced() -> None:
    schema = _ok(
        {
            "tls": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "required_unless": {"auto": True}},
                    "auto": {"type": "boolean", "default": False},
                },
            }
        }
    )
    assert (
        validate_document({"tls": {"auto": True}}, schema, context="s")["tls"]["auto"]
        is True
    )
    with pytest.raises(DocumentError, match=r"s\.tls\.path: required unless"):
        validate_document({"tls": {"auto": False}}, schema, context="s")


def test_a_nested_required_field_is_enforced() -> None:
    schema = _ok(
        {
            "tls": {
                "type": "object",
                "properties": {"ca": {"type": "string", "required": True}},
            }
        }
    )
    with pytest.raises(DocumentError, match=r"s\.tls\.ca: required and missing"):
        validate_document({"tls": {}}, schema, context="s")


def test_objects_inside_arrays_resolve_too() -> None:
    schema = _ok(
        {
            "targets": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "host": {"type": "string"},
                        "port": {"type": "integer", "default": 502},
                    },
                },
            }
        }
    )
    resolved = validate_document({"targets": [{"host": "a"}]}, schema, context="s")
    assert resolved["targets"] == [{"host": "a", "port": 502}]


def test_supersedes_must_name_a_declared_field() -> None:
    """An alias for a key that does not exist warns an operator towards nothing."""
    with pytest.raises(SchemaError, match="does not declare"):
        validate_schema(
            {"a": {"type": "integer", "deprecated": True, "supersedes": "ghost"}},
            name="test",
        )


def test_a_fallback_without_the_surrounding_configuration_is_refused() -> None:
    """The bound must not disappear when no context is supplied.

    Previously a field declaring `must_be_subset_of` validated as absent with
    `external=None`, and a widening value passed — the bound existed only when
    someone remembered to pass the configuration.
    """
    schema = _ok(
        {
            "h": {
                "type": "array",
                "items": {"type": "string"},
                "fallback_from": "actions.coap.allowed_hosts",
                "must_be_subset_of": "actions.coap.allowed_hosts",
            }
        }
    )
    with pytest.raises(DocumentError, match="can only be resolved"):
        validate_document({}, schema, context="s")
    with pytest.raises(DocumentError, match="can only be resolved"):
        validate_document({"h": ["evil.example"]}, schema, context="s")


def test_validate_document_refuses_an_unvalidated_schema() -> None:
    """The type is the boundary.

    `{"a": {}}` against an empty document raised nothing, because no descriptor
    was ever consulted.
    """
    with pytest.raises(
        SchemaError, match="requires a schema returned by validate_schema"
    ):
        validate_document({}, {"a": {}}, context="s")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "descriptor, fragment",
    [
        ({"type": "integer", "minimum": "x"}, "must be numeric"),
        ({"type": "integer", "maximum": True}, "must not be a boolean"),
        ({"type": "string", "required": "yes"}, "must be bool"),
        ({"type": "string", "deprecated": 1}, "must be bool"),
        ({"type": "string", "required_unless": "a"}, "must be dict"),
    ],
)
def test_a_malformed_descriptor_property_is_a_schema_error(
    descriptor: dict, fragment: str
) -> None:
    """Never a raw TypeError during a later comparison, which blames the wrong party."""
    with pytest.raises(SchemaError, match=fragment):
        validate_schema({"a": descriptor}, name="test")


# ── Regressions: the recursive contract ─────────────────────────────────────


def test_a_nested_required_unless_reference_is_validated() -> None:
    """A nested object is its own namespace, and references resolve inside it."""
    with pytest.raises(SchemaError, match="could never fire"):
        validate_schema(
            {
                "o": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "string", "required_unless": {"ghost": True}}
                    },
                }
            },
            name="test",
        )


def test_a_nested_supersedes_target_is_validated() -> None:
    with pytest.raises(SchemaError, match="does not declare"):
        validate_schema(
            {
                "o": {
                    "type": "object",
                    "properties": {
                        "old": {
                            "type": "integer",
                            "deprecated": True,
                            "supersedes": "ghost",
                        }
                    },
                }
            },
            name="test",
        )


def test_references_inside_array_items_are_validated() -> None:
    with pytest.raises(SchemaError, match="could never fire"):
        validate_schema(
            {
                "t": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "a": {"type": "string", "required_unless": {"ghost": True}}
                        },
                    },
                }
            },
            name="test",
        )


def test_a_nested_alias_and_its_replacement_together_are_refused() -> None:
    """Deprecation is checked at every level, not only the top."""
    schema = _ok(
        {
            "o": {
                "type": "object",
                "properties": {
                    "new": {"type": "integer", "default": 1},
                    "old": {"type": "integer", "deprecated": True, "supersedes": "new"},
                },
            }
        }
    )
    with pytest.raises(DocumentError, match="deprecated alias"):
        validate_document({"o": {"new": 1, "old": 1}}, schema, context="s")


def test_a_nested_alias_alone_warns(caplog: pytest.LogCaptureFixture) -> None:
    schema = _ok(
        {
            "o": {
                "type": "object",
                "properties": {
                    "new": {"type": "integer", "default": 1},
                    "old": {"type": "integer", "deprecated": True, "supersedes": "new"},
                },
            }
        }
    )
    with caplog.at_level(logging.WARNING):
        validate_document({"o": {"old": 5}}, schema, context="s")
    assert "deprecated" in caplog.text


def test_a_conditional_sees_the_resolved_sibling_not_the_raw_input() -> None:
    """Defaults are applied before requirements are evaluated.

    Previously the condition read the raw document, saw `None` where a default
    would have supplied `"auto"`, and refused a document that was complete.
    """
    schema = _ok(
        {
            "mode": {"type": "string", "default": "auto"},
            "path": {"type": "string", "required_unless": {"mode": "auto"}},
        }
    )
    assert validate_document({}, schema, context="s") == {"mode": "auto"}
    with pytest.raises(DocumentError, match="required unless"):
        validate_document({"mode": "manual"}, schema, context="s")


def test_a_bounded_array_of_objects_produces_a_verdict_not_a_crash() -> None:
    """The contract permits object items, and `set()` cannot hash them.

    A crash is the one outcome a validator must never produce.
    """
    schema = _ok(
        {
            "targets": {
                "type": "array",
                "items": {"type": "object", "properties": {"host": {"type": "string"}}},
                "must_be_subset_of": "allow",
            }
        }
    )
    external = {"allow": [{"host": "a"}, {"host": "b"}]}
    assert validate_document(
        {"targets": [{"host": "a"}]}, schema, context="s", external=external
    )

    with pytest.raises(DocumentError, match="never widen"):
        validate_document(
            {"targets": [{"host": "evil"}]},
            schema,
            context="s",
            external={"allow": [{"host": "a"}]},
        )


def test_a_conditional_is_satisfied_by_the_siblings_fallback() -> None:
    """A condition reads the sibling's *resolved* value, and inheritance resolves it.

    Covering only `default` would leave the ordering claim half-proved: if
    `fallback_from` were applied after requirements were evaluated, a document
    the deployment already answers would be refused, and the operator would be
    told to write a value that is sitting one section away.
    """
    schema = _ok(
        {
            "mode": {"type": "string", "fallback_from": "device.mode"},
            "path": {"type": "string", "required_unless": {"mode": "auto"}},
        }
    )
    resolved = validate_document(
        {}, schema, context="s", external={"device": {"mode": "auto"}}
    )
    assert resolved["mode"] == "auto", "inherited before the condition is evaluated"

    with pytest.raises(DocumentError, match="required unless"):
        validate_document(
            {}, schema, context="s", external={"device": {"mode": "manual"}}
        )


# ── ori-specs#118: conditional cycles, direct and indirect ──────────────────


def _conditional(**deps: Any) -> dict:
    """A schema of string fields, each optionally `required_unless` another."""
    return {
        name: {"type": "string", **({"required_unless": dep} if dep else {})}
        for name, dep in deps.items()
    }


def test_an_acyclic_conditional_chain_is_accepted() -> None:
    """`a` unless `b`, `b` unless `c` has exactly one evaluation order.

    An earlier implementation refused any conditional naming another
    conditional. That was wrong in both directions: it rejected chains that
    resolve fine, and missed cycles longer than two.
    """
    validated = validate_schema(
        _conditional(a={"b": "x"}, b={"c": "x"}, c=None), name="test"
    )
    assert isinstance(validated, ValidatedSchema), "usable, not merely not-refused"


def test_a_direct_conditional_cycle_is_refused() -> None:
    with pytest.raises(SchemaError, match="form a cycle"):
        validate_schema(_conditional(a={"b": "x"}, b={"a": "x"}), name="test")


def test_an_indirect_conditional_cycle_is_refused() -> None:
    """The case the one-level rule could not see."""
    with pytest.raises(SchemaError, match="form a cycle"):
        validate_schema(
            _conditional(a={"b": "x"}, b={"c": "x"}, c={"a": "x"}), name="test"
        )


def test_a_self_referential_condition_is_refused() -> None:
    with pytest.raises(SchemaError, match="form a cycle"):
        validate_schema(_conditional(a={"a": "x"}), name="test")


def test_the_refusal_names_the_cycle() -> None:
    """The author has to see which declarations form it."""
    with pytest.raises(SchemaError) as excinfo:
        validate_schema(
            _conditional(a={"b": "x"}, b={"c": "x"}, c={"a": "x"}), name="test"
        )
    chain = str(excinfo.value).split("form a cycle: ")[1].split(".")[0]
    assert chain == "a -> b -> c -> a", "every member, in dependency order, closed"


def test_the_cycle_is_reported_canonically_however_it_is_entered() -> None:
    """Same cycle, reached directly and reached through a lead-in field.

    `a -> c` only leads into the `b <-> c` cycle; it is not part of it. Walking
    from `a` first reaches the cycle at `c`, walking from `b` reaches it at `b`.
    Reporting whichever node the walk happened to arrive at makes one defect
    read as two, so the cycle is rotated to start at its lowest-sorting member.
    """
    entered_from_outside = _conditional(a={"c": "x"}, b={"c": "x"}, c={"b": "x"})
    entered_directly = _conditional(b={"c": "x"}, c={"b": "x"})
    messages = []
    for schema in (entered_from_outside, entered_directly):
        with pytest.raises(SchemaError) as excinfo:
            validate_schema(schema, name="test")
        messages.append(str(excinfo.value))
    assert "b -> c -> b" in messages[0]
    assert messages[0] == messages[1]


def test_the_lead_in_field_is_not_reported_as_part_of_the_cycle() -> None:
    """`a` depends on the cycle without being in it. Naming it misdirects."""
    with pytest.raises(SchemaError) as excinfo:
        validate_schema(
            _conditional(a={"c": "x"}, b={"c": "x"}, c={"b": "x"}), name="test"
        )
    chain = str(excinfo.value).split("form a cycle: ")[1].split(".")[0]
    assert chain == "b -> c -> b"


def test_cycles_are_detected_per_object_scope() -> None:
    """A nested object is its own namespace, so its cycle is its own."""
    with pytest.raises(SchemaError, match=r"test\.o.*form a cycle"):
        validate_schema(
            {
                "o": {
                    "type": "object",
                    "properties": _conditional(a={"b": "x"}, b={"a": "x"}),
                }
            },
            name="test",
        )


# ── schema-descriptor/v1: strengthened bounds ───────────────────────────────


@pytest.mark.parametrize(
    "descriptor, fragment",
    [
        ({"type": "number", "minimum": float("inf")}, "must be finite"),
        ({"type": "number", "maximum": float("-inf")}, "must be finite"),
        ({"type": "number", "minimum": float("nan")}, "must be finite"),
        ({"type": "integer", "minimum": 1.5}, "must be an integer"),
        ({"type": "integer", "maximum": 9.75}, "must be an integer"),
        ({"type": "integer", "minimum": True}, "must not be a boolean"),
        ({"type": "number", "maximum": False}, "must not be a boolean"),
    ],
)
def test_a_bound_the_core_forbids_is_refused(descriptor: dict, fragment: str) -> None:
    """`NaN` is the worst case: every comparison against it is false.

    The declaration reads as a constraint and enforces nothing.
    """
    with pytest.raises(SchemaError, match=fragment):
        validate_schema({"a": descriptor}, name="test")


@pytest.mark.parametrize(
    "descriptor",
    [
        {"type": "integer", "minimum": 1, "maximum": 60000},
        {"type": "number", "minimum": 1.5},
        {"type": "number", "minimum": -273.15, "maximum": 0.0},
    ],
)
def test_a_well_formed_bound_is_accepted(descriptor: dict) -> None:
    assert isinstance(validate_schema({"a": descriptor}, name="test"), ValidatedSchema)


# ── Hostile schemas: a malformed declaration is a verdict, never a traceback ─


# Large enough that CPython refuses to render it as a string (the cap is 4300
# digits), which is the property under test rather than the size itself.
_HUGE = 10**10000


def test_mixed_type_field_names_are_refused_not_sorted() -> None:
    """`sorted()` over `{1, "a"}` raises TypeError, which is not a verdict.

    YAML admits `1:` as a key, so this arrives from a real file rather than only
    from a test.
    """
    with pytest.raises(SchemaError, match="field names must be strings"):
        validate_schema(
            {
                1: {"type": "string", "required_unless": {"a": "x"}},
                "a": {"type": "string", "required_unless": {1: "x"}},
            },
            name="test",
        )


@pytest.mark.parametrize(
    "schema, fragment",
    [
        ({1: {"type": "string"}}, "field names must be strings"),
        (
            {"a": {"type": "string", 1: "x", "zz": "y"}},
            "descriptor properties must be strings",
        ),
        (
            {
                "o": {
                    "type": "object",
                    "properties": {1: {"type": "string"}, "b": {"type": "string"}},
                }
            },
            "'properties' keys must be strings",
        ),
    ],
)
def test_a_non_string_key_is_refused_at_every_level(
    schema: dict, fragment: str
) -> None:
    """Including the nested levels, where a later `sorted()` would also crash."""
    with pytest.raises(SchemaError, match=fragment):
        validate_schema(schema, name="test")


def test_a_non_string_conditional_target_is_refused_by_type() -> None:
    """Named by type, rather than reported as an absent field.

    Once field names must be strings, an integer target can never resolve; the
    author needs to be told which mistake they made.
    """
    with pytest.raises(SchemaError, match=r"names 1 \(int\)"):
        validate_schema(
            {
                "a": {"type": "string", "required_unless": {1: "x"}},
                "b": {"type": "string"},
            },
            name="test",
        )


@pytest.mark.parametrize(
    "descriptor",
    [
        {"type": "integer", "minimum": _HUGE},
        {"type": "number", "minimum": _HUGE},
        {"type": "integer", "maximum": -_HUGE},
    ],
)
def test_an_arbitrary_size_integer_bound_is_a_normal_bound(descriptor: dict) -> None:
    """`math.isfinite` converts its argument, so it overflows on a large int.

    An integer is finite however many digits it has, so this is accepted rather
    than refused — the interpreter's conversion limit is not a contract rule.
    """
    assert isinstance(validate_schema({"a": descriptor}, name="test"), ValidatedSchema)


def test_a_huge_bound_still_produces_a_document_verdict() -> None:
    """Both outcomes: the refusal renders, and the acceptance round-trips."""
    schema = validate_schema({"a": {"type": "integer", "minimum": _HUGE}}, name="test")
    with pytest.raises(DocumentError, match="is below the minimum"):
        validate_document({"a": 5}, schema, context="s")
    assert validate_document({"a": _HUGE}, schema, context="s")["a"] == _HUGE


@pytest.mark.parametrize(
    "schema, kwargs, fragment",
    [
        (
            {"a": {"type": "integer", "minimum": _HUGE, "maximum": 1}},
            {},
            "exceeds maximum",
        ),
        (
            {"a": {"type": "integer", "default": _HUGE, "maximum": 1}},
            {},
            "is above the maximum",
        ),
        ({_HUGE: {"type": "string"}}, {}, "field names must be strings"),
    ],
)
def test_refusing_a_huge_number_does_not_crash_while_naming_it(
    schema: dict, kwargs: dict, fragment: str
) -> None:
    """The check was never the fragile part — rendering the message was.

    CPython raises ValueError past 4300 digits, so the refusal crashed on the
    value it existed to report.
    """
    with pytest.raises(SchemaError, match=fragment) as excinfo:
        validate_schema(schema, name="test", **kwargs)
    assert "bits>" in str(excinfo.value), "abbreviated rather than rendered in full"


def test_a_huge_value_outside_an_enum_is_reported() -> None:
    """An `enum` is a list, so the list rendering has to be safe too."""
    schema = validate_schema({"a": {"type": "integer", "enum": [_HUGE]}}, name="test")
    with pytest.raises(DocumentError, match="is not one of"):
        validate_document({"a": 1}, schema, context="s")


@pytest.mark.parametrize(
    "schema, fragment",
    [
        ({"a": {"type": []}}, "'type' is required"),
        ({"a": {"type": {}}}, "'type' is required"),
        ({"a": {"type": {"x"}}}, "'type' is required"),
        ({"a": {"type": _HUGE}}, "'type' is required"),
        ({"a": {"type": "integer", "minimum": [_HUGE]}}, "must be numeric"),
    ],
)
def test_an_unrenderable_or_unhashable_type_is_refused(
    schema: dict, fragment: str
) -> None:
    """`kind not in _TYPES` hashes its left operand, so `type: []` crashed the
    membership test before the refusal below it could fire — and a `type` too
    large to render crashed the refusal itself.
    """
    with pytest.raises(SchemaError, match=fragment):
        validate_schema(schema, name="test")


def test_a_huge_document_value_of_the_wrong_type_is_reported() -> None:
    """The mismatch message names the value, so it has to survive naming it."""
    schema = validate_schema({"a": {"type": "boolean"}}, name="test")
    with pytest.raises(DocumentError, match="expected boolean"):
        validate_document({"a": _HUGE}, schema, context="s")


def test_a_huge_value_against_a_conditional_is_reported() -> None:
    """The refusal interpolates the condition's value and the document's."""
    schema = validate_schema(
        {
            "mode": {"type": "integer"},
            "path": {"type": "string", "required_unless": {"mode": _HUGE}},
        },
        name="test",
    )
    with pytest.raises(DocumentError, match="required unless"):
        validate_document({"mode": 1}, schema, context="s")


@pytest.mark.parametrize(
    "document",
    [
        None,
        1,
        1.5,
        True,
        "x",
        b"x",
        [],
        ["a"],
        (),
        {1, 2},
        # An explicit id: pytest renders a bare parameter to name the case, and
        # rendering this one raises the very ValueError under test — at
        # collection, so the whole module fails to load.
        pytest.param(_HUGE, id="oversized_integer"),
    ],
)
def test_a_non_object_document_is_refused_at_the_boundary(document: Any) -> None:
    """The top level gets the check every nested level already had.

    `_check_groups` iterates the document, so a scalar raised TypeError before
    any verdict existed. The tests for hostile *values* all passed a well-formed
    `{"a": ...}` wrapper, so none of them reached this.
    """
    schema = validate_schema({"a": {"type": "string"}}, name="test")
    with pytest.raises(DocumentError, match="expected object"):
        validate_document(document, schema, context="s")


@pytest.mark.parametrize("document", [None, 1, "x", (), b"x", []])
def test_a_non_object_document_is_refused_for_its_shape_not_its_groups(
    document: Any,
) -> None:
    """A group constraint must not answer first.

    A string, tuple or bytes document iterates successfully, so the group check
    produced a verdict — "exactly one of [['a']] must be fully present" — that
    blamed the operator for a missing field rather than for handing over
    something that is not a mapping. A confident wrong answer is worse than the
    traceback the scalars produced, because it reads as a real finding.
    """
    schema = validate_schema(
        {"a": {"type": "string"}, "exactly_one_of": [["a"]]}, name="test"
    )
    with pytest.raises(DocumentError, match="expected object") as excinfo:
        validate_document(document, schema, context="s")
    assert "exactly one of" not in str(excinfo.value)


def test_the_boundary_refusal_renders_a_hostile_document_safely() -> None:
    """The boundary message names the document, so it goes through `_show` too."""
    schema = validate_schema({"a": {"type": "string"}}, name="test")
    hostile: list[tuple[Any, str]] = [
        (_recursive_list(), "<circular reference>"),
        (_RaisingRepr(), "<_RaisingRepr>"),
        (_HUGE, "<integer of 33220 bits>"),
    ]
    document: Any
    expected: str
    for document, expected in hostile:
        with pytest.raises(DocumentError) as excinfo:
            validate_document(document, schema, context="s")
        assert expected in str(excinfo.value)


def _recursive_list() -> list:
    inner: list = []
    inner.append(inner)
    return inner


def _recursive_dict() -> dict:
    inner: dict = {}
    inner["self"] = inner
    return inner


def _mutually_recursive() -> list:
    first: list = []
    second: list = [first]
    first.append(second)
    return first


def _deeply_nested(depth: int) -> list:
    outer: list = []
    cursor = outer
    for _ in range(depth):
        nested: list = []
        cursor.append(nested)
        cursor = nested
    return outer


class _RaisingRepr:
    """`__repr__` is caller code, so it may do anything, including raise."""

    def __repr__(self) -> str:
        raise RuntimeError("this repr raises")


@pytest.mark.parametrize(
    "value, expected",
    [
        ({"x": _HUGE}, "<integer of 33220 bits>"),
        ({"x": {"y": _HUGE}}, "<integer of 33220 bits>"),
        ({_HUGE}, "<integer of 33220 bits>"),
        (frozenset({_HUGE}), "<integer of 33220 bits>"),
        ((_HUGE,), "<integer of 33220 bits>"),
        ([_HUGE], "<integer of 33220 bits>"),
        (_recursive_list(), "<circular reference>"),
        (_recursive_dict(), "<circular reference>"),
        (_mutually_recursive(), "<circular reference>"),
        (_deeply_nested(20000), "nested past depth"),
        (_RaisingRepr(), "<_RaisingRepr>"),
    ],
)
def test_a_hostile_document_value_is_reported_not_raised(
    value: Any, expected: str
) -> None:
    """Every way of *reporting* a bad value is a way of touching it.

    A validator whose contract is refusal must not answer a malformed document
    with a traceback. Each of these crashed the message that names the value:
    oversized integers past CPython's 4300-digit conversion cap, cycles and
    excessive nesting through RecursionError, and a `__repr__` that raises.
    """
    schema = validate_schema({"a": {"type": "integer"}}, name="test")
    with pytest.raises(DocumentError) as excinfo:
        validate_document({"a": value}, schema, context="s")
    assert expected in str(excinfo.value)


def test_a_wide_container_is_elided_rather_than_reproduced() -> None:
    """An error message names what the operator wrote; it is not a copy of it."""
    schema = validate_schema({"a": {"type": "integer"}}, name="test")
    with pytest.raises(DocumentError) as excinfo:
        validate_document({"a": list(range(1000))}, schema, context="s")
    message = str(excinfo.value)
    assert "... (1000 items)" in message
    assert "999" not in message, "elided, not merely truncated at the end"


def test_a_dict_with_unorderable_keys_is_rendered() -> None:
    """Rendering must not sort: mixed key types are what cannot be ordered."""
    schema = validate_schema({"a": {"type": "integer"}}, name="test")
    with pytest.raises(DocumentError, match="expected integer"):
        validate_document({"a": {1: "a", "b": 2, None: 3}}, schema, context="s")


def test_an_oversized_text_value_is_truncated_with_its_length() -> None:
    schema = validate_schema({"a": {"type": "integer"}}, name="test")
    for value, unit in ((("z" * 10**6), "characters"), ((b"z" * 10**6), "bytes")):
        with pytest.raises(DocumentError) as excinfo:
            validate_document({"a": value}, schema, context="s")
        assert f"(1000000 {unit})" in str(excinfo.value)


def _well_formed(rng: random.Random, depth: int = 0) -> dict:
    """A descriptor the validator accepts, so perturbing it reaches phase two."""
    kind = rng.choice(["string", "integer", "number", "boolean", "array", "object"])
    d: dict = {"type": kind}
    if kind == "object":
        d["properties"] = (
            {
                n: _well_formed(rng, depth + 1)
                for n in rng.sample(["p", "q"], rng.randint(1, 2))
            }
            if depth < 2
            else {"p": {"type": "string"}}
        )
    elif kind == "array":
        d["items"] = _well_formed(rng, depth + 1) if depth < 2 else {"type": "string"}
    elif kind in ("integer", "number"):
        if rng.random() < 0.5:
            d["minimum"] = (
                rng.choice([0, 1, -5]) if kind == "integer" else rng.choice([0, 1.5])
            )
        if rng.random() < 0.4:
            d["maximum"] = rng.choice([10, 100]) if kind == "integer" else 10.0
        if rng.random() < 0.3:
            d["default"] = rng.choice([0, 1]) if kind == "integer" else 1.0
    elif rng.random() < 0.3:
        d["default"] = "x" if kind == "string" else True
    return d


_HOSTILE = [
    None,
    True,
    False,
    0,
    -1,
    1.5,
    float("inf"),
    float("nan"),
    _HUGE,
    -_HUGE,
    "",
    b"x",
    (),
    [],
    {},
    {"a": 1, "b": 2},
    [_HUGE],
    # Containers that crash a naive renderer are in the pool deliberately: the
    # first sweep reported zero exceptions while generating none of them, so its
    # result was narrower than it read.
    {"x": _HUGE},
    {"x": {"y": _HUGE}},
    {_HUGE},
    (_HUGE,),
    frozenset({_HUGE}),
    "z" * 10**5,
    _recursive_list(),
    _recursive_dict(),
    _mutually_recursive(),
    _deeply_nested(20000),
    _RaisingRepr(),
    list(range(1000)),
    {1: "a", "b": 2, None: 3},
]
_HOSTILE_KEYS = [1, None, True, 1.5, "", "unknown"]


def _perturb(rng: random.Random, schema: dict) -> dict:
    """One hostile edit to an otherwise valid schema."""
    field = rng.choice(list(schema))
    d = dict(schema[field])
    match rng.choice(["key", "value", "cond", "type", "nested_key", "bound"]):
        case "key":
            d[rng.choice(_HOSTILE_KEYS)] = rng.choice(_HOSTILE)
        case "value":
            d[rng.choice(list(d))] = rng.choice(_HOSTILE)
        case "cond":
            d["required_unless"] = rng.choice(
                [
                    {rng.choice([*schema, 1, "nope"]): rng.choice(_HOSTILE)},
                    {},
                    {"a": 1, "b": 2},
                    "a",
                ]
            )
        case "type":
            d["type"] = rng.choice([*_HOSTILE, "int", "Object"])
        case "nested_key" if isinstance(d.get("properties"), dict):
            d["properties"] = {
                **d["properties"],
                rng.choice(_HOSTILE_KEYS): {"type": "string"},
            }
        case _:
            d[rng.choice(["minimum", "maximum"])] = rng.choice(_HOSTILE)
    out = dict(schema)
    out[field] = d
    if rng.random() < 0.15:
        out[rng.choice(_HOSTILE_KEYS)] = {"type": "string"}
    return out


@pytest.mark.parametrize("seed", [20260827, 1, 99, 424242, 7])
def test_no_hostile_schema_escapes_as_an_interpreter_error(seed: int) -> None:
    """A malformed declaration is always a verdict, whatever shape it takes.

    Five crashes reached review as tracebacks — an unorderable key set, an
    oversized bound, an unhashable `type`, an unrenderable `type`, and an
    oversized document value. Every one was structural rather than particular,
    and the enumerated cases above only cover the ones that were found. This
    covers the class, so the next one fails here rather than at a device's
    startup.

    Schemas are built well-formed and then given one hostile edit, because
    fully random descriptors are almost never valid and would leave document
    validation — half the surface — effectively unexercised.

    Five fixed seeds, so this is deterministic rather than flaky, and a failure
    names the seed that produced it. Roughly 25,000 cases and 6,500 document
    verdicts in about 0.2s — cheap enough that the committed budget is close to
    what an ad-hoc sweep would explore, which matters because only what is
    committed here runs in CI.
    """
    rng = random.Random(seed)
    reached_document = 0
    carried_a_declared_field = 0
    refused_at_load = 0
    non_mapping_documents = 0

    for _ in range(5000):
        names = rng.sample(["a", "b", "c"], rng.randint(1, 3))
        schema = {name: _well_formed(rng) for name in names}
        if rng.random() < 0.75:
            schema = _perturb(rng, schema)
        try:
            validated = validate_schema(schema, name="t")
        except SchemaError:
            refused_at_load += 1
            continue

        document: dict = {}
        for name in names:
            if rng.random() < 0.8:
                document[name] = rng.choice([*_HOSTILE, "x", 5, 5.0, {"p": "x"}, ["x"]])
        if rng.random() < 0.2:
            document[rng.choice(_HOSTILE_KEYS)] = 1

        # The document boundary itself, not only the values inside it: every
        # earlier case passed a well-formed mapping, so a scalar document
        # reached `_check_groups` and raised TypeError unexamined.
        maybe_document: Any = document
        if rng.random() < 0.2:
            maybe_document = rng.choice(_HOSTILE)
            if not isinstance(maybe_document, dict):
                non_mapping_documents += 1

        # A non-mapping `external` is refused the same way a non-mapping
        # document is, so both boundaries vary together.
        external: Any = rng.choice([None, {}, {"x": {"y": 1}}, 1, "x", []])

        reached_document += 1
        # A *declared* field, not merely a truthy document: a string, an
        # integer, or a mapping of nothing but undeclared keys is refused
        # before `_resolve_value` and `_check_value` are ever reached, so
        # counting those proved nothing about value validation.
        if isinstance(maybe_document, dict) and any(
            key in validated.fields for key in maybe_document
        ):
            carried_a_declared_field += 1

        with contextlib.suppress(SchemaError, DocumentError):
            validate_document(
                maybe_document,
                validated,
                context="s",
                external=external,
            )

    # Guards the generator, not the validator. Four counters, because each
    # weaker version passed against a generator that had stopped exercising
    # something: an empty document still "reached document validation"; a
    # truthy one still carried no declared field; well-formed-only schemas
    # still validated; and dropping non-mapping documents still left the
    # value paths busy.
    assert reached_document > 800, (
        f"only {reached_document} cases reached document validation — "
        f"the generator has stopped producing valid schemas"
    )
    assert refused_at_load > 1000, (
        f"only {refused_at_load} schemas were refused at load — the hostile "
        f"edit is no longer being applied, so only the document half is tested"
    )
    assert non_mapping_documents > 150, (
        f"only {non_mapping_documents} non-mapping documents were tried — the "
        f"document boundary itself is no longer being exercised"
    )
    assert carried_a_declared_field > 500, (
        f"only {carried_a_declared_field} documents carried a declared field — "
        f"the generator is no longer producing values that reach value checking"
    )
