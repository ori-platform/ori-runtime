# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Validator for adapter-declared sensor configuration schemas.

Implements `ori-specs/sensor-configuration/v1.md`. Nothing in the runtime uses
this yet: adapters do not declare schemas, and the loader does not call it. The
behaviour change lands atomically with the declarations, so that a validator and
the surface it validates never disagree about which exists.

Two failure modes, kept apart because they blame different people:

`SchemaError` means the *declaration* is wrong, and is raised when the schema is
loaded rather than when a document happens to exercise it. An object descriptor
with no properties, a default the descriptor would reject, a conditional naming
a field that does not exist — none of those need a document to be wrong, and
none should wait for one.

`DocumentError` means the *configuration* is wrong. It always carries the path
to the offending key, because a refusal naming only the leaf is unactionable in
a nested document.
"""

from __future__ import annotations

import logging
import math
from typing import Any

logger = logging.getLogger(__name__)

_TYPES: dict[str, type | tuple[type, ...]] = {
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "array": list,
    "object": dict,
}
_NUMERIC = {"integer", "number"}

# A fallback path a sensor could write is not a bound.
_FORBIDDEN_FALLBACK_ROOT = "sensors"

_DESCRIPTOR_KEYS = {
    "type",
    "required",
    "default",
    "minimum",
    "maximum",
    "enum",
    "properties",
    "items",
    "deprecated",
    "supersedes",
    "required_unless",
    "fallback_from",
    "must_be_subset_of",
    "description",
}
_SCHEMA_CONSTRAINTS = {"exactly_one_of", "at_least_one_of"}


class SchemaError(Exception):
    """The declaration is invalid. Raised when the schema is loaded."""


class DocumentError(Exception):
    """The configuration is invalid against a valid declaration."""


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else str(key)


# ── Schema load ──────────────────────────────────────────────────────────────


def validate_schema(schema: Any, *, name: str) -> ValidatedSchema:
    """Check a declaration on its own terms, with no document in hand.

    `name` identifies the schema in errors — a protocol, or a `(protocol, type)`
    calibration pair. Returns the validated form, which is the only thing
    `validate_document` accepts.
    """
    if not isinstance(schema, dict):
        raise SchemaError(
            f"{name}: a schema must be a mapping, got {type(schema).__name__}"
        )

    _require_string_keys(schema, name, "field names")

    fields = {k: v for k, v in schema.items() if k not in _SCHEMA_CONSTRAINTS}
    groups = {k: v for k, v in schema.items() if k in _SCHEMA_CONSTRAINTS}

    for key, descriptor in fields.items():
        _validate_descriptor(descriptor, _join(name, key))

    for constraint, value in groups.items():
        _validate_groups(value, set(fields), name, constraint)

    _validate_references_in(fields, name)

    return ValidatedSchema(name, fields, groups)


# Bounds for _show. Deliberately small: this renders a value into an error
# message, where the reader needs to recognise what they wrote, not receive it
# back in full.
_SHOW_MAX_INT_BITS = 3300  # ~993 digits, under CPython's 4300-digit cap
_SHOW_MAX_TEXT = 120
_SHOW_MAX_ITEMS = 8
_SHOW_MAX_DEPTH = 4


def _show(value: Any, _depth: int = 0, _seen: frozenset[int] = frozenset()) -> str:
    """Render a value for a message without letting the rendering itself fail.

    A validator whose contract is refusal must not answer a malformed document
    with a traceback, and every way of *reporting* a bad value is a way of
    touching it. Four things go wrong with the obvious `repr()`:

    - CPython caps int-to-string conversion at 4300 digits and raises
      ValueError past it, so a value large enough to be worth refusing crashes
      the refusal that names it.
    - A self-referential container recurses until RecursionError, as does one
      nested deeper than the interpreter's limit.
    - An arbitrary object's `__repr__` is caller code and may raise anything.
    - A large but valid container would otherwise be reproduced in full inside
      an error message.

    So this is total by construction: bounded in depth and width, cycle-aware,
    and it never calls `repr()` on a type it does not recognise.
    """
    if value is None or isinstance(value, bool):
        return repr(value)
    if isinstance(value, int):
        if value.bit_length() > _SHOW_MAX_INT_BITS:
            sign = "-" if value < 0 else ""
            return f"<{sign}integer of {value.bit_length()} bits>"
        return repr(value)
    if isinstance(value, float):
        return repr(value)
    if isinstance(value, (str, bytes)):
        if len(value) > _SHOW_MAX_TEXT:
            unit = "bytes" if isinstance(value, bytes) else "characters"
            return f"{value[:_SHOW_MAX_TEXT]!r}... ({len(value)} {unit})"
        return repr(value)

    if isinstance(value, (list, tuple, set, frozenset, dict)):
        # Identity, not equality: an unhashable or self-referential container
        # cannot be compared, and every id here belongs to a live object held
        # by a caller further up this stack.
        if id(value) in _seen:
            return "<circular reference>"
        if _depth >= _SHOW_MAX_DEPTH:
            return f"<{type(value).__name__} nested past depth {_SHOW_MAX_DEPTH}>"
        seen = _seen | {id(value)}
        depth = _depth + 1

        if isinstance(value, dict):
            parts = [
                f"{_show(k, depth, seen)}: {_show(v, depth, seen)}"
                for k, v in list(value.items())[:_SHOW_MAX_ITEMS]
            ]
        else:
            # Sets are left in iteration order: sorting them is exactly what
            # fails on the mixed-type contents this function exists to survive.
            parts = [_show(v, depth, seen) for v in list(value)[:_SHOW_MAX_ITEMS]]
        if len(value) > _SHOW_MAX_ITEMS:
            parts.append(f"... ({len(value)} items)")

        body = ", ".join(parts)
        if isinstance(value, dict):
            return "{" + body + "}"
        if isinstance(value, tuple):
            return f"({body},)" if len(value) == 1 else f"({body})"
        if isinstance(value, list):
            return f"[{body}]"
        return "{" + body + "}" if value else f"{type(value).__name__}()"

    # Never repr() an unrecognised type: __repr__ is caller code.
    return f"<{type(value).__name__}>"


def _require_string_keys(mapping: dict, where: str, what: str) -> None:
    """Refuse a non-string key rather than stringifying it.

    YAML admits `1:` as an integer key, and JSON object keys are always strings,
    so an integer-keyed declaration could never be satisfied by a JSON document
    — it is unsatisfiable rather than merely unusual. Stringifying it would hide
    that behind a key the author never wrote.

    Mixed key types also make every `sorted()` over the names raise `TypeError`,
    which reaches the operator as an interpreter traceback instead of a contract
    verdict. Refusing here is what keeps the later sorts total.
    """
    # Not sorted: the keys are exactly what cannot be ordered together.
    bad = [k for k in mapping if not isinstance(k, str)]
    if bad:
        rendered = ", ".join(f"{_show(k)} ({type(k).__name__})" for k in bad)
        raise SchemaError(f"{where}: {what} must be strings, got {rendered}")


def _validate_descriptor(descriptor: Any, where: str) -> None:
    if not isinstance(descriptor, dict):
        raise SchemaError(f"{where}: a field descriptor must be a mapping")

    _require_string_keys(descriptor, where, "descriptor properties")

    unknown = sorted(set(descriptor) - _DESCRIPTOR_KEYS)
    if unknown:
        raise SchemaError(f"{where}: unknown descriptor properties {unknown}")

    kind = descriptor.get("type")
    # `in` against a set hashes its left operand, so an unhashable declaration
    # (`type: []`) would raise TypeError before the refusal below could fire.
    if not isinstance(kind, str) or kind not in _TYPES:
        raise SchemaError(
            f"{where}: 'type' is required and must be one of {sorted(_TYPES)}, "
            f"got {_show(kind)}"
        )

    if descriptor.get("required") and "default" in descriptor:
        raise SchemaError(
            f"{where}: 'default' and 'required: true' are mutually exclusive — "
            f"a required field is never absent, so its default can never apply"
        )

    # Recursive closure. An object that does not say what may sit inside it
    # reopens, one level down, the pass-through this validator exists to close.
    if kind == "object":
        properties = descriptor.get("properties")
        if not isinstance(properties, dict):
            raise SchemaError(f"{where}: 'type: object' must declare 'properties'")
        _require_string_keys(properties, where, "'properties' keys")
        for key, sub in properties.items():
            _validate_descriptor(sub, _join(where, key))
    elif "properties" in descriptor:
        raise SchemaError(f"{where}: 'properties' is only valid on 'type: object'")

    if kind == "array":
        items = descriptor.get("items")
        if not isinstance(items, dict):
            raise SchemaError(f"{where}: 'type: array' must declare 'items'")
        _validate_descriptor(items, f"{where}[]")
    elif "items" in descriptor:
        raise SchemaError(f"{where}: 'items' is only valid on 'type: array'")

    for prop, expected in (
        ("required", bool),
        ("deprecated", bool),
        ("supersedes", str),
        ("required_unless", dict),
        ("description", str),
    ):
        if prop in descriptor and not isinstance(descriptor[prop], expected):
            raise SchemaError(
                f"{where}: '{prop}' must be {expected.__name__}, got "
                f"{type(descriptor[prop]).__name__}"
            )

    for bound in ("minimum", "maximum"):
        if bound not in descriptor:
            continue
        if kind not in _NUMERIC:
            raise SchemaError(f"{where}: '{bound}' is only valid on a numeric type")
        # A non-numeric bound would otherwise surface as a raw TypeError during
        # a comparison, at document validation, blaming the wrong party.
        value = descriptor[bound]
        # Checked before the numeric test: in Python a bool *is* an int, so
        # "must be numeric" would deny something true and misdirect the author.
        if isinstance(value, bool):
            raise SchemaError(
                f"{where}: '{bound}' must not be a boolean, got {_show(value)}"
            )
        if not isinstance(value, (int, float)):
            raise SchemaError(
                f"{where}: '{bound}' must be numeric, got "
                f"{type(value).__name__} ({_show(value)})"
            )
        # NaN admits everything, because every comparison against it is false:
        # the declaration reads as a constraint and enforces nothing.
        # Guarded on float: `math.isfinite` converts its argument, so asking it
        # about a large int raises OverflowError. An int is finite by
        # construction, however many digits it has.
        if isinstance(value, float) and not math.isfinite(value):
            raise SchemaError(f"{where}: '{bound}' must be finite, got {value!r}")
        # A fractional bound on an integer field describes a boundary no valid
        # value can sit on, and implementations disagree about which side wins.
        if kind == "integer" and not isinstance(value, int):
            raise SchemaError(
                f"{where}: '{bound}' must be an integer on 'type: integer', "
                f"got {_show(value)}"
            )
    lo, hi = descriptor.get("minimum"), descriptor.get("maximum")
    if lo is not None and hi is not None and lo > hi:
        raise SchemaError(f"{where}: minimum {_show(lo)} exceeds maximum {_show(hi)}")

    if "enum" in descriptor:
        values = descriptor["enum"]
        if not isinstance(values, list) or not values:
            raise SchemaError(f"{where}: 'enum' must be a non-empty list")
        for value in values:
            _check_value(value, descriptor, f"{where} enum", schema_phase=True)

    if descriptor.get("deprecated") and not descriptor.get("supersedes"):
        raise SchemaError(f"{where}: 'deprecated' requires 'supersedes'")
    if descriptor.get("supersedes") and not descriptor.get("deprecated"):
        raise SchemaError(f"{where}: 'supersedes' is only valid on a deprecated field")
    if descriptor.get("deprecated") and descriptor.get("required"):
        raise SchemaError(f"{where}: a deprecated field must not be required")

    # A default the schema would reject is a defect that otherwise appears only
    # for the operator who omits the key.
    if "default" in descriptor:
        _check_value(
            descriptor["default"], descriptor, f"{where} default", schema_phase=True
        )

    for prop in ("fallback_from", "must_be_subset_of"):
        if prop in descriptor:
            _validate_fallback_path(descriptor[prop], where, prop)
    if "must_be_subset_of" in descriptor and kind != "array":
        raise SchemaError(f"{where}: 'must_be_subset_of' requires 'type: array'")


def _validate_fallback_path(path: Any, where: str, prop: str) -> None:
    if not isinstance(path, str) or not path.strip():
        raise SchemaError(f"{where}: '{prop}' must be a non-empty config path")
    segments = [s for s in path.split(".") if s]
    if len(segments) != len(path.split(".")):
        raise SchemaError(f"{where}: '{prop}' path {path!r} has an empty segment")
    if segments[0] == _FORBIDDEN_FALLBACK_ROOT:
        raise SchemaError(
            f"{where}: '{prop}' names {path!r}, inside sensors[]. A value a sensor "
            f"can write is not a bound on what a sensor may write."
        )


def _validate_groups(groups: Any, fields: set[str], name: str, constraint: str) -> None:
    if not isinstance(groups, list) or not groups:
        raise SchemaError(f"{name}: '{constraint}' must be a non-empty list of groups")

    seen: dict[frozenset[str], int] = {}
    members: dict[str, int] = {}
    for index, group in enumerate(groups):
        if not isinstance(group, list) or not group:
            raise SchemaError(
                f"{name}: '{constraint}' group {index} is empty — an empty group is "
                f"either always satisfied or never satisfiable"
            )
        for field in group:
            if field not in fields:
                raise SchemaError(
                    f"{name}: '{constraint}' group {index} names {_show(field)}, "
                    f"which the schema does not declare"
                )
            if field in members and members[field] != index:
                raise SchemaError(
                    f"{name}: '{constraint}' names {_show(field)} in more than one group, "
                    f"which makes the constraint undecidable"
                )
            members[field] = index
        key = frozenset(group)
        if key in seen:
            raise SchemaError(
                f"{name}: '{constraint}' groups {seen[key]} and {index} are identical"
            )
        seen[key] = index


def _validate_conditional_cycles(fields: dict[str, Any], where: str) -> None:
    """Refuse a cycle among `required_unless` dependencies, naming it.

    A condition reads its sibling's resolved value, so two conditions that
    depend on each other have no defined evaluation order — each needs the other
    settled first. Declaration order would decide it invisibly, and two readers
    of the same schema would disagree about which field is required.

    A chain that does not close is fine: `a` unless `b`, `b` unless `c` has
    exactly one evaluation order. An earlier version refused any conditional
    naming another conditional, which was wrong in both directions — it rejected
    acyclic chains and missed `a` -> `b` -> `c` -> `a`.

    Each field declares at most one `required_unless`, so the dependency graph
    has out-degree one and a walk from every node finds any cycle it can reach.
    """
    edges: dict[str, str] = {}
    for key, descriptor in fields.items():
        condition = (
            descriptor.get("required_unless") if isinstance(descriptor, dict) else None
        )
        if isinstance(condition, dict) and len(condition) == 1:
            (target,) = condition
            # A non-string target is refused by _validate_references with a
            # message naming the type; it cannot participate in a cycle.
            if isinstance(target, str):
                edges[key] = target

    for start in sorted(edges):
        path: list[str] = []
        node = start
        while node in edges:
            if node in path:
                cycle = path[path.index(node) :] + [node]
                # Report from the lowest-sorting member so the same cycle reads
                # the same way whichever field the walk happened to start from.
                pivot = cycle.index(min(cycle[:-1]))
                rotated = cycle[pivot:-1] + cycle[:pivot]
                raise SchemaError(
                    f"{where}: 'required_unless' dependencies form a cycle: "
                    f"{' -> '.join(rotated + [rotated[0]])}. Each condition needs "
                    f"another settled first, so there is no evaluation order."
                )
            path.append(node)
            node = edges[node]


def _validate_references_in(fields: dict[str, Any], where: str) -> None:
    """Check references against the siblings of the object that declares them.

    Recursive, because a nested object is its own namespace: a nested
    `required_unless` or `supersedes` names a key in *that* mapping, and
    validating only the top level let a nested alias point at nothing.
    """
    names = set(fields)
    _validate_conditional_cycles(fields, where)
    for key, descriptor in fields.items():
        _validate_references(descriptor, names, _join(where, key), fields)
        if descriptor.get("type") == "object":
            _validate_references_in(descriptor["properties"], _join(where, key))
        elif (
            descriptor.get("type") == "array"
            and descriptor["items"].get("type") == "object"
        ):
            _validate_references_in(
                descriptor["items"]["properties"], f"{_join(where, key)}[]"
            )


def _validate_references(
    descriptor: dict, fields: set[str], where: str, fields_by_name: dict[str, Any]
) -> None:
    replacement = descriptor.get("supersedes")
    if replacement is not None and replacement not in fields:
        raise SchemaError(
            f"{where}: 'supersedes' names {_show(replacement)}, which the schema does not "
            f"declare. An alias for a key that does not exist warns an operator "
            f"towards nothing."
        )

    condition = descriptor.get("required_unless")
    if condition is None:
        return
    if not isinstance(condition, dict) or len(condition) != 1:
        raise SchemaError(
            f"{where}: 'required_unless' must be a mapping of exactly one key to a value"
        )
    (key,) = condition
    if not isinstance(key, str):
        raise SchemaError(
            f"{where}: 'required_unless' names {_show(key)} ({type(key).__name__}); "
            f"field names are strings, so this condition names nothing"
        )
    if key not in fields:
        raise SchemaError(
            f"{where}: 'required_unless' names {key!r}, which the schema does not declare — "
            f"the condition could never fire"
        )


# ── Value checking, shared by both phases ────────────────────────────────────


def _check_value(
    value: Any, descriptor: dict, where: str, *, schema_phase: bool
) -> None:
    error = SchemaError if schema_phase else DocumentError
    kind = descriptor["type"]

    # A boolean is not an integer, whatever the host language says, and 7.0 is
    # not 7: they are different documents and parsers disagree about them.
    if kind == "boolean":
        ok = isinstance(value, bool)
    elif kind == "integer":
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif kind == "number":
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    else:
        ok = isinstance(value, _TYPES[kind])
    if not ok:
        raise error(
            f"{where}: expected {kind}, got {type(value).__name__} ({_show(value)}). "
            f"Values are not coerced."
        )

    if "enum" in descriptor and value not in descriptor["enum"]:
        raise error(
            f"{where}: {_show(value)} is not one of {_show(descriptor['enum'])}"
        )
    lo, hi = descriptor.get("minimum"), descriptor.get("maximum")
    if lo is not None and value < lo:
        raise error(f"{where}: {_show(value)} is below the minimum {_show(lo)}")
    if hi is not None and value > hi:
        raise error(f"{where}: {_show(value)} is above the maximum {_show(hi)}")

    # The type check above already established the shape; these narrow it for
    # the reader and the type checker alike.
    if kind == "object" and isinstance(value, dict):
        _check_object(value, descriptor["properties"], where, schema_phase=schema_phase)
    elif kind == "array" and isinstance(value, list):
        for index, item in enumerate(value):
            _check_value(
                item,
                descriptor["items"],
                f"{where}[{index}]",
                schema_phase=schema_phase,
            )


def _check_object(
    value: dict, properties: dict, where: str, *, schema_phase: bool
) -> None:
    error = SchemaError if schema_phase else DocumentError
    for key in value:
        if key not in properties:
            raise error(f"{_join(where, key)}: not declared by the schema")
    for key, descriptor in properties.items():
        if key in value:
            _check_value(
                value[key], descriptor, _join(where, key), schema_phase=schema_phase
            )
        elif descriptor.get("required"):
            raise error(f"{_join(where, key)}: required and missing")


# ── Configuration load ───────────────────────────────────────────────────────


class ValidatedSchema:
    """A declaration that has passed `validate_schema`.

    `validate_document` accepts only this, never a raw mapping. Otherwise an
    invalid declaration reaches document validation and fails there, or does not
    fail at all: `{"a": {}}` against an empty document raised nothing, because
    no descriptor was ever consulted, and a malformed bound surfaced as a raw
    `TypeError` rather than a `SchemaError`. The type is the boundary.
    """

    __slots__ = ("name", "fields", "groups")

    def __init__(
        self, name: str, fields: dict[str, Any], groups: dict[str, Any]
    ) -> None:
        self.name = name
        self.fields = fields
        self.groups = groups


def validate_document(
    document: dict,
    schema: ValidatedSchema,
    *,
    context: str,
    external: dict | None = None,
) -> dict:
    """Validate a sensor's protocol configuration and return the resolved form.

    Returns a new mapping with defaults and fallbacks applied, at every depth,
    so the thing that was validated is the thing that reaches the adapter.

    `external` is the rest of the configuration document. It is **required**
    whenever any field declares `fallback_from` or `must_be_subset_of`: those
    paths must resolve at configuration load, and skipping them when no context
    is supplied would silently drop a security bound.
    """
    if not isinstance(schema, ValidatedSchema):
        raise SchemaError(
            "validate_document requires a schema returned by validate_schema; "
            f"got {type(schema).__name__}. An unvalidated declaration cannot be "
            "relied on to refuse anything."
        )

    # Before the group check, not after it. `_check_groups` iterates the
    # document, so a scalar raised TypeError there — and a string or tuple was
    # worse, iterating successfully into a group verdict that blamed the
    # operator for a missing field rather than for the shape of the document.
    # `_resolve_mapping` performs the same check for every nested level; this
    # one covers the boundary it never sees.
    if not isinstance(document, dict):
        raise DocumentError(
            f"{context}: expected object, got {type(document).__name__} "
            f"({_show(document)})"
        )

    _require_external(schema, context, external)
    _check_groups(document, schema.groups, context)
    return _resolve_mapping(document, schema.fields, context, external)


def _require_external(
    schema: ValidatedSchema, context: str, external: dict | None
) -> None:
    if external is not None:
        return
    needs = sorted(
        key
        for key, descriptor in schema.fields.items()
        if "fallback_from" in descriptor or "must_be_subset_of" in descriptor
    )
    if needs:
        raise DocumentError(
            f"{context}: {needs} declare a fallback or a bound, which can only be "
            f"resolved against the rest of the configuration. Validating without it "
            f"would drop the bound rather than check it."
        )


def _resolve_mapping(
    document: Any,
    fields: dict[str, Any],
    context: str,
    external: dict | None,
) -> dict:
    """Resolve one mapping level: unknown keys, conditionals, defaults, recursion.

    Used at the top level and for every nested object, so a nested default is
    applied and a nested conditional is enforced. An earlier version validated
    nested values but resolved only the top level, so `{"tls": {}}` came back as
    `{"tls": {}}` with the declared inner default silently absent.
    """
    if not isinstance(document, dict):
        raise DocumentError(
            f"{context}: expected object, got {type(document).__name__}"
        )

    for key in document:
        if key not in fields:
            raise DocumentError(
                f"{_join(context, key)}: not declared by the schema. "
                f"Declared keys: {sorted(fields)}"
            )

    # Deprecation is checked at every level: a nested alias and its nested
    # replacement together is the same ambiguity as at the top.
    _check_deprecations(document, fields, context)

    # Pass one: resolve everything that can be resolved without knowing whether
    # a dependent field is required. Conditionals are evaluated afterwards
    # against these values, not against the raw document — otherwise a
    # `required_unless` naming a defaulted sibling sees None and refuses a
    # document that is in fact complete.
    resolved: dict[str, Any] = {}
    for key, descriptor in fields.items():
        where = _join(context, key)

        if key in document:
            resolved[key] = _resolve_value(document[key], descriptor, where, external)
        elif "fallback_from" in descriptor:
            inherited = _resolve_path(
                descriptor["fallback_from"], external, where, "fallback_from"
            )
            # An inherited value must satisfy the same descriptor as a written
            # one. Arriving by inheritance is not a licence to be malformed; the
            # adapter cannot tell the difference.
            resolved[key] = _resolve_value(
                inherited,
                descriptor,
                f"{where} (inherited from {descriptor['fallback_from']})",
                external,
            )
        elif "default" in descriptor:
            resolved[key] = _resolve_value(
                descriptor["default"], descriptor, where, external
            )

    # Pass two: requirements, now that every sibling has its effective value.
    for key, descriptor in fields.items():
        if key in resolved:
            continue
        _check_conditional_requirement(key, descriptor, resolved, context)
        if descriptor.get("required"):
            raise DocumentError(f"{_join(context, key)}: required and missing")

    for key, descriptor in fields.items():
        if "must_be_subset_of" in descriptor and key in resolved:
            _check_subset(
                resolved[key],
                descriptor["must_be_subset_of"],
                external,
                _join(context, key),
            )

    return resolved


def _resolve_value(
    value: Any, descriptor: dict, where: str, external: dict | None
) -> Any:
    """Check a value and return its resolved form, recursing into objects."""
    _check_value(value, descriptor, where, schema_phase=False)
    if descriptor["type"] == "object":
        return _resolve_mapping(value, descriptor["properties"], where, external)
    if descriptor["type"] == "array" and descriptor["items"]["type"] == "object":
        return [
            _resolve_mapping(
                item, descriptor["items"]["properties"], f"{where}[{i}]", external
            )
            for i, item in enumerate(value)
        ]
    return value


def _check_deprecations(document: dict, fields: dict, context: str) -> None:
    for key, descriptor in fields.items():
        if not descriptor.get("deprecated") or key not in document:
            continue
        replacement = descriptor["supersedes"]
        if replacement in document:
            raise DocumentError(
                f"{context}: sets both {replacement!r} and its deprecated alias {key!r}. "
                f"Refused even when the values agree — agreement today is not agreement "
                f"after the next edit, and a precedence rule is invisible in the file "
                f"that carries it. Keep {replacement!r}."
            )
        logger.warning(
            "%s: %r is deprecated; the canonical spelling is %r. Rename it.",
            context,
            key,
            replacement,
        )


def _check_conditional_requirement(
    key: str, descriptor: dict, document: dict, context: str
) -> None:
    condition = descriptor.get("required_unless")
    if not condition:
        return
    (other,) = condition
    if document.get(other) != condition[other]:
        raise DocumentError(
            f"{_join(context, key)}: required unless {_show(other)} is "
            f"{_show(condition[other])}, and it is {_show(document.get(other))}"
        )


def _check_groups(document: dict, groups: dict[str, Any], context: str) -> None:
    present = set(document)

    if "exactly_one_of" in groups:
        alternatives = groups["exactly_one_of"]
        satisfied = [g for g in alternatives if set(g) <= present]
        if len(satisfied) != 1:
            raise DocumentError(
                f"{context}: exactly one of {alternatives} must be fully present, "
                f"{len(satisfied)} are"
            )
        # Naming a group is choosing it. A key from a rejected alternative
        # states an intent the runtime will not honour, so it is refused rather
        # than ignored.
        chosen = set(satisfied[0])
        strays = sorted((present & {f for g in alternatives for f in g}) - chosen)
        if strays:
            raise DocumentError(
                f"{context}: {strays} belong to an alternative that was not chosen. "
                f"Configured ambiguously rather than twice."
            )

    if "at_least_one_of" in groups:
        alternatives = groups["at_least_one_of"]
        if not any(set(g) <= present for g in alternatives):
            raise DocumentError(
                f"{context}: at least one of {alternatives} must be fully present"
            )


def _resolve_path(path: str, external: dict | None, where: str, prop: str) -> Any:
    if external is None:  # pragma: no cover - _require_external refuses first
        raise DocumentError(f"{where}: '{prop}' needs the surrounding configuration")
    node: Any = external
    for segment in path.split("."):
        if not isinstance(node, dict) or segment not in node:
            raise DocumentError(
                f"{where}: '{prop}' names {path!r}, which the configuration does not "
                f"contain. A reference pointing at nothing is refused rather than "
                f"treated as absent."
            )
        node = node[segment]
    return node


def _check_subset(value: Any, path: str, external: dict | None, where: str) -> None:
    node = _resolve_path(path, external, where, "must_be_subset_of")
    if not isinstance(node, list):
        raise DocumentError(
            f"{where}: 'must_be_subset_of' resolves to {type(node).__name__}, not an array."
        )
    # Membership by equality rather than by hash. The contract permits object
    # items, and `set()` raises TypeError on those — a crash instead of a
    # verdict, which is the one outcome a validator must never produce.
    extra = [item for item in value if item not in node]
    if extra:
        raise DocumentError(
            f"{where}: {extra} not permitted by {path}. A sensor may narrow this "
            f"list, never widen it."
        )
