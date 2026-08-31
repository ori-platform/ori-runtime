# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Verify a commissioned safety binding per commissioned-safety-binding/v1.

The runtime is the first consumer of the contract. Verification is the
contract's twelve ordered stages, and every refusal names the stage it was
decided at, because a refusal only proves a check ran if every earlier stage
passed. Nothing here derives a coil state, a terminal state, or a polarity from
anything but the signed document.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.security.evidence.canonical import CanonicalisationError, canonical_json

COIL = frozenset({"energised", "de_energised"})
CIRCUIT = frozenset({"open", "closed"})
KINDS = frozenset({"local_gpio", "firmware_channel"})
METHODS = frozenset({"actuate_and_observe", "pre_energisation", "undemonstrated"})
PROVENANCE = frozenset({"nameplate", "installer_measured", "design_document"})
GPIO_LEVELS = frozenset({"high", "low"})
OUTCOMES = frozenset({"open_protected_circuit", "close_protected_circuit"})

MAP_KEYS = frozenset(
    {"open_protected_circuit", "close_protected_circuit", "de_energised_terminal_state"}
)
BINDING_KEYS = frozenset(
    {
        "v",
        "binding_seq",
        "device_id",
        "issued_at_ms",
        "signer_id",
        "signing_key",
        "inventory_generation",
        "supersedes",
        "actor",
        "reason",
        "zones",
    }
)
ZONE_KEYS = frozenset({"zone_id", "rated_capacity", "sensor", "actuator", "proof"})
ACTUATOR_KEYS = frozenset({"kind", "identity", "commissioned_mapping"})
CAPACITY_KEYS = frozenset({"parameter", "value", "provenance"})
SENSOR_KEYS = frozenset(
    {
        "sensor_id",
        "quantity",
        "unit",
        "range_min",
        "range_max",
        "direction",
        "noise_floor",
        "calibration_ref",
    }
)
# Identity is a closed shape per kind: a local-GPIO identity on a firmware
# channel names an actuator that does not exist.
IDENTITY_KEYS: dict[str, frozenset[str]] = {
    "local_gpio": frozenset({"gpio_pin", "active_high"}),
    "firmware_channel": frozenset({"firmware_device_id", "channel"}),
}
PROOF_KEYS: dict[str, frozenset[str]] = {
    "actuate_and_observe": frozenset({"method", "performed_at_ms", "observations"}),
    "pre_energisation": frozenset({"method", "performed_at_ms", "observations"}),
    "undemonstrated": frozenset(
        {"method", "performed_at_ms", "reason", "observations"}
    ),
}
CONTROL_METHODS = frozenset({"commanded_and_observed", "undemonstrated"})
CONTROL_PATH_KEYS: dict[str, frozenset[str]] = {
    "commanded_and_observed": frozenset({"method", "performed_at_ms", "observations"}),
    "undemonstrated": frozenset(
        {"method", "performed_at_ms", "reason", "observations"}
    ),
}
OBSERVATION_REQUIRED = frozenset(
    {
        "commanded",
        "coil_state",
        "load_present_before",
        "load_present_after",
        "terminal_state_observed",
    }
)
OBSERVATION_OPTIONAL = frozenset(
    {"gpio_level", "sensor_before", "sensor_after", "instrument"}
)
PROFILE_KEYS = frozenset(
    {
        "v",
        "binding_hash",
        "binding_seq",
        "device_id",
        "firmware_device_id",
        "channel",
        "commissioned_mapping",
        "signing_key",
    }
)

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

# The field-type table decides a number's spelling. An `integer` field carries
# no fractional part; a `number` field carries one. Both are checked against
# the shortest form that round-trips, so one value has exactly one spelling.
INTEGER_SPELLED = frozenset(
    {
        "v",
        "binding_seq",
        "issued_at_ms",
        "inventory_generation",
        "performed_at_ms",
        "gpio_pin",
    }
)
NUMBER_SPELLED = frozenset(
    {"value", "range_min", "range_max", "noise_floor", "sensor_before", "sensor_after"}
)

ORDER: tuple[str, ...] = (
    "parses",
    "device_id",
    "key_selection",
    "signature",
    "authority",
    "freshness",
    "mapping_self_consistency",
    "proof_consistency",
    "bounds",
    "disambiguation",
    "inventory",
    "activation_posture",
)
PROFILE_ORDER: tuple[str, ...] = (
    "parses",
    "device_binding",
    "key_selection",
    "signature",
    "authority",
    "binding_match",
    "mapping_match",
)

Posture = Literal["development", "staging", "production"]


class BindingRefusedError(Exception):
    """A verdict: the stage it was decided at and the contract's reason."""

    def __init__(self, stage: str, reason: str) -> None:
        self.stage = stage
        self.reason = reason
        super().__init__(f"{stage}: {reason}")


@dataclass(frozen=True)
class ZoneState:
    """What the retained record keeps per zone for the revision rule."""

    identity: dict[str, Any]
    mapping: dict[str, str]
    calibration_ref: str
    proof_at_ms: int
    control_proof_at_ms: int | None = None


@dataclass(frozen=True)
class VerifierContext:
    """Everything a verdict depends on that is not in the document."""

    device_id: str
    commissioning_anchor_current: bytes | None
    commissioning_anchor_previous: bytes | None
    provisioning_anchor: bytes | None
    accepted_binding_seq: int
    accepted_binding_hash: str | None
    declared_sensor_ids: frozenset[str]
    declared_actuators: tuple[tuple[str, str], ...]
    deployment_posture: Posture
    profile_multiplier: float | None
    accepted_zone_state: dict[str, ZoneState] = field(default_factory=dict)

    @classmethod
    def from_corpus(cls, ctx: dict[str, Any]) -> VerifierContext:
        """The golden corpus's `verifier_context` shape."""
        prior = ctx.get("accepted_zone_state") or {}
        return cls(
            device_id=str(ctx["device_id"]),
            commissioning_anchor_current=_hex_or_none(
                ctx.get("commissioning_anchor_current_hex")
            ),
            commissioning_anchor_previous=_hex_or_none(
                ctx.get("commissioning_anchor_previous_hex")
            ),
            provisioning_anchor=_hex_or_none(ctx.get("provisioning_anchor_hex")),
            accepted_binding_seq=int(ctx["accepted_binding_seq"]),
            accepted_binding_hash=ctx.get("accepted_binding_hash"),
            declared_sensor_ids=frozenset(ctx["declared_inventory"]["sensor_ids"]),
            declared_actuators=tuple(
                actuator_identity(a["kind"], a["identity"])
                for a in ctx["declared_inventory"]["actuators"]
            ),
            deployment_posture=ctx["deployment_posture"],
            profile_multiplier=(
                None
                if ctx.get("profile_multiplier") is None
                else float(ctx["profile_multiplier"])
            ),
            accepted_zone_state={
                zone_id: ZoneState(
                    identity=dict(was["identity"]),
                    mapping=dict(was["mapping"]),
                    calibration_ref=str(was["calibration_ref"]),
                    proof_at_ms=int(was["proof_at_ms"]),
                    control_proof_at_ms=(
                        None
                        if was.get("control_proof_at_ms") is None
                        else int(was["control_proof_at_ms"])
                    ),
                )
                for zone_id, was in prior.items()
            },
        )


@dataclass(frozen=True)
class AcceptedZone:
    zone_id: str
    sensor_id: str
    quantity: str
    unit: str
    direction: str
    range_min: float
    range_max: float
    noise_floor: float
    calibration_ref: str
    rated_capacity_parameter: str
    rated_capacity_value: float
    kind: str
    identity: dict[str, Any]
    mapping: dict[str, str]
    proof_method: str
    proof_performed_at_ms: int
    control_proof_method: str | None = None
    control_proof_performed_at_ms: int | None = None

    @property
    def identity_key(self) -> tuple[str, str]:
        return actuator_identity(self.kind, self.identity)

    @property
    def in_force_eligible(self) -> bool:
        return zone_row_in_force_eligible(
            {
                "kind": self.kind,
                "proof_method": self.proof_method,
                "control_proof_method": self.control_proof_method,
            }
        )


@dataclass(frozen=True)
class AcceptedBinding:
    """A binding that passed every stage, with what the consumer retains."""

    binding_seq: int
    canonical_hash: str
    inventory_generation: int
    device_id: str
    signer_id: str
    issued_at_ms: int
    supersedes: str | None
    zones: tuple[AcceptedZone, ...]
    canonical_bytes: bytes
    signature: str

    @property
    def in_force_eligible(self) -> bool:
        """Every zone carries both legs. One zone short leaves the whole document provisional."""
        return all(zone.in_force_eligible for zone in self.zones)

    def zone_for_actuator(
        self, kind: str, identity: dict[str, Any]
    ) -> AcceptedZone | None:
        wanted = actuator_identity(kind, identity)
        for zone in self.zones:
            if zone.identity_key == wanted:
                return zone
        return None


def zone_row_in_force_eligible(zone: Any) -> bool:
    """Both legs proven for one zone. Absence denies; a firmware channel has no leg yet.

    The retained-row shape is the primary form so the store and the verifier
    decide this once, not twice.
    """
    if not isinstance(zone, dict):
        return False
    return (
        zone.get("kind") == "local_gpio"
        and zone.get("proof_method") in ("actuate_and_observe", "pre_energisation")
        and zone.get("control_proof_method") == "commanded_and_observed"
    )


def _leg_method(proof: dict[str, Any]) -> str | None:
    leg = proof.get("control_path")
    return str(leg["method"]) if isinstance(leg, dict) else None


def _leg_at_ms(proof: dict[str, Any]) -> int | None:
    leg = proof.get("control_path")
    return int(leg["performed_at_ms"]) if isinstance(leg, dict) else None


def actuator_identity(kind: str, identity: dict[str, Any]) -> tuple[str, str]:
    """The identity a zone binds, comparable across documents.

    Polarity is a commissioned fact about the driver stage, not an inventory
    fact: the provisioning document declares that a pin exists, and the binding
    says how it is wired. Two zones on one pin are the same actuator whatever
    polarity each claims, and a declared pin is bound whatever polarity the
    binding records for it.
    """
    if kind == "local_gpio":
        return (
            str(kind),
            canonical_json({"gpio_pin": identity.get("gpio_pin")}).decode("utf-8"),
        )
    return (str(kind), canonical_json(identity).decode("utf-8"))


def _hex_or_none(value: Any) -> bytes | None:
    return bytes.fromhex(value) if value else None


def canonical_bytes(value: Any) -> bytes:
    """Canonical bytes, refusing rather than raising on what cannot be encoded."""
    try:
        return canonical_json(value)
    except (
        CanonicalisationError,
        UnicodeEncodeError,
        ValueError,
        TypeError,
        RecursionError,
    ):
        # RecursionError: the loader canonicalises an unverified document to
        # ask whether it is the one already in force, before any grammar has
        # bounded its depth. A document that deep is malformed, not a crash.
        raise BindingRefusedError("parses", "malformed") from None


def canonical_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


class _Spelled:
    """A number with the spelling it arrived with.

    It exists only between the decoder and the object hook below, which checks
    the spelling against the field's declared type and then unwraps it. Nothing
    downstream sees one, so canonical bytes are unaffected.
    """

    __slots__ = ("raw", "value")

    def __init__(self, raw: str, value: Any) -> None:
        self.raw = raw
        self.value = value


def _spelled_int(raw: str) -> _Spelled:
    return _Spelled(raw, int(raw))


def _spelled_float(raw: str) -> _Spelled:
    return _Spelled(raw, float(raw))


def _check_spelling(key: str, number: _Spelled) -> None:
    """A number is spelled as its field's declared type requires.

    The rule is over the declared type and not the value, because JSON does not
    distinguish them and only the schema knows which was meant: a capacity of
    ten is `10.0` because the field is a capacity, and a sequence of ten is
    `10` because the field is a count.
    """
    raw = number.raw
    fractional = "." in raw
    exponent = "e" in raw or "E" in raw
    if key in INTEGER_SPELLED:
        if fractional or exponent or raw != str(int(raw)):
            raise ValueError(f"{key}: {raw!r} is not an integer's canonical spelling")
    elif key in NUMBER_SPELLED:
        if exponent or not fractional or raw != repr(float(raw)):
            raise ValueError(f"{key}: {raw!r} is not a number's canonical spelling")


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate object key {key!r}")
        if isinstance(value, _Spelled):
            _check_spelling(key, value)
            value = value.value
        obj[key] = value
    return obj


def parse_document(text: str) -> Any:
    """Decode a wire document, refusing what a decoded object can no longer show.

    A repeated key collapses before any grammar check can see it, and which
    occurrence survives depends on the parser: this one keeps the last, a
    first-wins parser on a device reads the other, and the signature verifies
    over whichever this side kept. evidence/v2 requires a verifier parsing
    bytes to reject the duplicate during parsing, so the wire form is refused
    here rather than repaired.
    """
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_int=_spelled_int,
            parse_float=_spelled_float,
        )
        # Every number in this contract sits under a key, so the hook above has
        # already unwrapped them. A bare number document has not been through
        # it and is not a document anyway.
        return decoded.value if isinstance(decoded, _Spelled) else decoded
    except (ValueError, RecursionError):
        # json.loads itself recurses per nesting level and raises past the
        # interpreter's limit; that is input, and the verdict is malformed.
        raise BindingRefusedError("parses", "malformed") from None


# ── grammar ───────────────────────────────────────────────────────────────


def _bad(condition: bool) -> None:
    if condition:
        raise BindingRefusedError("parses", "malformed")


def _closed(obj: Any, keys: frozenset[str]) -> None:
    _bad(not isinstance(obj, dict) or set(obj) != set(keys))


def _vocab(value: Any, allowed: frozenset[str]) -> None:
    # Type first: an unhashable value raises on membership, which is a crash,
    # not a verdict.
    _bad(not isinstance(value, str))
    _bad(value not in allowed)


def _encodable(value: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise BindingRefusedError("parses", "malformed") from None


def _text(value: Any) -> None:
    _bad(not isinstance(value, str) or not value.strip())
    _encodable(value)


def _number(value: Any) -> None:
    """A `number` field, which is spelled with a fractional part.

    Every field this contract types `number` reaches here, so requiring a float
    is the decoded half of the spelling rule: `10` and `10.0` are one value and
    two signing inputs, and an integer arriving where a capacity belongs is the
    spelling the schema did not mean. The byte-level half — exponent notation
    and non-shortest forms, which decode to a float either way — is checked
    where the spelling still exists, in `parse_document`.
    """
    _bad(isinstance(value, bool) or not isinstance(value, float))


def _flag(value: Any) -> None:
    _bad(not isinstance(value, bool))


def _whole(value: Any) -> None:
    _bad(isinstance(value, bool) or not isinstance(value, int))


def _canonical_b64(text: Any, expected_len: int) -> bytes:
    """Exactly one spelling: decode, re-encode, require the same text."""
    if not isinstance(text, str):
        raise BindingRefusedError("parses", "malformed")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise BindingRefusedError("parses", "malformed") from None
    if len(raw) != expected_len or base64.b64encode(raw).decode("ascii") != text:
        raise BindingRefusedError("parses", "malformed")
    return raw


def raw_key(prefixed: Any) -> bytes:
    if not isinstance(prefixed, str) or not prefixed.startswith("ed25519:"):
        raise BindingRefusedError("parses", "malformed")
    return _canonical_b64(prefixed.removeprefix("ed25519:"), 32)


def raw_signature(prefixed: Any) -> bytes:
    if not isinstance(prefixed, str) or not prefixed.startswith("ed25519:"):
        raise BindingRefusedError("parses", "malformed")
    return _canonical_b64(prefixed.removeprefix("ed25519:"), 64)


def parse_envelope(envelope: Any, inner: str) -> tuple[dict[str, Any], str]:
    """Close the wrapper as well as what it wraps."""
    _closed(envelope, frozenset({inner, "signature"}))
    _bad(not isinstance(envelope[inner], dict))
    raw_signature(envelope["signature"])
    return envelope[inner], envelope["signature"].removeprefix("ed25519:")


def _parse_sensor(sensor: Any) -> None:
    _closed(sensor, SENSOR_KEYS)
    for name in ("sensor_id", "quantity", "unit", "direction", "calibration_ref"):
        _text(sensor[name])
    for name in ("range_min", "range_max", "noise_floor"):
        _number(sensor[name])
    _bad(not sensor["range_min"] < sensor["range_max"])
    _bad(sensor["noise_floor"] <= 0)


def _parse_capacity(capacity: Any) -> None:
    _closed(capacity, CAPACITY_KEYS)
    _text(capacity["parameter"])
    _number(capacity["value"])
    _vocab(capacity["provenance"], PROVENANCE)


def _parse_actuator(actuator: Any) -> None:
    _closed(actuator, ACTUATOR_KEYS)
    _vocab(actuator["kind"], KINDS)
    identity = actuator["identity"]
    _closed(identity, IDENTITY_KEYS[actuator["kind"]])
    if actuator["kind"] == "local_gpio":
        _whole(identity["gpio_pin"])
        _flag(identity["active_high"])
    else:
        _text(identity["firmware_device_id"])
        _text(identity["channel"])
    mapping = actuator["commissioned_mapping"]
    _closed(mapping, MAP_KEYS)
    _vocab(mapping["open_protected_circuit"], COIL)
    _vocab(mapping["close_protected_circuit"], COIL)
    _vocab(mapping["de_energised_terminal_state"], CIRCUIT)


def _parse_observations(observations: Any, kind: str, *, level_required: bool) -> None:
    _bad(not observations)
    for observation in observations:
        _bad(not isinstance(observation, dict))
        present = set(observation)
        _bad(not OBSERVATION_REQUIRED <= present)
        _bad(not present <= OBSERVATION_REQUIRED | OBSERVATION_OPTIONAL)
        _vocab(observation["commanded"], OUTCOMES)
        _vocab(observation["coil_state"], COIL)
        _vocab(observation["terminal_state_observed"], CIRCUIT)
        _flag(observation["load_present_before"])
        _flag(observation["load_present_after"])
        _bad(level_required and "gpio_level" not in observation)
        if "gpio_level" in observation:
            _bad(kind != "local_gpio")
            _vocab(observation["gpio_level"], GPIO_LEVELS)
        for name in ("sensor_before", "sensor_after"):
            if name in observation:
                _number(observation[name])
        if "instrument" in observation:
            _text(observation["instrument"])
        _bad(("sensor_before" in observation) != ("sensor_after" in observation))


def _parse_control_path(leg: Any, kind: str) -> None:
    """The control leg: closed over its own methods, commanded proof local-GPIO only."""
    _bad(not isinstance(leg, dict))
    method = leg.get("method")
    _vocab(method, CONTROL_METHODS)
    _closed(leg, CONTROL_PATH_KEYS[method])
    _whole(leg["performed_at_ms"])
    _bad(not isinstance(leg["observations"], list))
    if method == "undemonstrated":
        _text(leg["reason"])
        _bad(leg["observations"] != [])
        return
    _bad(kind != "local_gpio")
    _parse_observations(leg["observations"], kind, level_required=True)


def _parse_proof(proof: Any, kind: str) -> None:
    _bad(not isinstance(proof, dict))
    method = proof.get("method")
    _vocab(method, METHODS)
    body = {key: value for key, value in proof.items() if key != "control_path"}
    _closed(body, PROOF_KEYS[method])
    _whole(proof["performed_at_ms"])
    _bad(not isinstance(proof["observations"], list))
    if "control_path" in proof:
        _parse_control_path(proof["control_path"], kind)
    if method == "undemonstrated":
        _text(proof["reason"])
        _bad(proof["observations"] != [])
        return
    _parse_observations(proof["observations"], kind, level_required=False)


def _walk(node: Any) -> Any:
    """Every value in the tree, keys included, without recursion.

    The walkers run over the document before the grammar has bounded its
    shape, so a value nested past the interpreter's recursion limit reached
    them first. An explicit stack has no such limit, and the grammar then
    refuses the nesting at whichever leaf it fails to type.
    """
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        if isinstance(current, dict):
            stack.extend(current.keys())
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)


def _encodable_tree(node: Any) -> None:
    for value in _walk(node):
        if isinstance(value, str):
            _encodable(value)


def _numbers_in_zone(node: Any) -> None:
    """The D-011 agreement zone, at every depth."""
    for value in _walk(node):
        if isinstance(value, bool):
            continue
        if isinstance(value, int) and abs(value) > 9007199254740991:
            raise BindingRefusedError("parses", "malformed")
        if (
            isinstance(value, float)
            and value != 0.0
            and not (1e-4 <= abs(value) < 1e16)
        ):
            raise BindingRefusedError("parses", "malformed")


# ── stages ────────────────────────────────────────────────────────────────


def st_parses(b: Any, ctx: VerifierContext) -> None:
    _closed(b, BINDING_KEYS)
    # Integer first: True == 1 and 1.0 == 1 in Python, and both spell
    # different signing bytes.
    _whole(b["v"])
    _bad(b["v"] != 1)
    _encodable_tree(b)
    for name in ("device_id", "signer_id", "actor", "reason"):
        _text(b[name])
    raw_key(b["signing_key"])
    _whole(b["binding_seq"])
    _bad(b["binding_seq"] < 1)
    _whole(b["issued_at_ms"])
    _whole(b["inventory_generation"])
    _bad(b["inventory_generation"] < 1)
    _bad(
        b["supersedes"] is not None
        and not (isinstance(b["supersedes"], str) and DIGEST.match(b["supersedes"]))
    )
    _bad(not isinstance(b["zones"], list) or not b["zones"])
    for zone in b["zones"]:
        _closed(zone, ZONE_KEYS)
        _text(zone["zone_id"])
        _parse_capacity(zone["rated_capacity"])
        _parse_sensor(zone["sensor"])
        _parse_actuator(zone["actuator"])
        _parse_proof(zone["proof"], zone["actuator"]["kind"])
        _numbers_in_zone(zone)
    _numbers_in_zone(b)
    canonical_bytes(b)


def st_device_id(b: dict[str, Any], ctx: VerifierContext) -> None:
    if b["device_id"] != ctx.device_id:
        raise BindingRefusedError("device_id", "wrong_device")


def _collision(ctx: VerifierContext) -> bool:
    provisioning = ctx.provisioning_anchor
    if provisioning is None:
        return False
    return provisioning in {
        ctx.commissioning_anchor_current,
        ctx.commissioning_anchor_previous,
    }


def st_key_selection(b: dict[str, Any], ctx: VerifierContext) -> None:
    """Select exactly one candidate key. No trial verification, no verdict."""
    if _collision(ctx):
        raise BindingRefusedError("key_selection", "anchor_collision")
    named = raw_key(b["signing_key"])
    candidates = {
        ctx.commissioning_anchor_current,
        ctx.commissioning_anchor_previous,
        ctx.provisioning_anchor,
    } - {None}
    if named not in candidates:
        raise BindingRefusedError("key_selection", "unknown_signer")


def st_signature(b: dict[str, Any], sig_b64: str) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(raw_key(b["signing_key"])).verify(
            base64.b64decode(sig_b64), canonical_bytes(b)
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise BindingRefusedError("signature", "bad_signature") from None


def st_authority(b: dict[str, Any], ctx: VerifierContext) -> None:
    """Decided only over a verified signature, so it cannot be manufactured."""
    named = raw_key(b["signing_key"])
    if ctx.provisioning_anchor is not None and named == ctx.provisioning_anchor:
        raise BindingRefusedError("authority", "wrong_authority")
    if (
        ctx.commissioning_anchor_previous is not None
        and named == ctx.commissioning_anchor_previous
    ):
        raise BindingRefusedError("authority", "superseded_signer")
    if named != ctx.commissioning_anchor_current:
        raise BindingRefusedError("authority", "unknown_signer")


def st_freshness(b: dict[str, Any], ctx: VerifierContext) -> None:
    if b["binding_seq"] <= ctx.accepted_binding_seq:
        raise BindingRefusedError("freshness", "stale")
    if b["supersedes"] != ctx.accepted_binding_hash:
        raise BindingRefusedError("freshness", "stale")


def st_mapping_self_consistency(b: dict[str, Any], ctx: VerifierContext) -> None:
    for zone in b["zones"]:
        m = zone["actuator"]["commissioned_mapping"]
        if m["open_protected_circuit"] == m["close_protected_circuit"]:
            raise BindingRefusedError(
                "mapping_self_consistency", "mapping_contradiction"
            )
        opens_by_release = m["open_protected_circuit"] == "de_energised"
        if opens_by_release != (m["de_energised_terminal_state"] == "open"):
            raise BindingRefusedError(
                "mapping_self_consistency", "mapping_contradiction"
            )


def _check_observations(zone: dict[str, Any], observations: list[Any]) -> None:
    """Observations must agree with the mapping they claim to establish."""
    mapping = zone["actuator"]["commissioned_mapping"]
    noise_floor = zone["sensor"]["noise_floor"]
    seen: set[str] = set()
    for ob in observations:
        outcome = ob["commanded"]
        seen.add(outcome)
        if ob["coil_state"] != mapping[outcome]:
            raise BindingRefusedError("proof_consistency", "proof_contradiction")
        opening = outcome == "open_protected_circuit"
        if ob["terminal_state_observed"] != ("open" if opening else "closed"):
            raise BindingRefusedError("proof_consistency", "proof_contradiction")
        # The instrument classifies load presence; the reading is evidence.
        before, after = ob["load_present_before"], ob["load_present_after"]
        if (before, after) != ((True, False) if opening else (False, True)):
            raise BindingRefusedError("proof_consistency", "proof_contradiction")
        if "sensor_before" in ob and "sensor_after" in ob:
            delta = ob["sensor_after"] - ob["sensor_before"]
            if abs(delta) <= noise_floor or (delta > 0) != after:
                raise BindingRefusedError("proof_consistency", "proof_contradiction")
        if "gpio_level" in ob:
            active_high = zone["actuator"]["identity"]["active_high"]
            energised = ob["coil_state"] == "energised"
            if ob["gpio_level"] != ("high" if energised == active_high else "low"):
                raise BindingRefusedError("proof_consistency", "proof_contradiction")
    if seen != set(OUTCOMES):
        raise BindingRefusedError("proof_consistency", "proof_contradiction")


def st_proof_consistency(b: dict[str, Any], ctx: VerifierContext) -> None:
    for zone in b["zones"]:
        proof = zone["proof"]
        if proof["method"] != "undemonstrated":
            _check_observations(zone, proof["observations"])
        leg = proof.get("control_path")
        if isinstance(leg, dict) and leg["method"] != "undemonstrated":
            _check_observations(zone, leg["observations"])
    # A revision changing actuator identity, mapping or calibration needs a
    # proof performed after the accepted document.
    for zone in b["zones"]:
        was = ctx.accepted_zone_state.get(zone["zone_id"])
        if was is None:
            continue
        changed = (
            was.identity != zone["actuator"]["identity"]
            or was.mapping != zone["actuator"]["commissioned_mapping"]
            or was.calibration_ref != zone["sensor"]["calibration_ref"]
        )
        if not changed:
            continue
        if zone["proof"]["performed_at_ms"] <= was.proof_at_ms:
            raise BindingRefusedError("proof_consistency", "stale_proof")
        # A changed pin or polarity invalidates the control proof too: it was
        # performed on the wiring this revision replaces.
        leg = zone["proof"].get("control_path")
        if (
            isinstance(leg, dict)
            and leg["method"] == "commanded_and_observed"
            and was.control_proof_at_ms is not None
            and leg["performed_at_ms"] <= was.control_proof_at_ms
        ):
            raise BindingRefusedError("proof_consistency", "stale_proof")


def st_bounds(b: dict[str, Any], ctx: VerifierContext) -> None:
    for zone in b["zones"]:
        cap, sensor = zone["rated_capacity"]["value"], zone["sensor"]
        if cap <= 0 or cap > sensor["range_max"] or cap < sensor["range_min"]:
            raise BindingRefusedError("bounds", "out_of_bounds")
        if (
            ctx.profile_multiplier is not None
            and cap * ctx.profile_multiplier > sensor["range_max"]
        ):
            raise BindingRefusedError("bounds", "out_of_bounds")


def st_disambiguation(b: dict[str, Any], ctx: VerifierContext) -> None:
    sensors = [zone["sensor"]["sensor_id"] for zone in b["zones"]]
    actuators = [
        actuator_identity(zone["actuator"]["kind"], zone["actuator"]["identity"])
        for zone in b["zones"]
    ]
    if len(set(sensors)) != len(sensors) or len(set(actuators)) != len(actuators):
        raise BindingRefusedError("disambiguation", "ambiguous_binding")


def st_inventory(b: dict[str, Any], ctx: VerifierContext) -> None:
    declared = set(ctx.declared_actuators)
    for zone in b["zones"]:
        if zone["sensor"]["sensor_id"] not in ctx.declared_sensor_ids:
            raise BindingRefusedError("inventory", "unknown_hardware")
        if (
            actuator_identity(zone["actuator"]["kind"], zone["actuator"]["identity"])
            not in declared
        ):
            raise BindingRefusedError("inventory", "unknown_hardware")
    bound = {
        actuator_identity(zone["actuator"]["kind"], zone["actuator"]["identity"])
        for zone in b["zones"]
    }
    if declared - bound:
        raise BindingRefusedError("inventory", "unbound_actuator")


def st_activation_posture(b: dict[str, Any], ctx: VerifierContext) -> None:
    if ctx.deployment_posture == "development":
        return
    for zone in b["zones"]:
        if zone["proof"]["method"] == "undemonstrated":
            raise BindingRefusedError("activation_posture", "undemonstrated_binding")


def verify_binding(b: Any, ctx: VerifierContext, sig_b64: str) -> AcceptedBinding:
    """Run every stage in the contract's order and return what is retained."""
    st_parses(b, ctx)
    st_device_id(b, ctx)
    st_key_selection(b, ctx)
    st_signature(b, sig_b64)
    st_authority(b, ctx)
    st_freshness(b, ctx)
    st_mapping_self_consistency(b, ctx)
    st_proof_consistency(b, ctx)
    st_bounds(b, ctx)
    st_disambiguation(b, ctx)
    st_inventory(b, ctx)
    st_activation_posture(b, ctx)
    body = canonical_bytes(b)
    return AcceptedBinding(
        binding_seq=int(b["binding_seq"]),
        canonical_hash="sha256:" + hashlib.sha256(body).hexdigest(),
        inventory_generation=int(b["inventory_generation"]),
        device_id=str(b["device_id"]),
        signer_id=str(b["signer_id"]),
        issued_at_ms=int(b["issued_at_ms"]),
        supersedes=b["supersedes"],
        zones=tuple(
            AcceptedZone(
                zone_id=str(zone["zone_id"]),
                sensor_id=str(zone["sensor"]["sensor_id"]),
                quantity=str(zone["sensor"]["quantity"]),
                unit=str(zone["sensor"]["unit"]),
                direction=str(zone["sensor"]["direction"]),
                range_min=float(zone["sensor"]["range_min"]),
                range_max=float(zone["sensor"]["range_max"]),
                noise_floor=float(zone["sensor"]["noise_floor"]),
                calibration_ref=str(zone["sensor"]["calibration_ref"]),
                rated_capacity_parameter=str(zone["rated_capacity"]["parameter"]),
                rated_capacity_value=float(zone["rated_capacity"]["value"]),
                kind=str(zone["actuator"]["kind"]),
                identity=dict(zone["actuator"]["identity"]),
                mapping=dict(zone["actuator"]["commissioned_mapping"]),
                proof_method=str(zone["proof"]["method"]),
                proof_performed_at_ms=int(zone["proof"]["performed_at_ms"]),
                control_proof_method=_leg_method(zone["proof"]),
                control_proof_performed_at_ms=_leg_at_ms(zone["proof"]),
            )
            for zone in b["zones"]
        ),
        canonical_bytes=body,
        signature="ed25519:" + sig_b64,
    )


def verify_binding_envelope(envelope: Any, ctx: VerifierContext) -> AcceptedBinding:
    """The wire form: the wrapper, then the document inside it."""
    binding, sig_b64 = parse_envelope(envelope, "binding")
    return verify_binding(binding, ctx, sig_b64)


# ── firmware profile ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class ProfileContext:
    firmware_device_id: str
    channel: str
    commissioning_anchor_current: bytes | None
    commissioning_anchor_previous: bytes | None
    provisioning_anchor: bytes | None
    accepted_binding_seq: int
    accepted_binding_hash: str | None
    expected_mapping: dict[str, str]

    @classmethod
    def from_corpus(cls, ctx: dict[str, Any]) -> ProfileContext:
        return cls(
            firmware_device_id=str(ctx["firmware_device_id"]),
            channel=str(ctx["channel"]),
            commissioning_anchor_current=_hex_or_none(
                ctx.get("commissioning_anchor_current_hex")
            ),
            commissioning_anchor_previous=_hex_or_none(
                ctx.get("commissioning_anchor_previous_hex")
            ),
            provisioning_anchor=_hex_or_none(ctx.get("provisioning_anchor_hex")),
            accepted_binding_seq=int(ctx["accepted_binding_seq"]),
            accepted_binding_hash=ctx.get("accepted_binding_hash"),
            expected_mapping=dict(ctx["expected_mapping"]),
        )


def verify_firmware_profile(pr: Any, ctx: ProfileContext, sig_b64: str) -> None:
    """Same authority discipline as a binding, then the binding-match checks."""
    _closed(pr, PROFILE_KEYS)
    _whole(pr["v"])
    _bad(pr["v"] != 1)
    _encodable_tree(pr)
    for name in ("device_id", "firmware_device_id", "channel"):
        _text(pr[name])
    _whole(pr["binding_seq"])
    _bad(pr["binding_seq"] < 1)
    _bad(
        not isinstance(pr["binding_hash"], str) or not DIGEST.match(pr["binding_hash"])
    )
    raw_key(pr["signing_key"])
    mapping = pr["commissioned_mapping"]
    _closed(mapping, MAP_KEYS)
    _vocab(mapping["open_protected_circuit"], COIL)
    _vocab(mapping["close_protected_circuit"], COIL)
    _vocab(mapping["de_energised_terminal_state"], CIRCUIT)
    canonical_bytes(pr)
    if pr["firmware_device_id"] != ctx.firmware_device_id:
        raise BindingRefusedError("device_binding", "wrong_device")
    if pr["channel"] != ctx.channel:
        raise BindingRefusedError("device_binding", "profile_channel_mismatch")

    provisioning = ctx.provisioning_anchor
    if provisioning is not None and provisioning in {
        ctx.commissioning_anchor_current,
        ctx.commissioning_anchor_previous,
    }:
        raise BindingRefusedError("key_selection", "anchor_collision")
    named = raw_key(pr["signing_key"])
    candidates = {
        ctx.commissioning_anchor_current,
        ctx.commissioning_anchor_previous,
        provisioning,
    } - {None}
    if named not in candidates:
        raise BindingRefusedError("key_selection", "unknown_signer")
    try:
        Ed25519PublicKey.from_public_bytes(named).verify(
            base64.b64decode(sig_b64), canonical_bytes(pr)
        )
    except (InvalidSignature, ValueError, binascii.Error):
        raise BindingRefusedError("signature", "bad_signature") from None
    if provisioning is not None and named == provisioning:
        raise BindingRefusedError("authority", "wrong_authority")
    if (
        ctx.commissioning_anchor_previous is not None
        and named == ctx.commissioning_anchor_previous
    ):
        raise BindingRefusedError("authority", "superseded_signer")
    if (
        pr["binding_hash"] != ctx.accepted_binding_hash
        or pr["binding_seq"] != ctx.accepted_binding_seq
    ):
        raise BindingRefusedError("binding_match", "profile_binding_mismatch")
    if pr["commissioned_mapping"] != ctx.expected_mapping:
        raise BindingRefusedError("mapping_match", "profile_mapping_mismatch")


def verify_firmware_profile_envelope(envelope: Any, ctx: ProfileContext) -> None:
    profile, sig_b64 = parse_envelope(envelope, "firmware_profile")
    verify_firmware_profile(profile, ctx, sig_b64)
