# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Independent verifier for the commissioned-safety-binding v1 vectors.

Implemented from the contract text, not from the generator. It answers two
questions the generator cannot answer about itself:

  1. Do the recorded canonical bytes, digests and signatures actually hold?
  2. Does each reject case fail at *exactly* its declared stage, having passed
     every earlier stage? A vector that refuses for the wrong reason proves
     nothing about the check it is named for.
"""

import base64
import binascii
import hashlib
import json
import re
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

COIL = {"energised", "de_energised"}
CIRCUIT = {"open", "closed"}
KINDS = {"local_gpio", "firmware_channel"}
METHODS = {"actuate_and_observe", "pre_energisation", "undemonstrated"}
PROVENANCE = {"nameplate", "installer_measured", "design_document"}
GPIO_LEVELS = {"high", "low"}
OUTCOMES = {"open_protected_circuit", "close_protected_circuit"}

MAP_KEYS = {
    "open_protected_circuit",
    "close_protected_circuit",
    "de_energised_terminal_state",
}
BINDING_KEYS = {
    "v",
    "binding_seq",
    "device_id",
    "issued_at_ms",
    "signer_id",
    "signing_key",
    "supersedes",
    "actor",
    "reason",
    "zones",
}
ZONE_KEYS = {"zone_id", "rated_capacity", "sensor", "actuator", "proof"}
ACTUATOR_KEYS = {"kind", "identity", "commissioned_mapping"}
CAPACITY_KEYS = {"parameter", "value", "provenance"}
SENSOR_KEYS = {
    "sensor_id",
    "quantity",
    "unit",
    "range_min",
    "range_max",
    "direction",
    "noise_floor",
    "calibration_ref",
}

#: Identity is a closed shape *per kind*. A local-GPIO identity on a firmware
#: channel is not a near-miss to be tolerated: it names an actuator that does
#: not exist and would leave `active_high` unread on a device that has no pin.
IDENTITY_KEYS = {
    "local_gpio": {"gpio_pin", "active_high"},
    "firmware_channel": {"firmware_device_id", "channel"},
}

PROOF_KEYS = {
    "actuate_and_observe": {"method", "performed_at_ms", "observations"},
    "pre_energisation": {"method", "performed_at_ms", "observations"},
    "undemonstrated": {"method", "performed_at_ms", "reason", "observations"},
}
OBSERVATION_REQUIRED = {
    "commanded",
    "coil_state",
    "load_present_before",
    "load_present_after",
    "terminal_state_observed",
}
OBSERVATION_OPTIONAL = {"gpio_level", "sensor_before", "sensor_after", "instrument"}

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

ORDER = [
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
]


class RefusedError(Exception):
    def __init__(self, stage: str, reason: str):
        self.stage, self.reason = stage, reason
        super().__init__(f"{stage}: {reason}")


def cbytes(value) -> bytes:
    """Canonical bytes, refusing rather than raising on unencodable input.

    The grammar rejects unpaired surrogates before anything reaches here, so
    this is defence in depth for a caller that canonicalises first.
    """
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        raise RefusedError("parses", "malformed") from None


def _bad(condition: bool) -> None:
    if condition:
        raise RefusedError("parses", "malformed")


def _closed(obj, keys) -> None:
    """Exactly these keys. Not a superset, not a subset."""
    _bad(not isinstance(obj, dict) or set(obj) != set(keys))


def _vocab(value, allowed) -> None:
    """Membership in a closed vocabulary, type-checked first.

    ``value in allowed`` raises TypeError on a list or dict, because those are
    unhashable. A verifier that crashes on a malformed value has not refused
    it, so the type check has to come before the membership test rather than
    be implied by it.
    """
    _bad(not isinstance(value, str))
    _bad(value not in allowed)


def _encodable(value: str) -> None:
    """Reject strings that cannot be canonically serialised.

    ``json.loads`` happily produces unpaired surrogates from ``\ud800``
    escapes, and they survive every type and vocabulary check — then raise
    UnicodeEncodeError at canonicalisation, downstream of the grammar. What a
    caller sees is a crash rather than a verdict.
    """
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise RefusedError("parses", "malformed") from None


def _text(value) -> None:
    _bad(not isinstance(value, str) or not value.strip())
    _encodable(value)


def _number(value) -> None:
    _bad(isinstance(value, bool) or not isinstance(value, (int, float)))


def _flag(value) -> None:
    _bad(not isinstance(value, bool))


def _whole(value) -> None:
    _bad(isinstance(value, bool) or not isinstance(value, int))


def _canonical_b64(text: str, expected_len: int) -> bytes:
    """Decode base64 that has exactly one spelling.

    `validate=True` is not enough. It rejects characters outside the alphabet
    and says nothing about the unused low bits of the final character, so four
    distinct strings decode to the same 32-byte key and all four pass. Any of
    them would be a different signing input while naming the same key.

    The only decoder property that admits one spelling is round-trip equality:
    decode, re-encode, require the same bytes back. That fixes the standard
    alphabet, mandatory padding, and zero pad bits together.
    """
    if not isinstance(text, str):
        raise RefusedError("parses", "malformed")
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise RefusedError("parses", "malformed") from None
    if len(raw) != expected_len:
        raise RefusedError("parses", "malformed")
    if base64.b64encode(raw).decode("ascii") != text:
        raise RefusedError("parses", "malformed")
    return raw


def raw_key(prefixed: str) -> bytes:
    """`ed25519:` followed by the canonical encoding of a 32-byte public key."""
    if not isinstance(prefixed, str) or not prefixed.startswith("ed25519:"):
        raise RefusedError("parses", "malformed")
    return _canonical_b64(prefixed.removeprefix("ed25519:"), 32)


def raw_signature(prefixed: str) -> bytes:
    """`ed25519:` followed by the canonical encoding of a 64-byte signature."""
    if not isinstance(prefixed, str) or not prefixed.startswith("ed25519:"):
        raise RefusedError("parses", "malformed")
    return _canonical_b64(prefixed.removeprefix("ed25519:"), 64)


def parse_envelope(envelope, inner: str):
    """Close the wrapper, not only what it wraps.

    A grammar that closes the signed object and leaves its container open is
    not closed: an unknown field beside the signature is unread, and a
    signature of the wrong length reaches a verifier that may raise on it
    rather than refuse it.
    """
    _closed(envelope, {inner, "signature"})
    _bad(not isinstance(envelope[inner], dict))
    raw_signature(envelope["signature"])
    return envelope[inner], envelope["signature"].removeprefix("ed25519:")


def _parse_sensor(sensor) -> None:
    _closed(sensor, SENSOR_KEYS)
    for field in ("sensor_id", "quantity", "unit", "direction", "calibration_ref"):
        _text(sensor[field])
    for field in ("range_min", "range_max", "noise_floor"):
        _number(sensor[field])
    _bad(not sensor["range_min"] < sensor["range_max"])
    _bad(sensor["noise_floor"] <= 0)


def _parse_capacity(capacity) -> None:
    _closed(capacity, CAPACITY_KEYS)
    _text(capacity["parameter"])
    _number(capacity["value"])
    _vocab(capacity["provenance"], PROVENANCE)


def _parse_actuator(actuator) -> None:
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


def _parse_proof(proof, kind) -> None:
    _bad(not isinstance(proof, dict))
    method = proof.get("method")
    _vocab(method, METHODS)
    _closed(proof, PROOF_KEYS[method])
    _whole(proof["performed_at_ms"])
    _bad(not isinstance(proof["observations"], list))
    if method == "undemonstrated":
        _text(proof["reason"])
        _bad(proof["observations"] != [])
        return
    _bad(not proof["observations"])
    for observation in proof["observations"]:
        _bad(not isinstance(observation, dict))
        present = set(observation)
        _bad(not OBSERVATION_REQUIRED <= present)
        _bad(not present <= OBSERVATION_REQUIRED | OBSERVATION_OPTIONAL)
        _vocab(observation["commanded"], OUTCOMES)
        _vocab(observation["coil_state"], COIL)
        _vocab(observation["terminal_state_observed"], CIRCUIT)
        _flag(observation["load_present_before"])
        _flag(observation["load_present_after"])
        if "gpio_level" in observation:
            # A pin level is meaningless for a channel with no pin, so its
            # presence is a shape error rather than an ignorable extra.
            _bad(kind != "local_gpio")
            _vocab(observation["gpio_level"], GPIO_LEVELS)
        for field in ("sensor_before", "sensor_after"):
            if field in observation:
                _number(observation[field])
        if "instrument" in observation:
            _text(observation["instrument"])
        # Readings are paired: one side alone cannot show a change.
        _bad(("sensor_before" in observation) != ("sensor_after" in observation))


def _encodable_tree(node) -> None:
    """Every string anywhere in the document must be UTF-8 encodable."""
    if isinstance(node, str):
        _encodable(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                _encodable(key)
            _encodable_tree(value)
    elif isinstance(node, list):
        for value in node:
            _encodable_tree(value)


def st_parses(b, ctx):
    """The complete closed grammar.

    Every object is exactly its declared keys. An unknown key is refused rather
    than ignored, at every level rather than only the top: a stale safety field
    that a consumer silently drops reads, to whoever wrote it, as a declaration
    that took effect.
    """
    _closed(b, BINDING_KEYS)
    _bad(b["v"] != 1)
    _encodable_tree(b)
    for field in ("device_id", "signer_id", "actor", "reason"):
        _text(b[field])
    raw_key(b["signing_key"])
    _whole(b["binding_seq"])
    _bad(b["binding_seq"] < 1)
    _whole(b["issued_at_ms"])
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
        _numbers(zone)


def _numbers(node):
    if isinstance(node, bool):
        return
    if isinstance(node, int) and abs(node) > 9007199254740991:
        raise RefusedError("parses", "malformed")
    if isinstance(node, float):
        if node != 0.0 and not (1e-4 <= abs(node) < 1e16):
            raise RefusedError("parses", "malformed")
    if isinstance(node, dict):
        for v in node.values():
            _numbers(v)
    elif isinstance(node, list):
        for v in node:
            _numbers(v)


def st_device_id(b, ctx):
    if b["device_id"] != ctx["device_id"]:
        raise RefusedError("device_id", "wrong_device")


def _anchors(ctx):
    current = bytes.fromhex(ctx["commissioning_anchor_current_hex"])
    prev_hex = ctx.get("commissioning_anchor_previous_hex")
    previous = bytes.fromhex(prev_hex) if prev_hex else None
    provisioning = bytes.fromhex(ctx["provisioning_anchor_hex"])
    return current, previous, provisioning


def st_key_selection(b, ctx):
    """Select exactly one candidate key. No trial verification, no verdict."""
    current, previous, provisioning = _anchors(ctx)
    if current == provisioning or (previous is not None and previous == provisioning):
        raise RefusedError("key_selection", "anchor_collision")
    named = raw_key(b["signing_key"])
    if named not in {current, previous, provisioning}:
        raise RefusedError("key_selection", "unknown_signer")


def st_signature(b, ctx, sig_b64):
    try:
        Ed25519PublicKey.from_public_bytes(raw_key(b["signing_key"])).verify(
            base64.b64decode(sig_b64), cbytes(b)
        )
    except InvalidSignature:
        raise RefusedError("signature", "bad_signature") from None


def st_authority(b, ctx):
    """Decided only over a verified signature, so it cannot be manufactured."""
    current, previous, provisioning = _anchors(ctx)
    named = raw_key(b["signing_key"])
    if named == provisioning:
        raise RefusedError("authority", "wrong_authority")
    if previous is not None and named == previous:
        raise RefusedError("authority", "superseded_signer")
    if named != current:  # unreachable after key_selection; fail closed anyway
        raise RefusedError("authority", "unknown_signer")


def st_freshness(b, ctx):
    if b["binding_seq"] <= ctx["accepted_binding_seq"]:
        raise RefusedError("freshness", "stale")
    if b["supersedes"] != ctx["accepted_binding_hash"]:
        raise RefusedError("freshness", "stale")


def st_mapping_self_consistency(b, ctx):
    for z in b["zones"]:
        m = z["actuator"]["commissioned_mapping"]
        if m["open_protected_circuit"] == m["close_protected_circuit"]:
            raise RefusedError("mapping_self_consistency", "mapping_contradiction")
        opens = m["open_protected_circuit"] == "de_energised"
        if opens != (m["de_energised_terminal_state"] == "open"):
            raise RefusedError("mapping_self_consistency", "mapping_contradiction")


def st_proof_consistency(b, ctx):
    for z in b["zones"]:
        p, m = z["proof"], z["actuator"]["commissioned_mapping"]
        if p["method"] == "undemonstrated":
            continue
        noise_floor = z["sensor"]["noise_floor"]
        seen = set()
        for ob in p["observations"]:
            outcome = ob["commanded"]
            seen.add(outcome)
            if ob["coil_state"] != m[outcome]:
                raise RefusedError("proof_consistency", "proof_contradiction")
            opening = outcome == "open_protected_circuit"
            if ob["terminal_state_observed"] != ("open" if opening else "closed"):
                raise RefusedError("proof_consistency", "proof_contradiction")

            # The instrument decides whether the load was present. The sensor
            # reading is recorded evidence, never the classifier: a threshold
            # in prose is a threshold two implementations pick differently.
            before, after = ob["load_present_before"], ob["load_present_after"]
            if (before, after) != ((True, False) if opening else (False, True)):
                raise RefusedError("proof_consistency", "proof_contradiction")

            if "sensor_before" in ob and "sensor_after" in ob:
                delta = ob["sensor_after"] - ob["sensor_before"]
                if abs(delta) <= noise_floor:
                    raise RefusedError("proof_consistency", "proof_contradiction")
                if (delta > 0) != after:
                    raise RefusedError("proof_consistency", "proof_contradiction")

            if "gpio_level" in ob:
                active_high = z["actuator"]["identity"]["active_high"]
                energised = ob["coil_state"] == "energised"
                want = "high" if energised == active_high else "low"
                if ob["gpio_level"] != want:
                    raise RefusedError("proof_consistency", "proof_contradiction")
        if seen != {"open_protected_circuit", "close_protected_circuit"}:
            raise RefusedError("proof_consistency", "proof_contradiction")
    # A revision that changes actuator identity, mapping or calibration must
    # carry a proof performed after the accepted document.
    prior = ctx.get("accepted_zone_state")
    if prior:
        for z in b["zones"]:
            was = prior.get(z["zone_id"])
            if not was:
                continue
            changed = (
                was["identity"] != z["actuator"]["identity"]
                or was["mapping"] != z["actuator"]["commissioned_mapping"]
                or was["calibration_ref"] != z["sensor"]["calibration_ref"]
            )
            if changed and z["proof"]["performed_at_ms"] <= was["proof_at_ms"]:
                raise RefusedError("proof_consistency", "stale_proof")


def st_bounds(b, ctx):
    mult = ctx["profile_multiplier"]
    for z in b["zones"]:
        cap, s = z["rated_capacity"]["value"], z["sensor"]
        if cap <= 0 or cap > s["range_max"] or cap < s["range_min"]:
            raise RefusedError("bounds", "out_of_bounds")
        if cap * mult > s["range_max"]:
            raise RefusedError("bounds", "out_of_bounds")


def _ident(a):
    return (a["kind"], json.dumps(a["identity"], sort_keys=True))


def st_disambiguation(b, ctx):
    sensors = [z["sensor"]["sensor_id"] for z in b["zones"]]
    acts = [_ident(z["actuator"]) for z in b["zones"]]
    if len(set(sensors)) != len(sensors) or len(set(acts)) != len(acts):
        raise RefusedError("disambiguation", "ambiguous_binding")


def st_inventory(b, ctx):
    inv = ctx["declared_inventory"]
    declared_acts = {_ident(a) for a in inv["actuators"]}
    for z in b["zones"]:
        if z["sensor"]["sensor_id"] not in inv["sensor_ids"]:
            raise RefusedError("inventory", "unknown_hardware")
        if _ident(z["actuator"]) not in declared_acts:
            raise RefusedError("inventory", "unknown_hardware")
    bound = {_ident(z["actuator"]) for z in b["zones"]}
    if declared_acts - bound:
        raise RefusedError("inventory", "unbound_actuator")


def st_activation_posture(b, ctx):
    if ctx["deployment_posture"] == "development":
        return
    for z in b["zones"]:
        if z["proof"]["method"] == "undemonstrated":
            raise RefusedError("activation_posture", "undemonstrated_binding")


STAGES = {
    "parses": st_parses,
    "device_id": st_device_id,
    "key_selection": st_key_selection,
    "authority": st_authority,
    "freshness": st_freshness,
    "mapping_self_consistency": st_mapping_self_consistency,
    "proof_consistency": st_proof_consistency,
    "bounds": st_bounds,
    "disambiguation": st_disambiguation,
    "inventory": st_inventory,
    "activation_posture": st_activation_posture,
}


def run(b, ctx, sig_b64):
    for stage in ORDER:
        if stage == "signature":
            st_signature(b, ctx, sig_b64)
        else:
            STAGES[stage](b, ctx)


PROFILE_KEYS = {
    "v",
    "binding_hash",
    "binding_seq",
    "device_id",
    "firmware_device_id",
    "channel",
    "commissioned_mapping",
    "signing_key",
}

PROFILE_ORDER = [
    "parses",
    "device_binding",
    "key_selection",
    "signature",
    "authority",
    "binding_match",
    "mapping_match",
]


def run_profile(pr, ctx, sig_b64):
    """Same authority discipline as a binding, then the two bindings checks."""
    _closed(pr, PROFILE_KEYS)
    _bad(pr["v"] != 1)
    _encodable_tree(pr)
    for field in ("device_id", "firmware_device_id", "channel"):
        _text(pr[field])
    _whole(pr["binding_seq"])
    _bad(pr["binding_seq"] < 1)
    _bad(not DIGEST.match(str(pr["binding_hash"])))
    raw_key(pr["signing_key"])
    mapping = pr["commissioned_mapping"]
    _closed(mapping, MAP_KEYS)
    _vocab(mapping["open_protected_circuit"], COIL)
    _vocab(mapping["close_protected_circuit"], COIL)
    _vocab(mapping["de_energised_terminal_state"], CIRCUIT)
    if pr["firmware_device_id"] != ctx["firmware_device_id"]:
        raise RefusedError("device_binding", "wrong_device")
    if pr["channel"] != ctx["channel"]:
        raise RefusedError("device_binding", "profile_channel_mismatch")

    # Identical discipline to a binding, including rotation. A profile naming
    # the previous generation must verify first and then be refused as
    # superseded -- not dismissed as an unknown key, which would report a
    # rotation as a stranger and hide that the key was ours.
    current, previous, provisioning = _anchors(ctx)
    if current == provisioning or (previous is not None and previous == provisioning):
        raise RefusedError("key_selection", "anchor_collision")
    named = raw_key(pr["signing_key"])
    candidates = {current, provisioning}
    if previous is not None:
        candidates.add(previous)
    if named not in candidates:
        raise RefusedError("key_selection", "unknown_signer")

    try:
        Ed25519PublicKey.from_public_bytes(named).verify(
            base64.b64decode(sig_b64), cbytes(pr)
        )
    except InvalidSignature:
        raise RefusedError("signature", "bad_signature") from None

    if named == provisioning:
        raise RefusedError("authority", "wrong_authority")
    if previous is not None and named == previous:
        raise RefusedError("authority", "superseded_signer")

    if (
        pr["binding_hash"] != ctx["accepted_binding_hash"]
        or pr["binding_seq"] != ctx["accepted_binding_seq"]
    ):
        raise RefusedError("binding_match", "profile_binding_mismatch")
    if pr["commissioned_mapping"] != ctx["expected_mapping"]:
        raise RefusedError("mapping_match", "profile_mapping_mismatch")


def run_envelope(envelope, ctx):
    """Verify a wire envelope: the wrapper, then the document inside it."""
    binding, sig_b64 = parse_envelope(envelope, "binding")
    run(binding, ctx, sig_b64)


def run_profile_envelope(envelope, ctx):
    profile, sig_b64 = parse_envelope(envelope, "firmware_profile")
    run_profile(profile, ctx, sig_b64)


def main(path: str) -> int:
    corpus = json.loads(open(path, encoding="utf-8").read())
    failures = []

    for c in corpus["cases"] + corpus["reject_cases"]:
        b, name = c["binding"], c["name"]
        # Recorded bytes must be reproducible.
        if cbytes(b).hex() != c["canonical_hex"]:
            failures.append(f"{name}: canonical_hex does not reproduce")
        want = "sha256:" + hashlib.sha256(cbytes(b)).hexdigest()
        if want != c["canonical_sha256"]:
            failures.append(f"{name}: canonical_sha256 wrong")
        env = {"binding": b, "signature": "ed25519:" + c["signature_b64"]}
        if cbytes(env).hex() != c["message_hex"]:
            failures.append(f"{name}: message_hex does not reproduce")

    for c in corpus["cases"]:
        try:
            run(c["binding"], c["verifier_context"], c["signature_b64"])
        except RefusedError as r:
            failures.append(
                f"{c['name']}: accept case refused at {r.stage} ({r.reason})"
            )

    for c in corpus["reject_cases"]:
        name, want_reason = c["name"], c["reason"]
        try:
            run(c["binding"], c["verifier_context"], c["signature_b64"])
        except RefusedError as r:
            if r.reason != want_reason:
                failures.append(
                    f"{name}: refused as {r.reason!r} at {r.stage}, declared {want_reason!r}"
                )
            # The stage is part of the vector: refusing for the right reason at
            # the wrong stage is not evidence the named check exists.
            if r.stage != c.get("stage"):
                failures.append(
                    f"{name}: refused at {r.stage!r}, vector declares {c.get('stage')!r}"
                )
            # signature_valid must agree with where the refusal happened.
            decided_after_sig = ORDER.index(r.stage) > ORDER.index("signature")
            if c["signature_valid"] and r.stage == "signature":
                failures.append(
                    f"{name}: signature_valid true but refused at signature"
                )
            if not c["signature_valid"] and decided_after_sig:
                failures.append(
                    f"{name}: signature_valid false but refused after signature"
                )
        else:
            failures.append(f"{name}: reject case was ACCEPTED")

    for c in corpus.get("firmware_profile_cases", []):
        pr = c["firmware_profile"]
        if cbytes(pr).hex() != c["canonical_hex"]:
            failures.append(f"{c['name']}: profile canonical_hex does not reproduce")
        try:
            run_profile(pr, c["verifier_context"], c["signature_b64"])
        except RefusedError as r:
            failures.append(
                f"{c['name']}: accept profile refused at {r.stage} ({r.reason})"
            )

    for c in corpus.get("firmware_profile_reject_cases", []):
        pr = c["firmware_profile"]
        if cbytes(pr).hex() != c["canonical_hex"]:
            failures.append(f"{c['name']}: profile canonical_hex does not reproduce")
        try:
            run_profile(pr, c["verifier_context"], c["signature_b64"])
        except RefusedError as r:
            if r.reason != c["reason"]:
                failures.append(
                    f"{c['name']}: refused as {r.reason!r}, declared {c['reason']!r}"
                )
            if r.stage != c.get("stage"):
                failures.append(
                    f"{c['name']}: refused at {r.stage!r}, vector declares "
                    f"{c.get('stage')!r}"
                )
            decided_after_sig = PROFILE_ORDER.index(r.stage) > PROFILE_ORDER.index(
                "signature"
            )
            if c.get("signature_valid") and r.stage == "signature":
                failures.append(
                    f"{c['name']}: signature_valid true but refused at signature"
                )
            if c.get("signature_valid") is False and decided_after_sig:
                failures.append(
                    f"{c['name']}: signature_valid false but refused after signature"
                )
            if "signature_valid" not in c:
                failures.append(f"{c['name']}: reject profile has no signature_valid")
        else:
            failures.append(f"{c['name']}: reject profile was ACCEPTED")

    for c in corpus.get("envelope_reject_cases", []):
        runner = run_envelope if "binding" in c["envelope"] else run_profile_envelope
        try:
            runner(c["envelope"], c["verifier_context"])
        except RefusedError as r:
            if r.reason != c["reason"] or r.stage != c["stage"]:
                failures.append(
                    f"{c['name']}: refused {r.reason!r}@{r.stage}, declared "
                    f"{c['reason']!r}@{c['stage']}"
                )
        except Exception as exc:  # noqa: BLE001 - the property under test
            failures.append(
                f"{c['name']}: raised {type(exc).__name__} instead of a verdict"
            )
        else:
            failures.append(f"{c['name']}: envelope reject case was ACCEPTED")

    for f in failures:
        print("FAIL", f)
    print(
        f"\n{len(corpus['cases'])} accept, {len(corpus['reject_cases'])} reject, "
        f"{len(corpus.get('firmware_profile_cases', []))} profile accept, "
        f"{len(corpus.get('firmware_profile_reject_cases', []))} profile reject, "
        f"{len(corpus.get('envelope_reject_cases', []))} envelope reject, "
        f"{len(failures)} failures"
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
