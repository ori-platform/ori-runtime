# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Reconstruct every `ori-specs/evidence/v2` vector from its documented inputs.

These are the runtime's conformance fixtures for issue #326. The runtime is
becoming a second producer of the evidence chain format, and the contract's
vectors are what "producing it correctly" means, byte for byte.

Nothing here imports whatever generated the vectors. Every value is rebuilt
from the inputs each vector publishes — the genesis preimage, the namespace
URI, the per-event name format, the canonical rules, the seeds — so a vector
that documents one derivation and was produced by another fails.

What this does *not* establish: cross-language agreement. These vectors were
generated in Python and this reconstruction is also Python, so passing proves
the derivations are self-consistent and reproducible, not that a Rust or C
implementation reaches the same bytes. That remains open under
`ori-platform/ori-verity#39`, and `evidence/v2` stays a design target until it
lands.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import pathlib
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

VECTORS = pathlib.Path(__file__).parent / "vectors" / "evidence_v2"

# From ori-specs evidence/v2.md. Restated rather than imported: a conformance
# test that reads its expectations from the thing under test proves nothing.
SCHEMA_VERSION = "ori.evidence.v2"
GENESIS_PREIMAGE = "ori.evidence.genesis.v2"
ROTATION_CONTEXT = "ori.evidence.rotation.v2"
NAMESPACE_URI = "https://oriplatform.dev/specs/evidence/v2/event-id"
INTEGER_MAX = 9007199254740991
ENVELOPE_FIELDS = frozenset(
    {
        "device_id",
        "emitted_at_ms",
        "event_id",
        "event_type",
        "payload",
        "prev_event_hash",
        "schema_version",
        "sequence_num",
    }
)


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


def canonical(value) -> bytes:
    """The contract's canonical form. Sorting is recursive; `sort_keys` does that."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def in_number_zone(value) -> bool:
    """The D-011 agreement zone, where CPython and serde_json emit identical bytes."""
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return abs(value) <= INTEGER_MAX
    if isinstance(value, float):
        if not math.isfinite(value):
            return False
        magnitude = abs(value)
        return magnitude == 0.0 or 1e-4 <= magnitude < 1e16
    if isinstance(value, dict):
        return all(isinstance(k, str) and in_number_zone(v) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return all(in_number_zone(v) for v in value)
    return True


# --------------------------------------------------------------------------
# The vendored copy is intact
# --------------------------------------------------------------------------


def test_vendored_vectors_match_their_manifest():
    """A locally edited vector would make every test below pass vacuously."""
    manifest = load("MANIFEST.json")
    assert manifest["files"], "manifest lists no vectors"
    for name, digest in manifest["files"].items():
        actual = sha256_hex((VECTORS / name).read_bytes())
        assert actual == digest, f"{name} differs from the vendored manifest"


def test_every_vector_is_covered_by_the_manifest():
    present = {p.name for p in VECTORS.glob("*.json")} - {"MANIFEST.json"}
    assert present == set(load("MANIFEST.json")["files"]), (
        "a vector file is present that the manifest does not record, or vice versa"
    )


# --------------------------------------------------------------------------
# Genesis
# --------------------------------------------------------------------------


def test_genesis_derives_from_its_published_preimage():
    vector = load("genesis.json")
    assert vector["preimage"] == GENESIS_PREIMAGE
    assert vector["preimage"].encode().hex() == vector["preimage_utf8_hex"]
    assert (
        sha256_hex(vector["preimage"].encode()) == vector["genesis_prev_event_hash"]
    ), "the genesis value is not the SHA-256 of its own published preimage"


def test_genesis_carries_no_branded_preimage():
    """The whole point of v2's vocabulary. A regression here is the old value."""
    assert "verity" not in load("genesis.json")["preimage"].lower()


# --------------------------------------------------------------------------
# Canonical form
# --------------------------------------------------------------------------


def test_canonical_accept_cases_reproduce_their_bytes():
    vector = load("canonical-form.json")
    assert vector["integer_max"] == INTEGER_MAX
    for case in vector["accept_cases"]:
        rebuilt = canonical(case["value"])
        assert rebuilt.hex() == case["canonical_hex"], f"bytes differ: {case['name']}"
        assert rebuilt.decode() == case["canonical_utf8"], (
            f"text differs: {case['name']}"
        )
        assert in_number_zone(case["value"]), (
            f"accepted case is outside the zone: {case['name']}"
        )


def test_negative_zero_survives_canonicalisation():
    """Distinct from positive zero in the bytes, which is why the rule names it."""
    vector = load("canonical-form.json")
    negative = [c for c in vector["accept_cases"] if "negative zero" in c["name"]]
    assert negative, "no negative-zero case to check"
    assert "-0.0" in negative[0]["canonical_utf8"]


def test_refused_forms_are_enumerated_with_reasons():
    vector = load("canonical-form.json")
    assert len(vector["reject_cases"]) >= 8
    for case in vector["reject_cases"]:
        assert case.get("why"), f"refusal without a reason: {case['name']}"


def _refuse_reason(input_json: str) -> str | None:
    """Parse an input the way a conforming producer must, and name why it is refused.

    A default loader is not enough. `json.loads` accepts NaN and Infinity, and
    silently keeps the last of a duplicated key, so both defects would vanish
    before anything could inspect them.
    """
    seen_duplicate = False

    def pairs_hook(pairs):
        nonlocal seen_duplicate
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            seen_duplicate = True
        return dict(pairs)

    def constant_hook(name):
        raise ValueError(f"non-finite constant: {name}")

    try:
        value = json.loads(
            input_json, object_pairs_hook=pairs_hook, parse_constant=constant_hook
        )
    except ValueError as exc:
        return "non_finite" if "non-finite" in str(exc) else "unparseable"
    if seen_duplicate:
        return "duplicate_key"
    return _first_structural_refusal(value)


def _first_structural_refusal(value) -> str | None:
    """Walk the whole value. Canonicalisation is recursive, so this must be.

    A top-level-only check would accept `{"a": [1e-5]}` and then emit bytes no
    other implementation reproduces, which is the failure the zone exists to
    prevent.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return "integer_range" if abs(value) > INTEGER_MAX else None
    if isinstance(value, float):
        return None if in_number_zone(value) else "number_zone"
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            return "non_string_key"
        for nested in value.values():
            found = _first_structural_refusal(nested)
            if found:
                return found
        return None
    if isinstance(value, list):
        for nested in value:
            found = _first_structural_refusal(nested)
            if found:
                return found
    return None


def test_every_published_refusal_is_actually_refused():
    """Drive the vector's own inputs rather than a hand-written list beside it.

    The earlier version checked six numbers chosen here, which meant the
    duplicate-key and non-string-key refusals in the contract were never
    executed by anything.
    """
    vector = load("canonical-form.json")
    for case in vector["reject_cases"]:
        kind = case["input_kind"]
        if kind == "json_text":
            reason = _refuse_reason(case["input_json"])
        elif kind == "native_pairs":
            # JSON text cannot carry a non-string key, so the vector describes
            # the native object instead and it is built here. An earlier version
            # fed the malformed string `{1:2}`, which was refused as unparseable
            # without the key's type ever being examined — and the mismatch was
            # then hidden behind an exemption, which is how a gap survives a
            # test that appears to cover it.
            reason = _first_structural_refusal(
                {key: value for key, value in case["input_pairs"]}
            )
        else:
            raise AssertionError(f"unknown input_kind {kind!r} in {case['name']}")
        assert reason == case["violates"], (
            f"{case['name']}: refused as {reason!r}, contract declares "
            f"{case['violates']!r}"
        )


def test_accepted_forms_are_not_refused():
    """The refusal path must not reject everything."""
    for case in load("canonical-form.json")["accept_cases"]:
        assert _refuse_reason(canonical(case["value"]).decode()) is None, case["name"]


# --------------------------------------------------------------------------
# Event identifier
# --------------------------------------------------------------------------


def test_namespace_derives_from_the_published_uri():
    vector = load("event-id.json")
    assert vector["namespace_name_uri"] == NAMESPACE_URI
    assert (
        vector["namespace_name_uri"].encode().hex() == vector["namespace_name_utf8_hex"]
    )
    derived = uuid.uuid5(
        uuid.UUID(vector["root_namespace_uuid"]), vector["namespace_name_uri"]
    )
    assert str(derived) == vector["event_id_namespace"]


def test_namespace_bytes_carry_no_hidden_identifier():
    """The v1 namespace decoded to ASCII. This asserts v2's does not."""
    raw = uuid.UUID(load("event-id.json")["event_id_namespace"]).bytes
    assert "verity" not in raw.decode("ascii", "replace").lower()


def test_event_ids_derive_from_the_published_name_format():
    vector = load("event-id.json")
    namespace = uuid.UUID(vector["event_id_namespace"])
    for case in vector["cases"]:
        name = vector["per_event_name_format"].format(**case)
        assert name == case["uuid5_name"]
        assert str(uuid.uuid5(namespace, name)) == case["event_id"]


# --------------------------------------------------------------------------
# Chain rows
# --------------------------------------------------------------------------


def test_rows_chain_hash_and_verify():
    vector = load("chain-row.json")
    public = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["device_seed_hex"])
    ).public_key()
    assert public.public_bytes_raw().hex() == vector["device_public_key_hex"]

    previous = vector["genesis_prev_event_hash"]
    for index, row in enumerate(vector["rows"], start=1):
        envelope = row["envelope"]
        assert set(envelope) == ENVELOPE_FIELDS, f"row {index}: envelope field set"
        assert envelope["schema_version"] == SCHEMA_VERSION, (
            f"row {index}: schema version"
        )
        rebuilt = canonical(envelope)
        assert rebuilt.hex() == row["canonical_hex"], f"row {index}: canonical bytes"
        assert sha256_hex(rebuilt) == row["event_hash"], f"row {index}: event hash"
        assert envelope["prev_event_hash"] == previous, (
            f"row {index}: chains to previous"
        )
        public.verify(base64.b64decode(row["signature"].split("ed25519:")[1]), rebuilt)
        previous = row["event_hash"]


ENVELOPE_TO_COLUMN = {
    5: ("sequence_num", "seq"),
    6: ("prev_event_hash", "prev_event_hash"),
    7: ("event_id", "event_id"),
    8: ("event_type", "event_type"),
    9: ("device_id", "device_id"),
    10: ("emitted_at_ms", "emitted_at_ms"),
}


def _rules_violated(case: dict, public_key) -> set[int]:
    """Independently derive which of the thirteen rules this artifact breaks.

    Written from the contract, not from the case's own claim about itself. A
    check that trusted `case["rule"]` would confirm the label rather than the
    artifact, which is what the previous version of this test did.
    """
    row = case["row"]
    # `canonical_json` is what was signed and hashed, so it is the authority on
    # what the envelope says. The convenience `envelope` object is checked
    # against it separately: a vector whose two copies disagreed would otherwise
    # satisfy every rule below while describing bytes nobody signed.
    signed_bytes = row["canonical_json"].encode()
    envelope = json.loads(signed_bytes)
    columns = row["row_columns"]
    context = case["chain_context"]
    broken: set[int] = set()

    if columns.get("seq") != context["expected_sequence_num"]:
        broken.add(1)
    if columns.get("prev_event_hash") != context["expected_prev_event_hash"]:
        broken.add(2)

    if sha256_hex(signed_bytes) != row["event_hash"]:
        broken.add(3)
    try:
        public_key.verify(
            base64.b64decode(row["signature"].split("ed25519:")[1]), signed_bytes
        )
    except Exception:
        broken.add(4)

    for rule, (envelope_field, column) in ENVELOPE_TO_COLUMN.items():
        if columns.get(column) != envelope.get(envelope_field):
            broken.add(rule)

    if envelope.get("schema_version") != SCHEMA_VERSION:
        broken.add(11)
    if json.loads(row["payload_json"]) != envelope.get("payload"):
        broken.add(12)
    if set(envelope) - ENVELOPE_FIELDS:
        broken.add(13)
    return broken


def test_every_rejection_rule_has_a_case():
    """Thirteen rules, thirteen concrete rows. A rule without one is untested."""
    covered = {case["rule"] for case in load("chain-row.json")["rejection_cases"]}
    assert covered == set(range(1, 14)), (
        f"rules without a case: {set(range(1, 14)) - covered}"
    )


def test_each_rejection_case_violates_exactly_the_rule_it_names():
    """The artifact must break its own rule and nothing else.

    Purity is the property under test, not merely presence of a defect. A case
    that violates a second rule is rejected for the wrong reason and never
    exercises the rule it was written for, so a suite of impure cases reports
    coverage it does not have. Two cases in the contract's first draft did
    exactly that, and this assertion is what found them.
    """
    vector = load("chain-row.json")
    public = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["device_seed_hex"])
    ).public_key()
    for case in vector["rejection_cases"]:
        row = case["row"]
        signed_bytes = row["canonical_json"].encode()
        assert canonical(row["envelope"]) == signed_bytes, (
            f"rule {case['rule']}: the published envelope does not re-canonicalise "
            "to the bytes that were signed"
        )
        assert bytes.fromhex(row["canonical_hex"]) == signed_bytes, (
            f"rule {case['rule']}: canonical_hex is not the signed bytes"
        )
        broken = _rules_violated(case, public)
        assert broken == {case["rule"]}, (
            f"case for rule {case['rule']} ({case['name']}) violates {sorted(broken)}; "
            "it must break exactly its own rule so that rule is the one reached"
        )


def test_a_valid_row_violates_no_rule():
    """The validator must not reject everything, or the test above proves nothing."""
    vector = load("chain-row.json")
    public = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["device_seed_hex"])
    ).public_key()
    first = vector["rows"][0]
    envelope = first["envelope"]
    clean = {
        "row": {
            **first,
            "row_columns": {
                "seq": envelope["sequence_num"],
                "event_id": envelope["event_id"],
                "event_type": envelope["event_type"],
                "device_id": envelope["device_id"],
                "emitted_at_ms": envelope["emitted_at_ms"],
                "prev_event_hash": envelope["prev_event_hash"],
            },
            "payload_json": json.dumps(
                envelope["payload"], sort_keys=True, separators=(",", ":")
            ),
        },
        "chain_context": {
            "expected_sequence_num": envelope["sequence_num"],
            "expected_prev_event_hash": vector["genesis_prev_event_hash"],
        },
    }
    assert _rules_violated(clean, public) == set()


def test_a_v1_row_is_rejected_rather_than_reinterpreted():
    """Rule 11 is what makes version confusion impossible rather than merely unlikely."""
    case = next(c for c in load("chain-row.json")["rejection_cases"] if c["rule"] == 11)
    assert case["row"]["envelope"]["schema_version"] != SCHEMA_VERSION
    assert case["expected"] == "reject"


# --------------------------------------------------------------------------
# Key rotation
# --------------------------------------------------------------------------


def test_rotation_proof_uses_the_neutral_context():
    vector = load("key-rotation.json")
    assert vector["proof_context"] == ROTATION_CONTEXT
    expected = (
        ROTATION_CONTEXT.encode()
        + b"\x00"
        + bytes.fromhex(vector["new_public_key_hex"])
    )
    assert expected.hex() == vector["proof_input_hex"]


def test_rotation_is_dual_signed():
    """The row by the outgoing key, the possession proof by the incoming one."""
    vector = load("key-rotation.json")
    outgoing = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(vector["old_seed_hex"])
    ).public_key()
    incoming_raw = bytes.fromhex(vector["new_public_key_hex"])

    proof = base64.b64decode(
        vector["row"]["envelope"]["payload"]["rotation_sig"].split("ed25519:")[1]
    )
    Ed25519PublicKey.from_public_bytes(incoming_raw).verify(
        proof, bytes.fromhex(vector["proof_input_hex"])
    )

    rebuilt = canonical(vector["row"]["envelope"])
    assert rebuilt.hex() == vector["row"]["canonical_hex"]
    outgoing.verify(
        base64.b64decode(vector["row"]["signature"].split("ed25519:")[1]), rebuilt
    )
