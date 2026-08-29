# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The native chain producer, measured against `ori-specs/evidence/v2`.

The vectors are the acceptance criteria: what the producer emits must be what
the contract says, byte for byte, and the rules it must never break are the
thirteen the contract enumerates. Tests here drive the producer and compare
against those vectors rather than against the producer's own output.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.evidence.canonical import (
    INTEGER_MAX,
    CanonicalisationError,
    canonical_json,
)
from ori.security.evidence.chain import (
    GENESIS_PREV_EVENT_HASH,
    SCHEMA_VERSION,
    SIGNED_COLUMNS,
    EvidenceChain,
    EvidenceChainError,
    attestation_event_id,
)
from ori.security.evidence.device_key import DeviceKeyError, EvidenceDeviceKey

VECTORS = pathlib.Path(__file__).parent.parent / "vectors" / "evidence_v2"
DEVICE = "energy-monitor-ikeja-01"


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text())


@pytest.fixture
def chain(tmp_path):
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "install-secret")
    produced = EvidenceChain(tmp_path / "chain.db", key, DEVICE)
    yield produced
    produced.close()


def _append(produced, action_log_id: int, *, emitted: int = 1751500800000):
    return produced.append(
        event_id=attestation_event_id(DEVICE, action_log_id),
        event_type="SAFETY_ACTION_EXECUTED",
        emitted_at_ms=emitted,
        payload={
            "kind": "runtime_action",
            "attestation": "at_emission",
            "action_log_id": action_log_id,
        },
        created_at_ms=emitted + 40,
    )


# --------------------------------------------------------------------------
# Agreement with the contract's own constants
# --------------------------------------------------------------------------


def test_genesis_matches_the_contract_vector():
    assert GENESIS_PREV_EVENT_HASH == load("genesis.json")["genesis_prev_event_hash"]


def test_event_ids_match_the_contract_vector():
    vector = load("event-id.json")
    for case in vector["cases"]:
        assert (
            attestation_event_id(case["device_id"], case["action_log_id"])
            == case["event_id"]
        )


def test_canonical_form_matches_the_contract_vector():
    for case in load("canonical-form.json")["accept_cases"]:
        assert canonical_json(case["value"]).hex() == case["canonical_hex"], case[
            "name"
        ]


# The contract's refusals divide by which side can actually enforce them, and
# the division is not stated there. A producer serialises a native mapping, and
# a native mapping cannot hold the same key twice — `{"a":1,"a":2}` has already
# collapsed to `{"a": 2}` before the producer sees it. So the duplicate-key
# rule binds whoever parses bytes back, never the producer, and asserting the
# producer refuses it would be asserting something structurally impossible.
PRODUCER_BINDINGS = frozenset({"producer", "both"})


def test_the_contract_declares_an_owner_for_every_refusal():
    """An unowned refusal is one nobody is obliged to enforce."""
    for case in load("canonical-form.json")["reject_cases"]:
        assert case["binds"] in {"producer", "verifier", "both"}, case["name"]


def test_the_producer_refuses_every_form_it_can_be_handed():
    """The refusals are the producer's own, not a test-local reimplementation."""
    checked = 0
    for case in load("canonical-form.json")["reject_cases"]:
        if case["binds"] not in PRODUCER_BINDINGS:
            continue
        if case["input_kind"] == "native_pairs":
            value = {key: item for key, item in case["input_pairs"]}
        else:
            # NaN and the infinities have no JSON literal, so they are parsed
            # with constants allowed and then handed to the producer, which is
            # the component that must refuse them.
            value = json.loads(case["input_json"], parse_constant=float)
        with pytest.raises(CanonicalisationError):
            canonical_json(value)
        checked += 1
    assert checked >= 6, "the producer-side refusals were not exercised"


def test_duplicate_keys_are_a_parse_side_rule_the_producer_cannot_reach():
    """Documented as a real division, not waved away as an exception.

    Skipping this case silently would look identical to covering it, so the
    reason it does not apply to the producer is asserted instead: the defect is
    destroyed by parsing, which is exactly why a reader must catch it there.
    """
    case = next(
        c
        for c in load("canonical-form.json")["reject_cases"]
        if c["binds"] == "verifier"
    )
    assert case["violates"] == "duplicate_key"
    collapsed = json.loads(case["input_json"])
    assert collapsed == {"a": 2}, "the duplicate was not collapsed as expected"
    # Having collapsed, it is an ordinary object the producer will accept.
    assert canonical_json(collapsed) == b'{"a":2}'

    # A reader must therefore detect it while parsing, before it is lost.
    seen = []

    def pairs_hook(pairs):
        seen.append([key for key, _ in pairs])
        return dict(pairs)

    json.loads(case["input_json"], object_pairs_hook=pairs_hook)
    assert seen and len(seen[0]) != len(set(seen[0])), (
        "duplicate detection must happen during parsing"
    )


def test_nested_values_are_refused_too():
    """Canonicalisation is recursive, so the refusal must be."""
    with pytest.raises(CanonicalisationError):
        canonical_json({"readings": [{"amps": 1e-5}]})
    with pytest.raises(CanonicalisationError):
        canonical_json({"a": {"b": [INTEGER_MAX + 1]}})


# --------------------------------------------------------------------------
# What the producer emits
# --------------------------------------------------------------------------


def test_first_row_chains_from_genesis_and_verifies(chain):
    row = _append(chain, 1)
    envelope = json.loads(row["canonical_json"])

    assert envelope["prev_event_hash"] == GENESIS_PREV_EVENT_HASH
    assert envelope["schema_version"] == SCHEMA_VERSION
    assert envelope["sequence_num"] == 1
    assert set(envelope) == {
        "device_id",
        "emitted_at_ms",
        "event_id",
        "event_type",
        "payload",
        "prev_event_hash",
        "schema_version",
        "sequence_num",
    }
    signed = row["canonical_json"].encode()
    assert hashlib.sha256(signed).hexdigest() == row["event_hash"]
    assert canonical_json(envelope) == signed


def test_rows_chain_to_their_predecessor(chain):
    first = _append(chain, 1)
    second = _append(chain, 2)
    assert second["prev_event_hash"] == first["event_hash"]
    assert second["seq"] == first["seq"] + 1
    assert chain.verify_chain() == []


def test_a_produced_chain_breaks_no_contract_rule(chain):
    """The whole point: nothing the producer emits violates the thirteen rules."""
    for index in range(1, 6):
        _append(chain, index, emitted=1751500800000 + index * 1000)
    assert chain.verify_chain() == []


def test_appending_is_idempotent_on_event_id(chain):
    """A crash between append and status update must not double-attest."""
    first = _append(chain, 7)
    again = _append(chain, 7)
    assert again["seq"] == first["seq"]
    assert again["event_hash"] == first["event_hash"]
    assert chain.head()[0] == 1


def test_unknown_event_types_are_refused(chain):
    with pytest.raises(EvidenceChainError):
        chain.append(
            event_id="e1",
            event_type="NOT_A_PROTOCOL_EVENT",
            emitted_at_ms=1,
            payload={},
            created_at_ms=1,
        )


def test_an_unrepresentable_payload_is_refused_before_it_is_signed(chain):
    """Signing bytes no verifier can reproduce would be worse than refusing."""
    with pytest.raises(CanonicalisationError):
        chain.append(
            event_id="e2",
            event_type="UPTIME_HEARTBEAT",
            emitted_at_ms=1,
            payload={"drift": float("inf")},
            created_at_ms=1,
        )
    assert chain.head() == (0, GENESIS_PREV_EVENT_HASH)


# --------------------------------------------------------------------------
# Immutability is the database's job
# --------------------------------------------------------------------------


# One value per signed column that differs from what the producer writes.
# Parametrised deliberately: an earlier version mutated only `payload_json`,
# and the trigger was missing `seq` entirely — a column could be rewritten
# while the test reported immutability enforced.
COLUMN_MUTATIONS = {
    "seq": 9,
    "event_id": "a-different-identity",
    "event_type": "UPTIME_HEARTBEAT",
    "device_id": "some-other-device",
    "emitted_at_ms": 1,
    "payload_json": "{}",
    "canonical_json": "{}",
    "event_hash": "0" * 64,
    "prev_event_hash": "0" * 64,
    "signature": "ed25519:AA==",
    "created_at_ms": 1,
}


def test_every_signed_column_is_covered_by_a_mutation():
    """The table above must not drift behind the contract's column list."""
    assert set(COLUMN_MUTATIONS) == set(SIGNED_COLUMNS)


@pytest.mark.parametrize("column", sorted(COLUMN_MUTATIONS))
def test_signed_columns_cannot_be_updated(chain, column):
    """Enforced by trigger, not by application code remembering not to."""
    _append(chain, 1)
    connection = sqlite3.connect(chain._db_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                f"UPDATE evidence_chain SET {column} = ? WHERE seq = 1",
                (COLUMN_MUTATIONS[column],),
            )
    finally:
        connection.close()


def test_rows_cannot_be_deleted(chain):
    _append(chain, 1)
    connection = sqlite3.connect(chain._db_path)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute("DELETE FROM evidence_chain WHERE seq = 1")
    connection.close()


def test_export_bookkeeping_is_the_one_permitted_mutation(chain):
    row = _append(chain, 1)
    chain.mark_exported(row["seq"], 1751500999999)
    updated = chain.find_by_event_id(row["event_id"])
    assert updated["exported"] == 1
    assert updated["exported_at_ms"] == 1751500999999
    assert chain.verify_chain() == []


def test_the_schema_names_nothing_after_the_authority(chain):
    """Naming is scoped to what an operator can reach, and this runs on the device."""
    connection = sqlite3.connect(chain._db_path)
    names = [
        str(name)
        for (name,) in connection.execute(
            "SELECT name FROM sqlite_master WHERE name IS NOT NULL"
        )
    ]
    connection.close()
    assert names, "no schema objects to inspect"
    for name in names:
        assert "verity" not in name.lower(), (
            f"schema object names the authority: {name}"
        )


# --------------------------------------------------------------------------
# The device key
# --------------------------------------------------------------------------


def test_the_key_survives_a_restart(tmp_path):
    path = tmp_path / "device.key"
    first = EvidenceDeviceKey.load_or_create(path, "secret")
    second = EvidenceDeviceKey.load_or_create(path, "secret")
    assert first.public_key_hex == second.public_key_hex


def test_the_wrong_secret_cannot_open_the_key(tmp_path):
    path = tmp_path / "device.key"
    EvidenceDeviceKey.load_or_create(path, "secret")
    with pytest.raises(DeviceKeyError):
        EvidenceDeviceKey.load_or_create(path, "not-the-secret")


def test_an_empty_secret_is_refused(tmp_path):
    """A key sealed under an empty secret is not sealed."""
    with pytest.raises(DeviceKeyError):
        EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "")


def test_the_key_file_is_not_the_raw_seed(tmp_path):
    """Reading the file alone must not yield a signing key."""
    path = tmp_path / "device.key"
    key = EvidenceDeviceKey.load_or_create(path, "secret")
    blob = path.read_bytes()
    assert bytes.fromhex(key.public_key_hex) not in blob
    for offset in range(0, max(1, len(blob) - 32)):
        candidate = blob[offset : offset + 32]
        if len(candidate) < 32:
            break
        derived = Ed25519PrivateKey.from_private_bytes(candidate)
        assert derived.public_key().public_bytes_raw().hex() != key.public_key_hex


def test_the_key_file_is_owner_only(tmp_path):
    path = tmp_path / "device.key"
    EvidenceDeviceKey.load_or_create(path, "secret")
    assert path.stat().st_mode & 0o077 == 0


def test_a_tampered_key_file_is_refused(tmp_path):
    path = tmp_path / "device.key"
    EvidenceDeviceKey.load_or_create(path, "secret")
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 0xFF
    path.write_bytes(bytes(blob))
    with pytest.raises(DeviceKeyError):
        EvidenceDeviceKey.load_or_create(path, "secret")


def test_signatures_are_base64_under_the_wire_prefix(chain):
    row = _append(chain, 1)
    assert row["signature"].startswith("ed25519:")
    assert len(base64.b64decode(row["signature"].split("ed25519:")[1])) == 64


# --------------------------------------------------------------------------
# Idempotency means same identity AND same content
# --------------------------------------------------------------------------


def test_a_replay_with_different_content_is_a_conflict(chain):
    """Returning the stored row would report success for evidence never recorded.

    The caller believes its event is attested. Something else is. A
    deterministic identity colliding with different content is a defect
    upstream, and it has to surface rather than be absorbed.
    """
    event_id = attestation_event_id(DEVICE, 1)
    _append(chain, 1)
    with pytest.raises(EvidenceChainError, match="different content"):
        chain.append(
            event_id=event_id,
            event_type="SAFETY_ACTION_EXECUTED",
            emitted_at_ms=1751500800000,
            payload={
                "kind": "runtime_action",
                "attestation": "at_emission",
                "action_log_id": 999,
            },
            created_at_ms=1751500800040,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("event_type", "UPTIME_HEARTBEAT"),
        ("emitted_at_ms", 1751599999999),
    ],
)
def test_each_component_of_intent_is_compared(chain, field, value):
    event_id = attestation_event_id(DEVICE, 1)
    _append(chain, 1)
    request = {
        "event_id": event_id,
        "event_type": "SAFETY_ACTION_EXECUTED",
        "emitted_at_ms": 1751500800000,
        "payload": {
            "kind": "runtime_action",
            "attestation": "at_emission",
            "action_log_id": 1,
        },
        "created_at_ms": 1751500800040,
    }
    request[field] = value
    with pytest.raises(EvidenceChainError, match="different content"):
        chain.append(**request)


def test_an_identical_replay_still_succeeds(chain):
    """The conflict check must not break the property it guards."""
    first = _append(chain, 1)
    again = _append(chain, 1)
    assert again["seq"] == first["seq"]
    assert chain.head()[0] == 1


# --------------------------------------------------------------------------
# One key, one device, one chain
# --------------------------------------------------------------------------


def test_the_chain_signs_only_for_its_bound_device(chain):
    """append() cannot be handed another identity, because it does not take one."""
    row = _append(chain, 1)
    assert row["device_id"] == DEVICE
    assert json.loads(row["canonical_json"])["device_id"] == DEVICE


def test_reopening_under_another_identity_is_refused(tmp_path):
    """A key that signs for several devices makes attribution unenforceable."""
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "secret")
    first = EvidenceChain(tmp_path / "chain.db", key, DEVICE)
    _append(first, 1)
    first.close()

    with pytest.raises(EvidenceChainError, match="other device identities"):
        EvidenceChain(tmp_path / "chain.db", key, "a-different-device")


def test_a_chain_requires_a_device_identity(tmp_path):
    key = EvidenceDeviceKey.load_or_create(tmp_path / "device.key", "secret")
    with pytest.raises(EvidenceChainError):
        EvidenceChain(tmp_path / "chain.db", key, "")


# --------------------------------------------------------------------------
# verify_chain reports rather than raises
# --------------------------------------------------------------------------


def _forge(chain, tmp_path, name: str, mutations: list[tuple[int, str, object]]):
    """A copy of the chain with the immutability trigger dropped and rows edited.

    Tampering has to happen outside the producer, because the producer refuses
    it — which is the point of the trigger. Verification must still describe
    what it finds in a database someone else has altered.
    """
    forged = tmp_path / name
    source = sqlite3.connect(chain._db_path)
    source.execute("VACUUM INTO ?", (str(forged),))
    source.close()

    connection = sqlite3.connect(forged)
    connection.execute("DROP TRIGGER IF EXISTS evidence_chain_no_signed_update")
    for seq, column, value in mutations:
        connection.execute(
            f"UPDATE evidence_chain SET {column} = ? WHERE seq = ?", (value, seq)
        )
    connection.commit()
    connection.close()

    key = EvidenceDeviceKey.load_or_create(tmp_path / f"{name}.key", "secret")
    return EvidenceChain(forged, key, DEVICE)


def test_verification_reports_a_corrupt_row_without_abandoning_the_walk(
    chain, tmp_path
):
    """An unparseable row must not hide the defects in every row after it.

    Row 1 is made unparseable and row 2 is given a different, distinct defect.
    Both must be reported: raising on the first would end the walk, and the
    second finding is the evidence that it continued.
    """
    _append(chain, 1)
    _append(chain, 2)
    forged = _forge(
        chain,
        tmp_path,
        "walk.db",
        [(1, "canonical_json", "{not json at all"), (2, "event_hash", "0" * 64)],
    )
    try:
        problems = forged.verify_chain()
    finally:
        forged.close()

    assert any("seq 1" in p and "not parseable" in p for p in problems), problems
    assert any("seq 2" in p and "event_hash" in p for p in problems), problems

    # The rules that read the envelope must not run on a row whose bytes will
    # not parse. Corrupting `canonical_json` legitimately breaks the hash and
    # the signature too, so those findings are expected; what must not appear
    # is a dozen derived complaints about fields that could never be read,
    # which bury the one finding that explains the row.
    first_row = [p for p in problems if p.startswith("seq 1:")]
    derived = [p for p in first_row if "envelope" in p or "schema_version" in p]
    assert not derived, f"envelope rules ran on an unparseable row: {derived}"
    assert len(first_row) <= 3, f"corrupt row produced a cascade: {first_row}"


def test_verification_reports_a_non_object_envelope(chain, tmp_path):
    _append(chain, 1)
    forged = _forge(chain, tmp_path, "notobject.db", [(1, "canonical_json", "[1,2,3]")])
    try:
        problems = forged.verify_chain()
    finally:
        forged.close()
    assert any("not a JSON object" in p for p in problems), problems


def test_verification_reports_an_unparseable_payload_column(chain, tmp_path):
    """The payload column is stored separately and can rot on its own."""
    _append(chain, 1)
    forged = _forge(chain, tmp_path, "payload.db", [(1, "payload_json", "{broken")])
    try:
        problems = forged.verify_chain()
    finally:
        forged.close()
    assert any("payload_json is not parseable" in p for p in problems), problems


def test_verification_flags_an_envelope_missing_a_field(chain, tmp_path):
    """The counterpart to the undefined-field case; the code handles both."""
    _append(chain, 1)
    row = chain.find_by_event_id(attestation_event_id(DEVICE, 1))
    envelope = json.loads(row["canonical_json"])
    envelope.pop("sequence_num")
    forged = _forge(
        chain,
        tmp_path,
        "missing.db",
        [
            (
                1,
                "canonical_json",
                json.dumps(envelope, sort_keys=True, separators=(",", ":")),
            )
        ],
    )
    try:
        problems = forged.verify_chain()
    finally:
        forged.close()
    assert any("missing fields" in p and "sequence_num" in p for p in problems), (
        problems
    )


def test_verification_flags_an_envelope_with_an_undefined_field(chain, tmp_path):
    """Rule 13, which the first version of verify_chain did not implement."""
    _append(chain, 1)
    row = chain.find_by_event_id(attestation_event_id(DEVICE, 1))
    envelope = json.loads(row["canonical_json"])
    envelope["unexpected"] = True
    forged = _forge(
        chain,
        tmp_path,
        "undefined.db",
        [
            (
                1,
                "canonical_json",
                json.dumps(envelope, sort_keys=True, separators=(",", ":")),
            )
        ],
    )
    try:
        problems = forged.verify_chain()
    finally:
        forged.close()
    assert any("undefined fields" in p for p in problems), problems
