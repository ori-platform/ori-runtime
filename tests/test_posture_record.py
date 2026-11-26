# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""runtime-posture/v1's record, held to the vendored corpus byte for byte."""

import base64
import dataclasses
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.posture import (
    PostureMembers,
    PostureRecordError,
    alert_class_list,
    build_record,
    key_identity,
)

CORPUS = json.loads(
    (
        Path(__file__).parent / "vectors" / "runtime_posture" / "posture-v1.json"
    ).read_text(encoding="utf-8")
)


def _key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(
        f"ori runtime-posture/v1 posture {label} test key".encode()
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


KEYS = {label: _key(label) for label in ("A", "B")}


def _members(record: dict[str, Any]) -> PostureMembers:
    return PostureMembers(
        device_id=record["device_id"],
        release=record["release"],
        deployment_profile=record["deployment_profile"],
        commissioned_binding=record["commissioned_binding"],
        alert_classes=tuple(record["alert_classes"]),
        boot_generation=record["boot_generation"],
        posture_seq=record["posture_seq"],
        issued_at_ms=record["issued_at_ms"],
    )


def test_the_test_keys_are_the_corpus_keys() -> None:
    for label, key in KEYS.items():
        raw = key.public_key().public_bytes_raw()
        listed = CORPUS["test_keys"][label]
        assert listed["public_key"] == "ed25519:" + base64.b64encode(raw).decode()
        assert key_identity(raw) == listed["key_identity"]


def _signed_by(record: dict[str, Any]) -> Ed25519PrivateKey | None:
    for key in KEYS.values():
        raw = key.public_key().public_bytes_raw()
        if record.get("key_identity") == key_identity(raw):
            return key
    return None


PASSING = [case for case in CORPUS["records"] if case["expected"] == "pass"]


@pytest.mark.parametrize("case", PASSING, ids=[c["name"] for c in PASSING])
def test_the_runtime_reproduces_every_accepted_record_byte_for_byte(
    case: dict[str, Any],
) -> None:
    record = json.loads(case["record"])
    key = _signed_by(record)
    assert key is not None, "an accepted record is signed by a corpus key"
    built = build_record(
        _members(record),
        public_key=key.public_key().public_bytes_raw(),
        sign=key.sign,
    )
    assert built == case["record"].encode("ascii")


MALFORMED_MEMBERS: list[tuple[str, dict[str, Any]]] = [
    ("device_id", {"device_id": "a/b"}),
    ("device_id", {"device_id": "A" * 129}),
    ("release", {"release": "2.5.1-beta.1"}),
    ("release", {"release": "02.5.1"}),
    ("release", {"release": "1" * 61 + ".0.0"}),
    ("deployment_profile", {"deployment_profile": "prod"}),
    ("commissioned_binding", {"commissioned_binding": "sha256:" + "A" * 64}),
    ("alert_classes", {"alert_classes": ("b", "a")}),
    ("alert_classes", {"alert_classes": ("a", "a")}),
    ("alert_classes", {"alert_classes": ("Bad",)}),
    ("alert_classes", {"alert_classes": ("a" + "b" * 32,)}),
    ("alert_classes", {"alert_classes": ("caf\u00e9",)}),
    ("alert_classes", {"alert_classes": (1,)}),
    ("device_id", {"device_id": 7}),
    ("release", {"release": "1" * 56 + ".0.0-rc.1"}),
    ("alert_classes", {"alert_classes": tuple(f"c{i}" for i in range(11))}),
    ("boot_generation", {"boot_generation": 0}),
    ("posture_seq", {"posture_seq": True}),
    ("issued_at_ms", {"issued_at_ms": 2**53}),
]


@pytest.mark.parametrize(
    ("member", "change"), MALFORMED_MEMBERS, ids=[m for m, _ in MALFORMED_MEMBERS]
)
def test_a_member_v1_cannot_carry_signs_nothing(
    member: str, change: dict[str, Any]
) -> None:
    base = _members(json.loads(PASSING[0]["record"]))
    fields = base.__dict__ | change
    signed: list[bytes] = []
    with pytest.raises(PostureRecordError):
        build_record(
            PostureMembers(**fields),
            public_key=KEYS["A"].public_key().public_bytes_raw(),
            sign=lambda data: signed.append(data) or KEYS["A"].sign(data),
        )
    assert signed == []


def test_the_bounds_v1_states_are_accepted_at_their_edge() -> None:
    base = _members(json.loads(PASSING[0]["record"]))
    edge = base.__dict__ | {
        "device_id": "A" * 128,
        "release": "1" * 60 + ".0.0",
        "alert_classes": tuple(sorted(f"c{i}" + "x" * 30 for i in range(10))),
        "issued_at_ms": 2**53 - 1,
        "commissioned_binding": None,
    }
    build_record(
        PostureMembers(**edge),
        public_key=KEYS["A"].public_key().public_bytes_raw(),
        sign=KEYS["A"].sign,
    )


def test_alert_classes_are_ordered_by_bytes_and_deduplicated() -> None:
    assert alert_class_list(["b_x", "a", "b", "a"]) == ("a", "b", "b_x")


# --- operator-socket/v3 runtime_device_key -----------------------------------

READBACK = CORPUS["readback"]
OPERATOR_UID = 1000
PEERS = {"root": 0, "operator": OPERATOR_UID, "other": 2000}


@pytest.mark.parametrize("case", READBACK, ids=[c["name"] for c in READBACK])
async def test_the_readback_answers_every_corpus_case(
    case: dict[str, Any], tmp_path: Path
) -> None:
    from ori.operator_socket import OperatorSocketServer, PeerCredentials

    key = base64.b64decode(case["posture_key"].removeprefix("ed25519:"))

    async def unused(*_args: Any) -> Any:
        raise AssertionError("no other operation is reached")

    server = OperatorSocketServer(
        directory=tmp_path,
        reconcile=unused,
        commission=unused,
        operator_uid=lambda: OPERATOR_UID,
        device_key=lambda: (case["device_id"], key) if case["key_loaded"] else None,
    )

    async def caller() -> PeerCredentials | None:
        uid = PEERS.get(case["peer"]) if case["peer"] is not None else None
        return None if uid is None else PeerCredentials(uid=uid, pid=1, login_uid=None)

    answer = await server.answer(case["request"].encode("utf-8") + b"\n", caller)
    if not answer.get("ok"):
        answer = answer | {"error": {"code": answer["error"]["code"]}}
    assert answer == case["expected"]


def test_the_largest_record_v1_allows_fits_the_gateway_payload_bound() -> None:
    from ori.gateway.payload_bounds import PAYLOAD_MAXIMA, RUNTIME_POSTURE

    largest = PostureMembers(
        device_id="A" * 128,
        release="1" * 60 + ".0.0",
        deployment_profile="development",
        commissioned_binding="sha256:" + "f" * 64,
        alert_classes=tuple(sorted(f"{c}" + "x" * 31 for c in "abcdefghij")),
        boot_generation=2**53 - 1,
        posture_seq=2**53 - 1,
        issued_at_ms=2**53 - 1,
    )
    record = build_record(
        largest,
        public_key=KEYS["A"].public_key().public_bytes_raw(),
        sign=KEYS["A"].sign,
    )
    assert len(record) <= PAYLOAD_MAXIMA[RUNTIME_POSTURE]


def test_a_candidate_release_of_exactly_64_characters_is_accepted() -> None:
    base = _members(json.loads(PASSING[0]["record"]))
    build_record(
        dataclasses.replace(base, release="1" * 55 + ".0.0-rc.1"),
        public_key=KEYS["A"].public_key().public_bytes_raw(),
        sign=KEYS["A"].sign,
    )
