# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime half of the shared runtime-liveness golden corpus.

The device verifier and this signer have to agree on bytes, not on
"equivalent JSON". These tests drive the **production** builder, signer
and envelope against the same file the firmware repo verifies, so a
change on either side that alters the wire format fails here rather than
on a bench.

The runtime only ever produces liveness; it never parses it. So the
reject corpus is mostly a set of device obligations, and what the runtime
owes it is the producer side: it must be unable to emit any message the
device is required to refuse. A signer that can produce an unacceptable
message means the two sides disagree about the contract, and the
disagreement would surface on a device rather than here.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ori.security.firmware.liveness import (
    FirmwareLivenessError,
    FirmwareLivenessSigner,
    FirmwareLivenessSupervisor,
    build_liveness_bytes,
)

VECTOR_PATH = (
    Path(__file__).parent.parent / "fixtures" / "firmware_liveness_vectors.json"
)

# The digest of ori-specs/firmware-commands/liveness-vectors-v1.json. That
# file is the authority and the fixture here is a byte-for-byte mirror of
# it; expectations are never generated from runtime behaviour.
#
# Pinned against the contract rather than against the firmware repo's
# constant: two constants coordinated by hand are not a parity mechanism,
# because a change made in one repository leaves the other still matching
# its own unchanged constant while the corpora silently diverge. Holding
# the artifact in the contract repo is also what lets a reviewer ratify
# the cases rather than a hexadecimal number.
SPEC_DECLARED_SHA256 = (
    "199c9a3363e4fd05073ee43ce67a8cff278945f0fc2a5fc644df02e7ee70c44d"
)

VECTORS = json.loads(VECTOR_PATH.read_text())
CASES = VECTORS["cases"]
REJECT_CASES = VECTORS["reject_cases"]

# Reject cases with no runtime-side meaning, as an EXACT list rather than
# a maximum: a case added upstream fails here until someone triages it,
# so runtime coverage can only grow.
#
# These describe a verifier refusing bytes on receipt. The runtime has no
# parser, so it cannot execute them. Where a case corresponds to a value
# the builder could in principle be asked for, it is executed below
# instead — from the inputs, which is the only form the producer has.
RUNTIME_UNEXECUTED_REJECT_CASES = {
    # Refused on binding or freshness by the device, using state the
    # runtime does not hold.
    "reject_wrong_device_id",
    "reject_wrong_boot_id",
    "reject_manifest_epoch_mismatch",
    "reject_high_seq_from_previous_boot",
    "reject_replayed_runtime_seq",
    "reject_regressing_runtime_seq",
    "reject_rogue_key",
    # Byte-level corruptions the builder has no way to express: it emits
    # one fixed field order, one integer form, no extra members, and
    # always v:1.
    "reject_unsupported_version",
    "reject_non_canonical_integer",
    "reject_reordered_fields",
    "reject_extra_field",
    "reject_missing_field",
    "reject_malformed_signature",
    "reject_signature_wrong_length",
}

# The producer counterpart: values the builder must refuse outright.
BUILDER_REFUSED_CASES = {
    "reject_runtime_seq_zero",
    "reject_boot_id_zero",
    "reject_boot_id_above_max",
    "reject_runtime_seq_above_max",
    "reject_device_id_grammar",
    "reject_capability_hash_grammar",
}

VALID_INPUT = {
    "boot_id": 41,
    "capability_hash": (
        "sha256:13751b5335ccedcd4ffcc82bbda28ebfb7558859f36a74e710f1a0b0ab23da8d"
    ),
    "device_id": "ori-fw-7c9f2b3a",
    "runtime_seq": 2,
}


@pytest.fixture(scope="module")
def signer() -> FirmwareLivenessSigner:
    """The production signer, on the corpus's own test seed.

    Signing with ``Ed25519PrivateKey`` directly and reassembling the
    envelope by hand here would prove the corpus self-consistent and
    nothing about the runtime: a regression in ``sign_liveness_bytes`` — a
    changed separator, a different signature encoding, a reordered
    envelope — would leave every vector green.
    """

    class _NoStore:
        """``sign_liveness_bytes`` allocates no sequence, so the store is
        never touched on this path. Anything else is a defect, and this
        makes it one that fails loudly."""

        async def allocate_firmware_runtime_seq(self, device_id):
            raise AssertionError(
                "sign_liveness_bytes must not allocate a sequence number"
            )

    return FirmwareLivenessSigner(
        _NoStore(),
        bytes.fromhex(VECTORS["runtime_test_seed_hex"]),
        supervisor=FirmwareLivenessSupervisor(),
    )


def test_corpus_matches_the_spec_declared_digest() -> None:
    """Fails when the corpus moves without the contract moving with it."""
    actual = hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest()
    assert actual == SPEC_DECLARED_SHA256, (
        "liveness corpus does not match the digest ori-specs declares. A "
        "corpus change is a contract change: update the spec first, then "
        "this constant, the firmware constant, and the mirrored corpus."
    )


def test_corpus_targets_this_contract() -> None:
    assert VECTORS["contract"].startswith("ori-specs/firmware-commands/v1.md")
    assert VECTORS["version"] == 1
    # The transport rules travel with the corpus: a retained liveness
    # message is the broker asserting, for a runtime that may since have
    # died, that an authority is watching.
    assert VECTORS["retain"] is False
    assert VECTORS["qos"] == 1
    # The order matters as much as the checks: device identity is settled
    # before the signature, freshness last.
    assert VECTORS["acceptance_order"] == [
        "parses",
        "device_id",
        "signature",
        "boot_id",
        "capability_hash",
        "runtime_seq",
    ]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_production_signer_reproduces_the_whole_wire_message(case, signer) -> None:
    """Builder, signer and envelope end to end.

    Ed25519 is deterministic, so the runtime must reproduce the exact
    committed bytes rather than merely produce something that verifies.
    """
    i = case["input"]
    liveness = build_liveness_bytes(
        boot_id=i["boot_id"],
        capability_hash=i["capability_hash"],
        device_id=i["device_id"],
        runtime_seq=i["runtime_seq"],
    )
    assert liveness.hex() == case["liveness_hex"]
    assert signer.sign_liveness_bytes(liveness).hex() == case["message_hex"]


def test_the_signer_carries_the_corpus_key(signer) -> None:
    raw = signer.public_key_bytes()
    assert raw.hex() == VECTORS["runtime_public_key_hex"]
    assert base64.b64encode(raw).decode() == VECTORS["runtime_public_key_b64"]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_signatures_detect_tampering(case) -> None:
    liveness = bytes.fromhex(case["liveness_hex"])
    signature = base64.b64decode(case["signature_b64"], validate=True)
    public = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(VECTORS["runtime_public_key_hex"])
    )
    public.verify(signature, liveness)

    tampered = bytearray(liveness)
    tampered[-2] ^= 0x01
    with pytest.raises(Exception):
        public.verify(signature, bytes(tampered))


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_accept_cases_are_strictly_increasing_against_their_context(case) -> None:
    """The stateful half of the accept corpus.

    A case whose ``runtime_seq`` did not exceed the device's last accepted
    value would be a replay the corpus was asserting must be accepted.
    """
    ctx = case["verifier_context"]
    assert case["input"]["runtime_seq"] > ctx["last_accepted_runtime_seq"]
    assert case["input"]["boot_id"] == ctx["boot_id"]
    assert case["input"]["device_id"] == ctx["device_id"]
    assert case["input"]["capability_hash"] == ctx["capability_hash"]


def test_rogue_key_is_actually_a_different_key() -> None:
    """Otherwise the rogue-signer case tests nothing."""
    runtime = bytes.fromhex(VECTORS["runtime_public_key_hex"])
    rogue = bytes.fromhex(VECTORS["rogue_public_key_hex"])
    assert runtime != rogue

    case = next(c for c in REJECT_CASES if c["name"] == "reject_rogue_key")
    liveness, signature = _split(case["message_hex"])
    Ed25519PublicKey.from_public_bytes(rogue).verify(signature, liveness)
    with pytest.raises(Exception):
        Ed25519PublicKey.from_public_bytes(runtime).verify(signature, liveness)


def _split(message_hex: str) -> tuple[bytes, bytes]:
    raw = bytes.fromhex(message_hex)
    body = raw[len(b'{"liveness":') :]
    end = body.rindex(b',"signature":"ed25519:')
    signature = base64.b64decode(
        body[end:][len(b',"signature":"ed25519:') : -2], validate=True
    )
    return body[:end], signature


# --- What the runtime owes the reject corpus -----------------------------


def test_reject_cases_are_exactly_partitioned() -> None:
    """Every reject case is either executed here or declared unexecuted.

    A partition, not two independent lists: a case added upstream belongs
    to neither set and fails, so it has to be triaged rather than
    absorbed.
    """
    names = {c["name"] for c in REJECT_CASES}
    declared = RUNTIME_UNEXECUTED_REJECT_CASES | BUILDER_REFUSED_CASES

    assert declared - names == set(), (
        f"declared cases no longer in the corpus: {declared - names}"
    )
    assert names - declared == set(), (
        f"corpus gained reject cases nobody triaged: {names - declared}"
    )
    assert not (RUNTIME_UNEXECUTED_REJECT_CASES & BUILDER_REFUSED_CASES)


def test_the_builder_refuses_what_the_device_must_refuse() -> None:
    """The producer side of the reject corpus.

    A signer able to emit a message the verifier must refuse means the two
    sides disagree about the contract, and it would only be discovered on
    a device.
    """
    # Control: the base object IS accepted, so each refusal below is about
    # the field changed and not about a broken fixture.
    assert build_liveness_bytes(**VALID_INPUT)

    refusals = {
        "reject_runtime_seq_zero": ({"runtime_seq": 0}, "runtime_seq"),
        "reject_boot_id_zero": ({"boot_id": 0}, "boot_id"),
        "reject_boot_id_above_max": ({"boot_id": 2**32}, "boot_id"),
        "reject_runtime_seq_above_max": ({"runtime_seq": 2**53}, "runtime_seq"),
        "reject_device_id_grammar": (
            {"device_id": "ori fw/7c9f2b3a"},
            "device_id",
        ),
        "reject_capability_hash_grammar": (
            {"capability_hash": "sha256:" + "A" * 64},
            "capability_hash",
        ),
    }
    assert set(refusals) == BUILDER_REFUSED_CASES

    for name, (override, match) in refusals.items():
        with pytest.raises(FirmwareLivenessError, match=match):
            build_liveness_bytes(**{**VALID_INPUT, **override})


def test_the_builder_cannot_express_the_byte_level_rejects() -> None:
    """Why several reject cases have no runtime-side execution.

    The builder emits one fixed field order, one integer form, no extra
    members and always ``v:1``, so those messages are unreachable from
    this side rather than merely untested.
    """
    # The whole property in one place: exact field order, canonical
    # integers (no leading zeros, signs or decimal points), no extra
    # members, and v pinned to 1. Written independently of the builder
    # rather than as a set of proxies for it.
    grammar = re.compile(
        rb'^\{"boot_id":(?:0|[1-9][0-9]*),'
        rb'"capability_hash":"sha256:[0-9a-f]{64}",'
        rb'"device_id":"[A-Za-z0-9._-]{1,48}",'
        rb'"runtime_seq":(?:0|[1-9][0-9]*),'
        rb'"v":1\}$'
    )
    for case in CASES:
        i = case["input"]
        built = build_liveness_bytes(
            boot_id=i["boot_id"],
            capability_hash=i["capability_hash"],
            device_id=i["device_id"],
            runtime_seq=i["runtime_seq"],
        )
        assert grammar.match(built), f"{case['name']}: {built!r}"


def test_binding_and_freshness_rejects_carry_a_valid_signature() -> None:
    """Mirrors the firmware-side guarantee, from the other repo.

    A refusal decided after the signature check is only evidence the
    device made that check if the signature was good. Asserted here too so
    the property survives a change made in either repository alone.
    """
    after_signature = {
        "boot_mismatch",
        "capability_hash_mismatch",
        "seq_not_increasing",
    }
    public = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(VECTORS["runtime_public_key_hex"])
    )
    seen = set()
    for case in REJECT_CASES:
        if case["reason"] not in after_signature:
            continue
        seen.add(case["reason"])
        assert case["signature_valid"] is True, (
            f"{case['name']}: refused after the signature check, so an "
            f"invalid signature would let the device bail out earlier and "
            f"leave the check unproven"
        )
        liveness, signature = _split(case["message_hex"])
        public.verify(signature, liveness)

    assert seen == after_signature, f"missing reasons: {after_signature - seen}"


def test_replay_cases_declare_the_state_that_makes_them_replays() -> None:
    """``reject_replayed_runtime_seq`` is meaningless without saying what
    the device last accepted. A verifier that accepted replays forever
    would satisfy every byte-level vector in this corpus.
    """
    replayed = next(
        c for c in REJECT_CASES if c["name"] == "reject_replayed_runtime_seq"
    )
    regressing = next(
        c for c in REJECT_CASES if c["name"] == "reject_regressing_runtime_seq"
    )
    for case in (replayed, regressing):
        liveness, _ = _split(case["message_hex"])
        seq = int(liveness.split(b'"runtime_seq":')[1].split(b",")[0])
        last = case["verifier_context"]["last_accepted_runtime_seq"]
        assert seq <= last, f"{case['name']}: seq {seq} does exceed {last}"

    # Equal, not merely lower: a verifier using >= would pass a
    # lower-seq test and still accept the exact replayed message.
    liveness, _ = _split(replayed["message_hex"])
    seq = int(liveness.split(b'"runtime_seq":')[1].split(b",")[0])
    assert seq == replayed["verifier_context"]["last_accepted_runtime_seq"]


def test_transport_rejects_are_otherwise_acceptable_messages() -> None:
    """A retained message is refused on delivery, not on content. If its
    bytes were refusable the case would prove nothing about retention.
    """
    public = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(VECTORS["runtime_public_key_hex"])
    )
    cases = VECTORS["transport_reject_cases"]
    assert cases, "the retained-delivery obligation must be represented"
    for case in cases:
        assert case["transport"]["retain"] is True
        liveness, signature = _split(case["message_hex"])
        public.verify(signature, liveness)
        ctx = case["verifier_context"]
        seq = int(liveness.split(b'"runtime_seq":')[1].split(b",")[0])
        assert seq > ctx["last_accepted_runtime_seq"]
