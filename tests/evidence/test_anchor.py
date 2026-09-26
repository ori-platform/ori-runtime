# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The runtime must reproduce the anchor derivations the contract publishes.

These identifiers are sealed into immutable delivery envelopes and recomputed by
the evidence authority before it accepts a registration. Agreeing with the
contract's vectors is therefore not a nicety: a runtime that derives differently
mints evidence under an identity no authority will accept, and cannot correct it
afterwards.
"""

from __future__ import annotations

import base64
import json
import pathlib

import pytest

from ori.security.evidence.anchor import (
    POSTURE_SOFTWARE_WRAPPED,
    AnchorDerivationError,
    EvidenceCapabilityProfile,
    capability_hash,
    derive_anchor_epoch_id,
    derive_key_id,
    derive_runtime_anchor,
    public_key_b64,
)

VECTORS = json.loads(
    (
        pathlib.Path(__file__).resolve().parent.parent
        / "vectors"
        / "runtime_evidence_anchor"
        / "runtime-anchor-v2.json"
    ).read_text()
)
CASES = VECTORS["cases"]


def _profile(inputs: dict) -> EvidenceCapabilityProfile:
    return EvidenceCapabilityProfile.from_document(inputs["capability_profile"])


def _pubkey_hex(inputs: dict) -> str:
    return base64.b64decode(inputs["public_key_b64"]).hex()


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_derivations_match_the_contract_vectors(case) -> None:
    inputs = case["inputs"]
    profile = _profile(inputs)
    pubkey_hex = _pubkey_hex(inputs)

    assert capability_hash(profile) == case["capability_hash"]
    assert (
        derive_key_id(device_id=inputs["device_id"], pubkey_hex=pubkey_hex)
        == case["key_id"]
    )
    assert (
        derive_anchor_epoch_id(
            device_id=inputs["device_id"],
            pubkey_hex=pubkey_hex,
            posture=inputs["posture"],
            profile=profile,
        )
        == case["anchor_epoch_id"]
    )


def test_the_vector_set_still_moves_every_input() -> None:
    """Guards the parametrised test above against a corpus that stops discriminating.

    Every input must be exercised: a case that changed nothing would pass while
    proving the derivation ignores that field.
    """
    baseline = next(c for c in CASES if c["name"] == "baseline")
    key_moved = {c["name"] for c in CASES if c["key_id"] != baseline["key_id"]}
    epoch_moved = {
        c["name"] for c in CASES if c["anchor_epoch_id"] != baseline["anchor_epoch_id"]
    }
    # Key or device changes move both identifiers.
    assert {"rotated_key", "other_device"} <= key_moved
    assert {"rotated_key", "other_device"} <= epoch_moved
    # Posture and capability changes move only the epoch: the key is unchanged,
    # so a selector that moved would break rotation semantics.
    for name in (
        "posture_hardware",
        "freshness_verified",
        "protocol_v3",
        "fewer_purposes",
        "with_disposition_purpose",
        "with_fifo_handoff",
    ):
        assert name in epoch_moved, f"{name} does not move the epoch"
        assert name not in key_moved, f"{name} wrongly moves key_id"


#: What each refusal in the corpus must be refused for, as the error names it.
REFUSAL_WORDING = {
    "unsorted": "artifact_purposes must be sorted",
    "duplicated": "artifact_purposes must not repeat",
    "unknown": "artifact_purposes contains unknown",
    "empty_capabilities": "carriage_capabilities must be a non-empty list",
    "duplicated_capability": "carriage_capabilities must not repeat",
    "unknown_capability": "carriage_capabilities contains unknown",
}


@pytest.mark.parametrize(
    "case",
    VECTORS["refused_profiles"],
    ids=[c["name"] for c in VECTORS["refused_profiles"]],
)
def test_refused_profiles_are_refused_before_derivation_for_their_reason(case) -> None:
    """Each corpus refusal is refused, and for the defect it is named for."""
    with pytest.raises(AnchorDerivationError, match=REFUSAL_WORDING[case["refusal"]]):
        _profile(case["inputs"])


def test_the_corpus_names_every_refusal_this_test_knows() -> None:
    assert {c["refusal"] for c in VECTORS["refused_profiles"]} == set(REFUSAL_WORDING)


@pytest.mark.parametrize(
    "migration",
    VECTORS["migrations"],
    ids=[m["name"] for m in VECTORS["migrations"]],
)
def test_a_purpose_migration_changes_the_epoch_and_nothing_about_the_identity(
    migration,
) -> None:
    """The derivation half of the corpus migration.

    Its other properties are runtime state: a reference recorded against one
    epoch binds no other (`test_evidence_commission.py`), and a confirmation
    completes only the obligation of the epoch it names
    (`test_registration_obligation.py`).
    """
    before = next(c for c in CASES if c["name"] == migration["from"])
    after = next(c for c in CASES if c["name"] == migration["to"])
    expected = migration["expected"]
    assert (before["inputs"]["device_id"] == after["inputs"]["device_id"]) is expected[
        "device_id_unchanged"
    ]
    assert (before["key_id"] == after["key_id"]) is expected["key_id_unchanged"]
    assert (before["anchor_epoch_id"] != after["anchor_epoch_id"]) is expected[
        "epoch_changed"
    ]
    for case in (before, after):
        inputs = case["inputs"]
        assert (
            derive_anchor_epoch_id(
                device_id=inputs["device_id"],
                pubkey_hex=_pubkey_hex(inputs),
                posture=inputs["posture"],
                profile=_profile(inputs),
            )
            == case["anchor_epoch_id"]
        )


BASELINE_DOCUMENT = next(c for c in CASES if c["name"] == "baseline")["inputs"][
    "capability_profile"
]


@pytest.mark.parametrize(
    "mutation, why",
    [
        ({"firmware_freshness_verified": "false"}, "a string is not a boolean"),
        ({"firmware_freshness_verified": 0}, "an integer is not a boolean"),
        ({"artifact_purposes": "gateway_custody"}, "a string is not a list"),
        ({"artifact_purposes": ["gateway_custody", 7]}, "a non-string purpose"),
        ({"chain_protocol": 2}, "a non-string protocol"),
        ({"signing_alg": None}, "a null algorithm"),
        ({"carriage_capabilities": "checkpoint_fifo_handoff_v1"}, "not a list"),
        ({"carriage_capabilities": None}, "a null member"),
        ({"carriage_capabilities": [1]}, "a non-string capability"),
        ({"artifact_purposes": None}, "a null purpose list"),
        ({"v": 2}, "a profile version this release does not derive"),
        ({"v": "1"}, "a string version"),
        ({"v": True}, "a boolean that equals 1"),
        ({"v": 1.0}, "a float that equals 1"),
        (
            {"extra": "x"},
            "a member the derivation would ignore but the signature carry",
        ),
        ({"Artifact_purposes": []}, "a member differing only in case"),
    ],
)
def test_a_document_with_a_wrongly_typed_field_is_refused_not_coerced(
    mutation, why
) -> None:
    """`bool("false")` is True: a lenient read derives an epoch the document denies."""
    document = dict(BASELINE_DOCUMENT, **mutation)
    with pytest.raises(AnchorDerivationError):
        EvidenceCapabilityProfile.from_document(document)


@pytest.mark.parametrize("document", [None, [], "profile", 3])
def test_a_profile_that_is_not_an_object_is_refused(document) -> None:
    with pytest.raises(AnchorDerivationError):
        EvidenceCapabilityProfile.from_document(document)


def test_a_document_missing_a_field_is_refused() -> None:
    for field in BASELINE_DOCUMENT:
        document = {k: v for k, v in BASELINE_DOCUMENT.items() if k != field}
        with pytest.raises(AnchorDerivationError):
            EvidenceCapabilityProfile.from_document(document)


def test_the_baseline_document_round_trips() -> None:
    profile = EvidenceCapabilityProfile.from_document(BASELINE_DOCUMENT)
    assert profile.as_document() == BASELINE_DOCUMENT


def test_a_profile_declaring_no_carriage_capability_omits_the_member() -> None:
    """Absent, never an empty list: the contract refuses the empty array."""
    document = EvidenceCapabilityProfile(
        artifact_purposes=("gateway_custody",)
    ).as_document()
    assert "carriage_capabilities" not in document
    assert EvidenceCapabilityProfile.from_document(document).carriage_capabilities == ()


def test_this_release_declares_no_carriage_capability() -> None:
    """Declaring one is an epoch migration, taken with the disposition purpose."""
    anchor = derive_runtime_anchor(device_id="dev-01", pubkey_hex="ab" * 32)
    assert anchor.profile.carriage_capabilities == ()
    assert "evidence_authority_disposition" not in anchor.profile.artifact_purposes


class TestTheEncodingBridge:
    """Malformed keys are refused before derivation, never normalised.

    Normalising would let two distinct wire forms derive the same identifiers, so
    a device could present its key in a spelling the authority never recorded.
    """

    def test_a_well_formed_key_converts(self) -> None:
        raw = bytes(range(32))
        assert public_key_b64(raw.hex()) == base64.b64encode(raw).decode("ascii")

    @pytest.mark.parametrize(
        "bad, why",
        [
            ("ab" * 31, "too short"),
            ("ab" * 33, "too long"),
            ("AB" * 32, "uppercase"),
            ("zz" * 32, "non-hex"),
            ("", "empty"),
        ],
    )
    def test_malformed_keys_are_refused(self, bad, why) -> None:
        with pytest.raises(AnchorDerivationError):
            public_key_b64(bad)

    def test_padding_is_standard_base64_with_padding(self) -> None:
        encoded = public_key_b64("ab" * 32)
        assert encoded.endswith("=")
        assert "-" not in encoded and "_" not in encoded


class TestCapabilityProfileDiscipline:
    def test_purposes_must_be_sorted(self) -> None:
        with pytest.raises(AnchorDerivationError):
            capability_hash(
                EvidenceCapabilityProfile(
                    artifact_purposes=("gateway_custody", "evidence_authority_epoch")
                )
            )

    def test_purposes_must_not_repeat(self) -> None:
        """A duplicate would produce a distinct epoch without a distinct capability."""
        with pytest.raises(AnchorDerivationError):
            capability_hash(
                EvidenceCapabilityProfile(
                    artifact_purposes=("gateway_custody", "gateway_custody")
                )
            )

    def test_purposes_must_be_known(self) -> None:
        with pytest.raises(AnchorDerivationError):
            capability_hash(
                EvidenceCapabilityProfile(artifact_purposes=("not_a_purpose",))
            )


class TestRuntimePosture:
    def test_the_default_posture_is_software_wrapped(self) -> None:
        """A file-sealed key on a general-purpose OS is not sealed flash.

        Defaulting to anything stronger would overclaim non-exportability inside
        an artifact a third party may rely on.
        """
        anchor = derive_runtime_anchor(device_id="dev-01", pubkey_hex="ab" * 32)
        assert anchor.posture == POSTURE_SOFTWARE_WRAPPED

    def test_both_identifiers_derive_together(self) -> None:
        anchor = derive_runtime_anchor(device_id="dev-01", pubkey_hex="ab" * 32)
        assert anchor.key_id == derive_key_id(device_id="dev-01", pubkey_hex="ab" * 32)
        assert anchor.anchor_epoch_id == derive_anchor_epoch_id(
            device_id="dev-01",
            pubkey_hex="ab" * 32,
            posture=POSTURE_SOFTWARE_WRAPPED,
            profile=anchor.profile,
        )

    def test_a_missing_device_identity_is_refused(self) -> None:
        with pytest.raises(AnchorDerivationError):
            derive_key_id(device_id="", pubkey_hex="ab" * 32)
