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

from ori.security.evidence_anchor import (
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
        pathlib.Path(__file__).resolve().parent
        / "vectors"
        / "runtime_evidence_anchor"
        / "runtime-anchor.json"
    ).read_text()
)
CASES = VECTORS["cases"]


def _profile(inputs: dict) -> EvidenceCapabilityProfile:
    doc = inputs["capability_profile"]
    return EvidenceCapabilityProfile(
        artifact_purposes=tuple(doc["artifact_purposes"]),
        chain_protocol=doc["chain_protocol"],
        signing_alg=doc["signing_alg"],
        firmware_freshness_verified=doc["firmware_freshness_verified"],
    )


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
    ):
        assert name in epoch_moved, f"{name} does not move the epoch"
        assert name not in key_moved, f"{name} wrongly moves key_id"


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
