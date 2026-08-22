# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The vendored exchange vectors must reconstruct, in CI, not merely locally.

`ori-specs` is documentation-only, so its CI proves markdown links and file
hygiene. It cannot execute a reconstruction of the graph its vectors describe.
This is where that runs: the vectors are normative upstream, vendored here under
a digest manifest, and rebuilt from the contracts on every run.

The reconstruction imports nothing from the generator that produced the vectors.
Agreement therefore means two implementations agree, rather than one
implementation agreeing with itself -- which is the failure mode that let two
rejection vectors sit flattened into copies of their valid case while the corpus
kept passing.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from tests.evidence_graph_reconstruction import reconstruct

VECTORS = pathlib.Path(__file__).resolve().parent / "vectors"

#: Raising this is intentional friction. The count only moves when a rule is
#: added or removed, and a silent drop means the corpus stopped proving
#: something it used to.
MINIMUM_CHECKS = 62


def test_the_exchange_graph_reconstructs_from_the_contracts() -> None:
    checks, failures = reconstruct()
    assert not failures, "the vector graph does not reconstruct:\n  " + "\n  ".join(
        failures
    )
    assert checks >= MINIMUM_CHECKS, (
        f"only {checks} reconstruction checks ran, expected at least "
        f"{MINIMUM_CHECKS}. A drop means rules stopped being exercised."
    )


def test_no_placeholder_identifier_survives_in_any_vendored_vector() -> None:
    """Placeholders are how an unverifiable claim hides in a passing corpus.

    Every epoch and key_id in the exchange graph is derived. A literal like
    `epoch-0002` cannot be recomputed, so a vector carrying one asserts an
    identity no authority can check.
    """
    offenders = []
    for path in sorted(VECTORS.rglob("*.json")):
        text = path.read_text(encoding="utf-8")
        for placeholder in ("epoch-0002", "dev-key-2", "anchor-key-2"):
            if placeholder in text:
                offenders.append(f"{path.relative_to(VECTORS)}: {placeholder}")
    assert not offenders, "placeholder identifiers found:\n  " + "\n  ".join(offenders)


def test_every_vendored_vector_set_records_its_provenance() -> None:
    """A vendored copy without a pinned source commit has no provenance trail."""
    for manifest_path in sorted(VECTORS.rglob("MANIFEST.json")):
        manifest = json.loads(manifest_path.read_text())
        assert manifest.get("source_repository"), (
            f"{manifest_path}: no source repository"
        )
        assert manifest.get("source_commit"), f"{manifest_path}: no source commit"
        assert manifest.get("files"), f"{manifest_path}: lists no files"
        for name, want in manifest["files"].items():
            body = (manifest_path.parent / name).read_bytes()
            got = hashlib.sha256(body).hexdigest()
            assert got == want, (
                f"{manifest_path.parent.name}/{name} has been edited locally; "
                f"re-vendor from {manifest['source_repository']}@"
                f"{manifest['source_commit']} instead"
            )


def test_all_vendored_sets_pin_the_same_specs_commit() -> None:
    """A split pin means the graph was assembled from two different contracts.

    The exchange vectors reference the anchor derivations, so a manifest that
    lagged would reconstruct against rules the other half no longer follows.
    """
    pins = {
        m.parent.name: json.loads(m.read_text())["source_commit"]
        for m in sorted(VECTORS.rglob("MANIFEST.json"))
    }
    assert len(set(pins.values())) == 1, f"vendored sets pin different commits: {pins}"


#: Fields each vector family must publish. Written out rather than derived from
#: the files, so a regeneration that drops one fails here instead of in whichever
#: consumer happened to read it.
#:
#: This exists because a regeneration rebuilt each family's schema from what its
#: author had noticed while reading it, and three keys vanished -- including the
#: note warning against exactly that class of mistake. Semantic reconstruction
#: stayed green throughout, because nothing asked whether the schema survived.
REQUIRED_SCHEMA: dict[str, dict[str, set[str]]] = {
    "anchor-registration": {
        "top": {
            "artifact",
            "domain_ascii",
            "key_purpose",
            "signing_key_seed_hex",
            "signing_key_public_hex",
            "cases",
        },
        "case": {
            "name",
            "authenticator",
            "expected",
            "note",
            "canonical_hex",
            "artifact",
        },
    },
    "commissioning-authorization": {
        "top": {
            "artifact",
            "domain_ascii",
            "key_purpose",
            "signing_key_seed_hex",
            "signing_key_public_hex",
            "cases",
        },
        "case": {
            "name",
            "authenticator",
            "expected",
            "note",
            "canonical_hex",
            "artifact",
        },
    },
    "epoch-confirmation": {
        "top": {
            "artifact",
            "domain_ascii",
            "key_purpose",
            "signing_key_seed_hex",
            "signing_key_public_hex",
            "cases",
        },
        "case": {
            "name",
            "authenticator",
            "expected",
            "note",
            "canonical_hex",
            "artifact",
        },
    },
    "checkpoint": {
        "top": {
            "artifact",
            "domain_ascii",
            "key_purpose",
            "signing_key_seed_hex",
            "signing_key_public_hex",
            "cases",
        },
        "case": {
            "name",
            "authenticator",
            "expected",
            "note",
            "canonical_hex",
            "artifact",
        },
    },
    "delivery-envelope": {
        "top": {
            "artifact",
            "domain_ascii",
            "key_purpose",
            "signing_key_seed_hex",
            "signing_key_public_hex",
            "chain_row_note",
            "wire_note",
            "cases",
        },
        # wire_hex is required here and nowhere else: a custody acknowledgement
        # digests an envelope's complete bytes, so a consumer without them cannot
        # check the digest.
        "case": {
            "name",
            "authenticator",
            "expected",
            "note",
            "canonical_hex",
            "wire_hex",
            "artifact",
        },
    },
    "delivery-receipt": {
        "top": {
            "artifact",
            "domain_ascii",
            "key_purpose",
            "signing_key_seed_hex",
            "signing_key_public_hex",
            "authority_receipt_seed_hex",
            "epoch_authority_seed_hex",
            "rejection_integrity_note",
            "cases",
        },
        "case": {
            "name",
            "authenticator",
            "expected",
            "note",
            "canonical_hex",
            "artifact",
        },
    },
    "custody-acknowledgement": {
        # Both secrets are published because they are different secrets. Shipping
        # one invites authenticating custody with the envelope secret and
        # concluding the two agree.
        "top": {
            "artifact",
            "domain_ascii",
            "shared_secret_hex",
            "gateway_secret_hex",
            "envelope_digest_note",
            "cases",
        },
        "case": {
            "name",
            "authenticator",
            "expected",
            "note",
            "canonical_hex",
            "artifact",
        },
    },
}


@pytest.mark.parametrize("family", sorted(REQUIRED_SCHEMA))
def test_each_vector_family_publishes_its_required_schema(family) -> None:
    doc = json.loads((VECTORS / "evidence_exchange" / f"{family}.json").read_text())
    required = REQUIRED_SCHEMA[family]

    missing_top = required["top"] - set(doc)
    assert not missing_top, (
        f"{family}.json is missing top-level fields: {sorted(missing_top)}"
    )

    for case in doc["cases"]:
        missing = required["case"] - set(case)
        assert not missing, (
            f"{family}.json case {case['name']!r} is missing: {sorted(missing)}"
        )


@pytest.mark.parametrize("family", sorted(REQUIRED_SCHEMA))
def test_every_case_in_a_family_carries_the_same_shape(family) -> None:
    """One family must not end up with two schemas.

    A hand-built case that bypasses the shared helper is how `checkpoint` ended
    up publishing `wire_hex` on four of five cases: the field looked present, and
    the one case missing it was the one testing an invalid authenticator.
    """
    doc = json.loads((VECTORS / "evidence_exchange" / f"{family}.json").read_text())
    shapes = {c["name"]: frozenset(c) for c in doc["cases"]}
    distinct = set(shapes.values())
    assert len(distinct) == 1, f"{family}.json cases do not share one shape: " + str(
        {n: sorted(s) for n, s in shapes.items()}
    )


def test_the_rejection_integrity_note_survives() -> None:
    """The note is load-bearing history, not decoration.

    It records that `authenticator: valid` marks a case which must verify so the
    semantic rule is reached -- not a case that is correct. A regeneration that
    re-signs every such case erases the defects those cases exist to carry, which
    has happened once already.
    """
    doc = json.loads(
        (VECTORS / "evidence_exchange" / "delivery-receipt.json").read_text()
    )
    note = doc.get("rejection_integrity_note", "")
    assert "re-signs every case" in note, (
        "the rejection integrity note has been removed or reworded past recognition"
    )
