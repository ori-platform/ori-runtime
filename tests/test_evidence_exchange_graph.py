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

import ast
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


#: Vendored sets that together reconstruct the evidence graph. Transport
#: fixtures are deliberately absent: `gateway-api` versions independently of
#: the evidence contracts and its fixtures take no part in reconstructing a
#: chain, so requiring one pin across both would couple two contracts that have
#: no reason to move together.
GRAPH_VECTOR_SETS = frozenset(
    {
        "evidence_exchange",
        "evidence_exchange_receiver_state",
        "evidence_v2",
        "runtime_evidence_anchor",
    }
)


def test_all_graph_vector_sets_pin_the_same_specs_commit() -> None:
    """A split pin means the graph was assembled from two different contracts.

    The exchange vectors reference the anchor derivations, so a manifest that
    lagged would reconstruct against rules the other half no longer follows.
    """
    pins = {
        m.parent.name: json.loads(m.read_text())["source_commit"]
        for m in sorted(VECTORS.rglob("MANIFEST.json"))
        if m.parent.name in GRAPH_VECTOR_SETS
    }
    assert set(pins) == set(GRAPH_VECTOR_SETS), (
        f"a graph vector set is missing or renamed: {sorted(pins)}"
    )
    assert len(set(pins.values())) == 1, f"vendored sets pin different commits: {pins}"


def test_every_vendored_set_is_either_a_graph_set_or_declares_why_not() -> None:
    """A new vendored set must be classified, not silently exempted.

    Narrowing the pin check to the graph sets creates a way to escape it by
    accident: a set added under a new name is simply not compared. Anything
    outside the graph belongs to another contract and must say so in its own
    manifest.
    """
    for manifest_path in sorted(VECTORS.rglob("MANIFEST.json")):
        if manifest_path.parent.name in GRAPH_VECTOR_SETS:
            continue
        manifest = json.loads(manifest_path.read_text())
        source = str(manifest.get("source_path", ""))
        assert not source.startswith("evidence"), (
            f"{manifest_path.parent.name} vendors from {source!r}, which is part "
            "of the evidence graph; add it to GRAPH_VECTOR_SETS so its pin is "
            "compared rather than exempted"
        )


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


# --------------------------------------------------------------------------
# Behavioural accounting for every vendored vector
# --------------------------------------------------------------------------

#: Statuses an unexercised vector may carry. Ownership and proof are separate
#: facts, and collapsing them is how "someone else owns this" becomes "someone
#: else has done this". Only `proven_elsewhere` asserts that a proof exists.
EXEMPTION_STATUSES = {
    "proof_pending": "owned by a repository or milestone; not proven anywhere yet",
    "proven_elsewhere": "a conforming implementation exercises it in the owning repository",
}

EXEMPTION_FIELDS = frozenset({"owner", "status", "tracking", "reason"})

#: Roles an exemption may name. A closed set, because an accounting note is a
#: public file: naming the implementation behind a role would disclose through
#: the diagnostic channel exactly what the role exists to keep out of it.
EXEMPTION_OWNERS = frozenset(
    {
        "the runtime",
        "the evidence authority",
        "the site gateway",
    }
)

#: Vendored vector -> one or more behavioural tests demonstrating that this
#: runtime reads and exercises the vector's normative bytes.
#:
#: **Not an exhaustive conformance-test catalogue.** A vector is a corpus, and
#: several tests usually consume one: `canonical-form` has rejection cases
#: beyond the entry named here, and `custody-acknowledgement` has parameterised
#: cases beyond its two. Entries record that the bytes are consumed and where to
#: start reading, not that every published case is covered. Whether the corpus
#: is fully exercised is a review question this registry cannot answer.
#:
#: Named tests, never a search of the tree. Textual mention establishes nothing:
#: a comment, a dead helper, or a `json.load` with no assertions all read as
#: consumption, which is the false green this accounting exists to refuse.
VECTOR_CONSUMERS = {
    ("evidence_exchange", "anchor-registration"): (
        "test_evidence_registration.py"
        "::test_the_registration_reproduces_the_contract_vector_byte_for_byte",
        "test_evidence_registration.py"
        "::test_the_registration_carries_exactly_the_contract_field_set",
    ),
    ("evidence_exchange", "checkpoint"): (
        "test_evidence_delivery_ledger.py"
        "::test_the_checkpoint_reproduces_the_contract_vector_byte_for_byte",
    ),
    ("evidence_exchange", "commissioning-authorization"): (
        "test_evidence_registration.py::test_the_digest_covers_the_complete_authorisation",
        "test_evidence_registration.py"
        "::test_an_authorisation_that_does_not_describe_this_registration_is_refused",
    ),
    ("evidence_exchange", "custody-acknowledgement"): (
        "test_evidence_ingest.py::test_the_registry_the_vectors_describe_reproduces_from_the_secrets",
        "test_evidence_ingest.py"
        "::test_a_key_id_naming_another_generation_is_refused_without_trial_verification",
    ),
    ("evidence_exchange", "delivery-envelope"): (
        "test_evidence_delivery_ledger.py"
        "::test_the_envelope_reproduces_the_contract_vector_byte_for_byte",
    ),
    ("evidence_exchange", "delivery-receipt"): (
        "test_evidence_ingest.py::test_the_valid_receipt_verifies",
        "test_evidence_ingest.py::test_a_receipt_signed_with_the_epoch_key_is_refused",
        "test_evidence_ingest.py::test_a_non_contiguous_receipt_is_refused",
    ),
    ("evidence_exchange", "epoch-confirmation"): (
        "test_evidence_ingest.py::test_the_valid_epoch_confirmation_verifies",
        "test_evidence_ingest.py::test_a_confirmation_signed_with_the_receipt_key_is_refused",
    ),
    ("evidence_exchange_receiver_state", "custody-key-purpose"): (
        "test_evidence_ingest.py::test_a_key_id_held_for_another_purpose_is_refused_as_such",
        "test_evidence_ingest.py::test_the_same_artifact_is_unknown_key_when_no_purpose_holds_it",
    ),
    ("evidence_v2", "canonical-form"): (
        "test_evidence_chain_producer.py::test_canonical_form_matches_the_contract_vector",
    ),
    ("evidence_v2", "chain-row"): (
        "test_evidence_v2_vectors.py::test_rows_chain_hash_and_verify",
        "test_evidence_v2_vectors.py::test_each_rejection_case_violates_exactly_the_rule_it_names",
    ),
    ("evidence_v2", "event-id"): (
        "test_evidence_chain_producer.py::test_event_ids_match_the_contract_vector",
    ),
    ("evidence_v2", "genesis"): (
        "test_evidence_chain_producer.py::test_genesis_matches_the_contract_vector",
    ),
    ("evidence_v2", "key-rotation"): (
        "test_evidence_v2_vectors.py::test_rotation_proof_uses_the_neutral_context",
        "test_evidence_v2_vectors.py::test_rotation_is_dual_signed",
    ),
    ("gateway_api", "inbound-evidence"): (
        "test_evidence_inbound_route.py::test_the_runtime_verifies_the_published_inbound_fixture",
        "test_evidence_inbound_route.py"
        "::test_the_runtime_reproduces_the_published_acknowledgement_fixture",
    ),
    ("runtime_evidence_anchor", "runtime-anchor"): (
        "test_evidence_anchor.py::test_derivations_match_the_contract_vectors",
    ),
    ("sensor_configuration", "schema-load"): (
        "test_sensor_config_schema.py"
        "::test_schema_load_conforms_to_the_vendored_contract_vectors",
    ),
    ("sensor_configuration", "protocol-config"): (
        "test_sensor_config_schema.py"
        "::test_protocol_config_conforms_to_the_vendored_contract_vectors",
    ),
    ("sensor_configuration", "sensor-entry"): (
        "test_sensor_config_schema.py"
        "::test_sensor_entry_conforms_to_the_vendored_contract_vectors",
    ),
    ("sensor_configuration", "calibration"): (
        "test_sensor_config_schema.py"
        "::test_calibration_conforms_to_the_vendored_contract_vectors",
    ),
    ("sensor_configuration", "protocol-definition"): (
        "test_sensor_config_schema.py"
        "::test_protocol_definition_conforms_to_the_vendored_contract_vectors",
    ),
}

#: Vendored vectors this runtime cannot exercise yet.
#:
#: Vendoring proves nothing on its own. The set is drift-checked, which is worth
#: having, but a file nothing reads is a file whose invariant is unproven -- and
#: one that reads as covered because it sits beside files that are. Each entry
#: records who is responsible, whether a proof exists yet, and where that is
#: tracked, because naming a repository says who is answerable rather than that
#: the work is done.
VECTOR_EXEMPTIONS = {
    ("evidence_exchange_receiver_state", "anchor-quarantine"): {
        "owner": "the evidence authority",
        "status": "proof_pending",
        "tracking": "ori-runtime#372",
        "reason": (
            "Authority-side. Its receiver_state is `held_anchors`, the registry "
            "an evidence authority keeps of other devices' anchors, and the "
            "outcome is that authority refusing to rebind one. This runtime "
            "produces its own registration and never holds another device's "
            "anchor, so there is no code path here to drive."
        ),
    },
    ("evidence_exchange_receiver_state", "commissioning-resolution"): {
        "owner": "the evidence authority",
        "status": "proof_pending",
        "tracking": "ori-specs#130",
        "reason": (
            "Authority-side. Its receiver_state is the set of commissioning "
            "authorisations the evidence authority holds, delivered to it "
            "through the commissioning path the device never sees, and the "
            "outcome is that authority resolving a registration's "
            "commissioning_digest against them. This runtime holds no "
            "authorisation -- it holds only the digest as a reference -- so "
            "there is no resolution here to drive. Vendored so the drift check "
            "covers the bytes the authority must match."
        ),
    },
    ("commissioned_safety_binding", "binding-vectors-v1"): {
        "owner": "the runtime",
        "status": "proof_pending",
        "tracking": "ori-runtime#324",
        "reason": (
            "The runtime holds no commissioned binding and has no verifier for "
            "one: the safety registry that would read a binding, and the "
            "actuation seam that would resolve an outcome through it, are both "
            "still open. `tests/test_commissioned_binding_vectors.py` drives a "
            "reference verifier written from the contract over these cases, "
            "which establishes that the corpus is internally coherent and says "
            "nothing about runtime behaviour, because no runtime code reads a "
            "binding. Vendored now so the drift check covers the bytes a "
            "consumer will have to match."
        ),
    },
    ("gateway_api", "outbound-evidence"): {
        "owner": "the runtime",
        "status": "proof_pending",
        "tracking": "ori-runtime#326",
        "reason": (
            "Outbound carriage is this runtime's own half of gateway-api/v1, so "
            "no other repository can establish it. Nothing here publishes an "
            "artifact to the courier yet: the producer and delivery ledger that "
            "would hand one over are still open. Vendored now so the drift "
            "check covers the bytes the producer must match, and exempt until a "
            "publisher exists to assert against them."
        ),
    },
}


def _vendored_vectors() -> set[tuple[str, str]]:
    return {
        (path.parent.name, path.stem)
        for path in VECTORS.rglob("*.json")
        if path.stem != "MANIFEST"
    }


def _module_source(module: str) -> str:
    path = pathlib.Path(__file__).resolve().parent / module
    return path.read_text() if path.is_file() else ""


def test_every_vendored_vector_is_classified_exactly_once() -> None:
    """A vendored vector is either consumed here or accounted for precisely.

    This is the failure mode the vendoring work was filed against: files
    arriving in the tree, passing the drift check, and quietly implying a
    coverage that does not exist. Adding a vector forces a decision rather than
    allowing silent accumulation.
    """
    vendored = _vendored_vectors()
    assert vendored, "no vectors are vendored"

    consumed = set(VECTOR_CONSUMERS)
    exempt = set(VECTOR_EXEMPTIONS)

    assert not (consumed & exempt), (
        f"a vector is recorded as both consumed and exempt: {sorted(consumed & exempt)}"
    )
    assert vendored <= consumed | exempt, (
        "vendored vectors that nothing consumes and nothing explains: "
        f"{sorted(vendored - (consumed | exempt))}"
    )
    assert (consumed | exempt) <= vendored, (
        "the registry names vectors that are not vendored: "
        f"{sorted((consumed | exempt) - vendored)}"
    )


def test_every_named_consumer_resolves_to_a_test_that_reads_its_vector() -> None:
    """Each consumer entry must resolve, and its module must load that vector.

    Two checks, and neither is the whole claim. Resolving the function refuses a
    plausible name that no longer exists; requiring the module to load the
    vector refuses an entry pointed at a test that could never have read it,
    which is how the checkpoint entry was wrong on its first writing.

    What this cannot establish is that the named test asserts anything about
    what it read -- replacing its body with `pass` leaves the mapping resolvable
    and the load in place -- nor that the vector's other cases are covered. Both
    are review obligations, and the registry is the artefact a reviewer checks
    rather than a substitute for checking.
    """
    for vector, references in sorted(VECTOR_CONSUMERS.items()):
        assert references, f"{vector}: no consumer named"
        stem = vector[1]
        for reference in references:
            module, _, name = reference.partition("::")
            assert name, f"{vector}: consumer reference {reference!r} has no test name"
            source = _module_source(module)
            assert source, f"{vector}: consumer names a missing module {module}"
            defined = {
                node.name
                for node in ast.walk(ast.parse(source))
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            assert name in defined, f"{vector}: {module} defines no {name}"
            assert stem in source, (
                f"{vector}: {module} never loads {stem}, so {name} cannot read it"
            )


def test_every_exemption_records_owner_status_tracking_and_reason() -> None:
    """`proof_pending` must never read as conformance.

    The four fields are separate on purpose. An entry naming a role says who is
    answerable; only `proven_elsewhere` says a proof exists. An earlier revision
    conflated the two by asserting only that a repository was named.
    """
    for vector, entry in sorted(VECTOR_EXEMPTIONS.items()):
        assert set(entry) == EXEMPTION_FIELDS, (
            f"{vector}: exemption fields are {sorted(entry)}, "
            f"expected {sorted(EXEMPTION_FIELDS)}"
        )
        for field in EXEMPTION_FIELDS:
            assert str(entry[field]).strip(), f"{vector}: {field} is empty"
        assert entry["owner"] in EXEMPTION_OWNERS, (
            f"{vector}: owner {entry['owner']!r} is not one of the declared "
            f"roles {sorted(EXEMPTION_OWNERS)}; an accounting note must not "
            "name an implementation"
        )
        assert entry["status"] in EXEMPTION_STATUSES, (
            f"{vector}: unrecognised status {entry['status']!r}"
        )
        assert "#" in entry["tracking"], (
            f"{vector}: tracking must name an issue, got {entry['tracking']!r}"
        )


def test_no_pending_proof_claims_a_proof_exists_elsewhere() -> None:
    """Applies to every `proof_pending` entry, not to a list of today's two.

    A rule written against named entries stops covering the next one, which is
    the moment it is most needed: a new exemption is exactly when someone is
    deciding how much the accounting has to say.
    """
    pending = {
        vector: entry
        for vector, entry in VECTOR_EXEMPTIONS.items()
        if entry["status"] == "proof_pending"
    }
    assert pending, "no pending exemptions; drop this test rather than weaken it"
    for vector, entry in sorted(pending.items()):
        assert "proven" not in entry["reason"].lower(), (
            f"{vector}: the reason must explain why it cannot be exercised "
            "here, not assert a proof elsewhere"
        )
