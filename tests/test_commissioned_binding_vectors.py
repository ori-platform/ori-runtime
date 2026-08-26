# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""The runtime's mirror of the commissioned-safety-binding golden corpus.

The runtime is a **consumer** of this contract and has no verifier of its own
yet — that arrives with the safety registry in #324 and the actuation seam in
#397. So this file makes a deliberately narrow claim, and the narrowness is the
point: it checks that the published corpus is internally coherent under a
verifier written from the contract text, and it does **not** show that any
runtime code behaves correctly, because none of it reads a binding.

Provenance and drift live where the other vendored sets keep them: the
`MANIFEST.json` beside the corpus pins the ori-specs commit it came from and
the digest of every file, and `scripts/refresh-evidence-vectors.sh` compares
both against ori-specs in CI. A digest constant copied into this module would
be a third copy of the same number and would detect nothing an upstream change
could do.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

import pytest

from tests.golden.verify_commissioned_binding_vectors import (
    PROFILE_ORDER,
    RefusedError,
    cbytes,
    run,
    run_envelope,
    run_profile,
    run_profile_envelope,
)

VECTOR_DIR = Path(__file__).parent / "vectors" / "commissioned_safety_binding"
VECTOR_PATH = VECTOR_DIR / "binding-vectors-v1.json"

VECTORS = json.loads(VECTOR_PATH.read_text())
CASES = VECTORS["cases"]
REJECT_CASES = VECTORS["reject_cases"]
PROFILE_CASES = VECTORS["firmware_profile_cases"]
PROFILE_REJECT_CASES = VECTORS["firmware_profile_reject_cases"]
ENVELOPE_REJECT_CASES = VECTORS["envelope_reject_cases"]


def test_corpus_is_the_published_artifact_at_the_pinned_revision() -> None:
    """The corpus is the one the manifest pins, not a locally edited copy.

    This is a local-edit check only. Upstream drift is the refresh script's
    job, because only it can see ori-specs.
    """
    manifest = json.loads((VECTOR_DIR / "MANIFEST.json").read_text())
    assert manifest["source_repository"] == "ori-platform/ori-specs"
    assert manifest["source_commit"]
    recorded = manifest["files"][VECTOR_PATH.name]
    assert hashlib.sha256(VECTOR_PATH.read_bytes()).hexdigest() == recorded, (
        "the vendored corpus has been edited locally; re-vendor with "
        "scripts/refresh-evidence-vectors.sh rather than editing it here"
    )


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_recorded_bytes_reproduce(case: dict) -> None:
    """A producer's bytes must be checkable without running a verifier."""
    binding = case["binding"]
    assert cbytes(binding).hex() == case["canonical_hex"]
    assert (
        "sha256:" + hashlib.sha256(cbytes(binding)).hexdigest()
        == case["canonical_sha256"]
    )
    envelope = {"binding": binding, "signature": "ed25519:" + case["signature_b64"]}
    assert cbytes(envelope).hex() == case["message_hex"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_accept_cases_pass_every_stage(case: dict) -> None:
    run(case["binding"], case["verifier_context"], case["signature_b64"])


@pytest.mark.parametrize("case", REJECT_CASES, ids=lambda c: c["name"])
def test_reject_cases_refuse_at_their_declared_stage(case: dict) -> None:
    """Right reason at the wrong stage is not evidence the check exists.

    A refusal only demonstrates the named check ran if every earlier stage
    passed, so the stage is asserted alongside the verdict.
    """
    with pytest.raises(RefusedError) as excinfo:
        run(case["binding"], case["verifier_context"], case["signature_b64"])
    assert excinfo.value.reason == case["reason"]
    assert excinfo.value.stage == case["stage"]


@pytest.mark.parametrize("case", REJECT_CASES, ids=lambda c: c["name"])
def test_reject_cases_declare_signature_validity(case: dict) -> None:
    """`signature_valid` must agree with where the refusal happened."""
    order = VECTORS["acceptance_order"]
    assert "signature_valid" in case
    decided_after_signature = order.index(case["stage"]) > order.index("signature")
    if case["signature_valid"]:
        assert case["stage"] != "signature"
    else:
        assert not decided_after_signature


@pytest.mark.parametrize("case", PROFILE_CASES, ids=lambda c: c["name"])
def test_firmware_profile_accept_cases(case: dict) -> None:
    profile = case["firmware_profile"]
    assert cbytes(profile).hex() == case["canonical_hex"]
    run_profile(profile, case["verifier_context"], case["signature_b64"])


@pytest.mark.parametrize("case", PROFILE_REJECT_CASES, ids=lambda c: c["name"])
def test_firmware_profile_reject_cases(case: dict) -> None:
    """A profile is verified by its own ordered stages, so it names them."""
    with pytest.raises(RefusedError) as excinfo:
        run_profile(
            case["firmware_profile"], case["verifier_context"], case["signature_b64"]
        )
    assert excinfo.value.reason == case["reason"]
    assert excinfo.value.stage == case["stage"]
    assert "signature_valid" in case
    if case["signature_valid"]:
        assert excinfo.value.stage != "signature"
    else:
        assert PROFILE_ORDER.index(excinfo.value.stage) <= PROFILE_ORDER.index(
            "signature"
        )


@pytest.mark.parametrize("case", ENVELOPE_REJECT_CASES, ids=lambda c: c["name"])
def test_envelope_reject_cases(case: dict) -> None:
    """The wrapper is grammar, so every one of these is `malformed` at `parses`.

    A field beside the signature sits outside the signed bytes and is therefore
    unauthenticated by construction; ignoring it would let an intermediary
    attach content a careless consumer might read.
    """
    runner = run_envelope if "binding" in case["envelope"] else run_profile_envelope
    with pytest.raises(RefusedError) as excinfo:
        runner(case["envelope"], case["verifier_context"])
    assert excinfo.value.reason == case["reason"]
    assert excinfo.value.stage == case["stage"]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_accept_cases_pass_as_whole_envelopes(case: dict) -> None:
    """The recorded envelope bytes verify, wrapper included."""
    envelope = {
        "binding": case["binding"],
        "signature": "ed25519:" + case["signature_b64"],
    }
    assert cbytes(envelope).hex() == case["message_hex"]
    run_envelope(envelope, case["verifier_context"])


def test_every_declared_stage_is_exercised() -> None:
    """A stage no vector reaches is a rule nothing holds the corpus to."""
    for order_key, cases, runner, payload in (
        ("acceptance_order", REJECT_CASES, run, "binding"),
        (
            "firmware_profile_acceptance_order",
            PROFILE_REJECT_CASES,
            run_profile,
            "firmware_profile",
        ),
    ):
        reached = set()
        for case in cases:
            with pytest.raises(RefusedError) as excinfo:
                runner(case[payload], case["verifier_context"], case["signature_b64"])
            reached.add(excinfo.value.stage)
        assert reached == set(VECTORS[order_key]), (
            f"{order_key}: no vector stops at "
            f"{sorted(set(VECTORS[order_key]) - reached)}"
        )


# --------------------------------------------------------------------------
# Grammar mutations
# --------------------------------------------------------------------------
#
# The corpus carries a vector per grammar class. These mutations cover the
# neighbouring shapes it does not enumerate, and they exist because the first
# reference verifier passed every published case while accepting an unknown
# sensor key, an unknown proof key and a `gpio_level` on a channel with no pin
# — and *raised* on a `signing_key` that was not base64, which is not a refusal
# at all. A corpus cannot catch that on its own: it only asserts what it lists.

BASE = CASES[0]


def _mutated(mutate: Callable[[dict], Any]) -> dict:
    case = copy.deepcopy(BASE)
    mutate(case["binding"])
    return case


GRAMMAR_MUTATIONS: dict[str, Callable[[dict], Any]] = {
    "unknown_capacity_key": lambda b: b["zones"][0]["rated_capacity"].update(
        {"derived_from": "nameplate photo"}
    ),
    "unknown_identity_key": lambda b: b["zones"][0]["actuator"]["identity"].update(
        {"board": "sainsmart-8ch"}
    ),
    "unknown_zone_key": lambda b: b["zones"][0].update({"notes": "see folder"}),
    "provenance_outside_the_vocabulary": lambda b: b["zones"][0][
        "rated_capacity"
    ].update({"provenance": "assumed"}),
    "gpio_level_outside_the_vocabulary": lambda b: b["zones"][0]["proof"][
        "observations"
    ][0].update({"gpio_level": "floating"}),
    "active_high_as_a_string": lambda b: b["zones"][0]["actuator"]["identity"].update(
        {"active_high": "false"}
    ),
    "load_present_as_a_string": lambda b: b["zones"][0]["proof"]["observations"][
        0
    ].update({"load_present_after": "no"}),
    "noise_floor_of_zero": lambda b: b["zones"][0]["sensor"].update(
        {"noise_floor": 0.0}
    ),
    "inverted_sensor_range": lambda b: b["zones"][0]["sensor"].update(
        {"range_min": 100.0, "range_max": 0.0}
    ),
    "binding_seq_below_one": lambda b: b.update({"binding_seq": 0}),
    "undemonstrated_carrying_observations": lambda b: b["zones"][0]["proof"].update(
        {"method": "undemonstrated"}
    ),
    "empty_observation_list": lambda b: b["zones"][0]["proof"].update(
        {"observations": []}
    ),
    "signing_key_without_its_prefix": lambda b: b.update(
        {"signing_key": b["signing_key"].removeprefix("ed25519:")}
    ),
    "signing_key_with_non_strict_base64": lambda b: b.update(
        {"signing_key": "ed25519:" + b["signing_key"].removeprefix("ed25519:") + "\n"}
    ),
    "zones_absent": lambda b: b.update({"zones": []}),
    # The field-type table, driven. A key set is not a grammar: two
    # implementations can agree on which keys exist and disagree on what may
    # sit behind them.
    "gpio_pin_as_a_boolean": lambda b: b["zones"][0]["actuator"]["identity"].update(
        {"gpio_pin": True}
    ),
    "capacity_value_as_a_boolean": lambda b: b["zones"][0]["rated_capacity"].update(
        {"value": True}
    ),
    "load_presence_as_an_integer": lambda b: b["zones"][0]["proof"]["observations"][
        0
    ].update({"load_present_after": 0}),
    "performed_at_ms_as_a_float": lambda b: b["zones"][0]["proof"].update(
        {"performed_at_ms": 1800000000000.0}
    ),
    "issued_at_ms_as_a_string": lambda b: b.update({"issued_at_ms": "1800000000000"}),
    "zone_id_empty": lambda b: b["zones"][0].update({"zone_id": ""}),
    "actor_whitespace_only": lambda b: b.update({"actor": "\t "}),
    "instrument_empty": lambda b: b["zones"][0]["proof"]["observations"][0].update(
        {"instrument": ""}
    ),
    "calibration_ref_empty": lambda b: b["zones"][0]["sensor"].update(
        {"calibration_ref": ""}
    ),
}

B64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _same_bytes_other_spellings(b64: str) -> list[str]:
    """Every alternative spelling of `b64` that decodes to identical bytes.

    Derived from the corpus key rather than written down, so it cannot go stale
    when the test keys change. Base64 leaves the low bits of the final
    character unused whenever the input is not a multiple of three, and a
    validating decoder ignores them.
    """
    raw = base64.b64decode(b64, validate=True)
    variants = []
    for index, char in enumerate(b64):
        if char == "=":
            continue
        for candidate in B64_ALPHABET:
            if candidate == char:
                continue
            variant = b64[:index] + candidate + b64[index + 1 :]
            try:
                if base64.b64decode(variant, validate=True) == raw:
                    variants.append(variant)
            except Exception:  # noqa: BLE001 - candidate simply does not decode
                continue
    return variants


def test_strict_decoding_alone_would_admit_several_spellings() -> None:
    """The premise of the canonical rule, asserted rather than assumed.

    If this ever finds no alternatives, the rule below is testing nothing and
    the reason for it has changed.
    """
    key = BASE["binding"]["signing_key"].removeprefix("ed25519:")
    assert _same_bytes_other_spellings(key), (
        "no alternative spelling decodes to the same key; the canonical "
        "encoding rule no longer has the problem it was written for"
    )


def test_non_canonical_key_spellings_are_malformed() -> None:
    """Same key, different bytes on the wire. Only round-trip equality sees it."""
    key = BASE["binding"]["signing_key"].removeprefix("ed25519:")
    for variant in _same_bytes_other_spellings(key):
        case = _mutated(lambda b, v=variant: b.update({"signing_key": "ed25519:" + v}))
        with pytest.raises(RefusedError) as excinfo:
            run(case["binding"], case["verifier_context"], case["signature_b64"])
        assert excinfo.value.reason == "malformed", variant
        assert excinfo.value.stage == "parses", variant


def test_non_canonical_signature_spellings_are_malformed() -> None:
    """The rule that applies to a key applies to a signature, for one reason."""
    signature = BASE["signature_b64"]
    variants = _same_bytes_other_spellings(signature)
    assert variants, "no alternative spelling of the signature to test"
    for variant in variants:
        envelope = {"binding": BASE["binding"], "signature": "ed25519:" + variant}
        with pytest.raises(RefusedError) as excinfo:
            run_envelope(envelope, BASE["verifier_context"])
        assert excinfo.value.reason == "malformed", variant
        assert excinfo.value.stage == "parses", variant


def _hostile_shapes() -> list[Callable[[dict], Any]]:
    """Values chosen to break decoders and lookups rather than checks.

    Wrong JSON types where objects are expected; arrays and objects where a
    closed vocabulary is expected, which are unhashable and raise TypeError on
    a membership test written before a type test; and unpaired surrogates,
    which `json.loads` produces from a `\\ud800` escape and which survive
    every type check to raise UnicodeEncodeError at canonicalisation.
    """
    return [
        lambda b: b.update({"zones": "not a list"}),
        lambda b: b["zones"].__setitem__(0, "not an object"),
        lambda b: b["zones"][0].update({"sensor": None}),
        lambda b: b["zones"][0].update({"actuator": []}),
        lambda b: b["zones"][0].update({"proof": 7}),
        lambda b: b["zones"][0].update({"rated_capacity": "10A"}),
        lambda b: b["zones"][0]["actuator"].update({"identity": "gpio26"}),
        lambda b: b["zones"][0]["actuator"].update({"commissioned_mapping": []}),
        lambda b: b["zones"][0]["proof"].update({"observations": "not a list"}),
        lambda b: b["zones"][0]["proof"].update({"observations": [None]}),
        # Unhashable values against every closed vocabulary.
        lambda b: b["zones"][0]["actuator"].update({"kind": []}),
        lambda b: b["zones"][0]["proof"].update({"method": {}}),
        lambda b: b["zones"][0]["rated_capacity"].update({"provenance": []}),
        lambda b: b["zones"][0]["actuator"]["commissioned_mapping"].update(
            {"open_protected_circuit": {}}
        ),
        lambda b: b["zones"][0]["actuator"]["commissioned_mapping"].update(
            {"de_energised_terminal_state": []}
        ),
        lambda b: b["zones"][0]["proof"]["observations"][0].update({"commanded": {}}),
        lambda b: b["zones"][0]["proof"]["observations"][0].update({"coil_state": []}),
        lambda b: b["zones"][0]["proof"]["observations"][0].update(
            {"terminal_state_observed": {}}
        ),
        lambda b: b["zones"][0]["proof"]["observations"][0].update({"gpio_level": []}),
        # Unpaired surrogates, in a value, in a nested value, and in a key.
        lambda b: b.update({"reason": "\ud800"}),
        lambda b: b["zones"][0].update({"zone_id": "a\udfffb"}),
        lambda b: b["zones"][0]["sensor"].update({"calibration_ref": "\udc00"}),
        lambda b: b["zones"][0]["sensor"].update({"\ud800": "surrogate key"}),
        # Encodings.
        lambda b: b.update({"signing_key": "ed25519:!!!!not base64!!!!"}),
        lambda b: b.update({"signing_key": 42}),
        lambda b: b.update({"signing_key": []}),
        lambda b: b.update({"supersedes": 7}),
        lambda b: b.update({"binding_seq": "one"}),
        lambda b: b.update({"v": "1"}),
    ]


def test_the_verifier_never_raises_anything_but_a_refusal() -> None:
    """A verifier that throws on malformed input has not refused it.

    The caller cannot distinguish a crash from a rejection, so the contract
    requires a verdict. Every shape here reached an exception at some point in
    development rather than a verdict.
    """
    for index, mutate in enumerate(_hostile_shapes()):
        case = _mutated(mutate)
        try:
            run(case["binding"], case["verifier_context"], case["signature_b64"])
        except RefusedError as refusal:
            assert refusal.reason == "malformed", f"hostile[{index}]: {refusal.reason}"
            assert refusal.stage == "parses", f"hostile[{index}]: {refusal.stage}"
        except Exception as exc:  # noqa: BLE001 - that is the failure under test
            pytest.fail(
                f"hostile[{index}] raised {type(exc).__name__} instead of "
                f"returning a verdict: {exc}"
            )
        else:
            pytest.fail(f"hostile[{index}] was accepted")


def test_neither_envelope_form_raises_on_hostile_input() -> None:
    """Both wire wrappers, not only the one the corpus happens to exercise."""
    envelopes: list[tuple[str, dict, dict]] = [
        (
            "binding",
            {
                "binding": BASE["binding"],
                "signature": "ed25519:" + BASE["signature_b64"],
            },
            BASE["verifier_context"],
        ),
        (
            "firmware_profile",
            {
                "firmware_profile": PROFILE_CASES[0]["firmware_profile"],
                "signature": "ed25519:" + PROFILE_CASES[0]["signature_b64"],
            },
            PROFILE_CASES[0]["verifier_context"],
        ),
    ]
    corruptions: list[Callable[[dict, str], Any]] = [
        lambda e, k: e.update({"signature": []}),
        lambda e, k: e.update({"signature": {}}),
        lambda e, k: e.update({"signature": 64}),
        lambda e, k: e.update({"signature": "ed25519:\ud800"}),
        lambda e, k: e.update({k: "not an object"}),
        lambda e, k: e.update({k: []}),
        lambda e, k: e.update({k: None}),
        lambda e, k: e.update({"extra": "unauthenticated"}),
        lambda e, k: e.pop("signature"),
        lambda e, k: e.pop(k),
    ]
    for form, envelope, ctx in envelopes:
        runner = run_envelope if form == "binding" else run_profile_envelope
        for index, corrupt in enumerate(corruptions):
            broken = copy.deepcopy(envelope)
            corrupt(broken, form)
            try:
                runner(broken, ctx)
            except RefusedError as refusal:
                assert refusal.reason == "malformed", f"{form}[{index}]"
                assert refusal.stage == "parses", f"{form}[{index}]"
            except Exception as exc:  # noqa: BLE001 - the property under test
                pytest.fail(
                    f"{form}[{index}] raised {type(exc).__name__} instead of "
                    f"returning a verdict: {exc}"
                )
            else:
                pytest.fail(f"{form}[{index}] was accepted")
