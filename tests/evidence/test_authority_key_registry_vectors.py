# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The authority key registry held to `evidence-exchange/v2`'s normative corpus.

Every registry, public key and selection in the corpus is driven through the
loader the runtime reads its release registry with, and each refusal must be
for the rule the corpus names, not merely a refusal.
"""

from __future__ import annotations

import json
import logging
import pathlib
from importlib import resources
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ori.security.evidence import authority_keys
from ori.security.evidence.authority_keys import (
    PURPOSE_DISPOSITION,
    PURPOSE_EPOCH,
    PURPOSE_RECEIPT,
    REGISTRY_SCHEMA,
    RULE_MEMBERS,
    RULE_PUBLISHED_TEST_KEY,
    RULE_REFUSED_KEY,
    RULE_UNREADABLE,
    AuthorityKeyError,
    derive_key_id,
    load_authority_key_registry,
    load_release_authority_key_registry,
    refused_public_key_clause,
    select_verifying_key,
)
from ori.security.evidence.ingest import IngestRejectedError, _select
from ori.security.published_test_keys import PUBLISHED_TEST_KEYS

CORPUS_PATH = (
    pathlib.Path(__file__).parent.parent
    / "vectors"
    / "evidence_exchange"
    / "authority-key-registry-v2.json"
)
CORPUS: dict[str, Any] = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
REGISTRIES = {case["name"]: case for case in CORPUS["registries"]}


def _write(
    tmp_path: pathlib.Path, document: object, name: str = "keys.json"
) -> pathlib.Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _load(tmp_path: pathlib.Path, document: object) -> str:
    """The loader's verdict: `accepted`, or the rule that refused the document."""
    try:
        load_authority_key_registry(_write(tmp_path, document))
    except AuthorityKeyError as exc:
        return exc.rule
    return "accepted"


def _fresh_key() -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()


def _entry(public_key_hex: str, purpose: str, status: str = "active") -> dict[str, str]:
    return {
        "key_id": derive_key_id(bytes.fromhex(public_key_hex)),
        "public_key_hex": public_key_hex,
        "purpose": purpose,
        "status": status,
    }


@pytest.mark.parametrize("name", sorted(REGISTRIES))
def test_every_corpus_registry_is_decided_for_its_own_rule(tmp_path, name):
    case = REGISTRIES[name]
    expected = (
        "accepted" if case["expected"].get("accepted") else case["expected"]["refused"]
    )
    assert _load(tmp_path, case["document"]) == expected, case["why"]


def test_the_disposition_purpose_is_accepted(tmp_path):
    registry = load_authority_key_registry(
        _write(tmp_path, REGISTRIES["all_three_purposes"]["document"])
    )
    assert {purpose for purpose, _ in registry} == {
        PURPOSE_RECEIPT,
        PURPOSE_EPOCH,
        PURPOSE_DISPOSITION,
    }


def test_the_corpus_exercises_every_contract_rule_the_loader_names():
    """A rule the loader names and no case reaches is untested; one the corpus names and the loader lacks is unenforced."""
    corpus_rules = {
        case["expected"]["refused"]
        for case in CORPUS["registries"]
        if "refused" in case["expected"]
    }
    loader_rules = {
        value
        for name, value in vars(authority_keys).items()
        if name.startswith("RULE_")
    } - {RULE_UNREADABLE, RULE_PUBLISHED_TEST_KEY}
    assert corpus_rules == loader_rules


@pytest.mark.parametrize(
    "case",
    CORPUS["public_keys"],
    ids=[f"{c['public_key_hex'][:12]}-{c['clause']}" for c in CORPUS["public_keys"]],
)
def test_every_corpus_public_key_is_decided_for_its_own_clause(tmp_path, case):
    """Each key alone in a registry otherwise valid: refused whole for the key, or accepted."""
    public_key_hex = case["public_key_hex"]
    assert refused_public_key_clause(bytes.fromhex(public_key_hex)) == case["clause"]
    document = {
        "schema": REGISTRY_SCHEMA,
        "keys": [_entry(public_key_hex, PURPOSE_RECEIPT)],
    }
    expected = "accepted" if case["expected"] == "accepted" else RULE_REFUSED_KEY
    assert _load(tmp_path, document) == expected, case["why"]


def test_one_refused_key_refuses_the_whole_registry(tmp_path):
    refused = next(c for c in CORPUS["public_keys"] if c["clause"] == "small_order")
    document = {
        "schema": REGISTRY_SCHEMA,
        "keys": [
            _entry(_fresh_key(), PURPOSE_RECEIPT),
            _entry(refused["public_key_hex"], PURPOSE_EPOCH),
        ],
    }
    assert _load(tmp_path, document) == RULE_REFUSED_KEY


@pytest.mark.parametrize(
    "case", CORPUS["selections"], ids=[c["name"] for c in CORPUS["selections"]]
)
def test_every_corpus_selection_is_decided_by_purpose_and_key_id(tmp_path, case):
    registry = load_authority_key_registry(
        _write(tmp_path, REGISTRIES[case["registry"]]["document"])
    )
    expected = case["expected"]
    if "selected" in expected:
        assert (
            select_verifying_key(registry, case["purpose"], case["key_id"]).key_id
            == expected["selected"]
        )
        assert (
            _select(registry, case["purpose"], case["key_id"]).key_id
            == (expected["selected"])
        )
        return
    with pytest.raises(AuthorityKeyError) as refused:
        select_verifying_key(registry, case["purpose"], case["key_id"])
    assert refused.value.rule == expected["refused"], case["why"]
    # The ingest verifiers report the same reason on the artifact.
    with pytest.raises(IngestRejectedError) as rejected:
        _select(registry, case["purpose"], case["key_id"])
    assert rejected.value.reason == expected["refused"], case["why"]


@pytest.mark.parametrize(
    "raw,rule",
    [
        (b"", RULE_UNREADABLE),
        (b"\xff\xfe", RULE_UNREADABLE),
        (b"{" * 100_000, RULE_UNREADABLE),
        (b'{"schema": "x", "schema": "y", "keys": []}', RULE_MEMBERS),
        (b"null", RULE_MEMBERS),
    ],
    ids=["empty", "not_utf8", "deep_nesting", "repeated_member", "null"],
)
def test_an_unreadable_document_is_refused_rather_than_raising(tmp_path, raw, rule):
    path = tmp_path / "keys.json"
    path.write_bytes(raw)
    with pytest.raises(AuthorityKeyError) as refused:
        load_authority_key_registry(path)
    assert refused.value.rule == rule


def test_a_repeated_key_member_is_refused(tmp_path):
    """The last value of a repeated member would otherwise be the one trusted."""
    entry = _entry(_fresh_key(), PURPOSE_RECEIPT)
    text = json.dumps({"schema": REGISTRY_SCHEMA, "keys": [entry]}).replace(
        '"status": "active"', '"status": "revoked", "status": "active"'
    )
    path = tmp_path / "keys.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(AuthorityKeyError) as refused:
        load_authority_key_registry(path)
    assert refused.value.rule == RULE_MEMBERS


# --------------------------------------------------------------------------
# The release path: what the runtime actually reads
# --------------------------------------------------------------------------


def test_the_corpus_keys_are_refused_as_a_release_registry(tmp_path):
    """The corpus's keys derive from published seeds and must never be trusted."""
    for case in CORPUS["test_keys"]:
        assert bytes.fromhex(case["public_key_hex"]) in PUBLISHED_TEST_KEYS, case[
            "name"
        ]
    path = _write(tmp_path, REGISTRIES["receipt_and_epoch"]["document"])
    assert load_authority_key_registry(path)
    with pytest.raises(AuthorityKeyError) as refused:
        load_release_authority_key_registry(path)
    assert refused.value.rule == RULE_PUBLISHED_TEST_KEY


@pytest.fixture
def shipped(monkeypatch, tmp_path):
    """Stand in for the package resource `_load_authority_keys` reads."""
    original = resources.files

    def files(package: Any) -> Any:
        return tmp_path if package == "ori.security" else original(package)

    monkeypatch.setattr(resources, "files", files)
    return tmp_path / "evidence-authority-keys.json"


def test_a_shipped_conforming_registry_is_loaded(shipped):
    from ori.runtime import _load_authority_keys

    document = {
        "schema": REGISTRY_SCHEMA,
        "keys": [
            _entry(_fresh_key(), PURPOSE_RECEIPT),
            _entry(_fresh_key(), PURPOSE_EPOCH),
            _entry(_fresh_key(), PURPOSE_DISPOSITION),
        ],
    }
    shipped.write_text(json.dumps(document), encoding="utf-8")
    loaded = _load_authority_keys()
    assert not loaded.refused
    assert {purpose for purpose, _ in loaded.keys} == {
        PURPOSE_RECEIPT,
        PURPOSE_EPOCH,
        PURPOSE_DISPOSITION,
    }


@pytest.mark.parametrize(
    "name",
    sorted(n for n, c in REGISTRIES.items() if "refused" in c["expected"])
    + ["receipt_and_epoch"],
)
def test_a_shipped_refused_registry_stops_verification_not_the_runtime(
    shipped, caplog, name
):
    """Refused whole and reported, never read in part and never raised into startup."""
    from ori.runtime import _load_authority_keys

    shipped.write_text(json.dumps(REGISTRIES[name]["document"]), encoding="utf-8")
    with caplog.at_level(logging.ERROR, logger="ori.runtime"):
        loaded = _load_authority_keys()
    assert loaded.keys == {}
    assert loaded.refused
    assert any(
        "authority keys are refused" in record.getMessage() for record in caplog.records
    )


def test_an_absent_registry_still_fails_closed(shipped):
    from ori.runtime import _load_authority_keys

    assert not shipped.exists()
    loaded = _load_authority_keys()
    assert loaded.keys == {}
    assert not loaded.refused
