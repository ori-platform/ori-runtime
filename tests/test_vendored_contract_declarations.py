# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Every vendored ori-specs corpus declares the contract version its manifest claims.

A manifest's `contract_version` is the version this runtime says it conforms to.
A corpus whose own `contract` or `vector_set` names another version cannot be
checked against that claim, so the two are held together here.

Versions follow the selection rule in `scripts/refresh-evidence-vectors.sh`: per
stem, the newest `<stem>-v<N>.json` at or below the claim, else the untokened
`<stem>.json`, so one file per stem is vendored. A tokened file stands at N. An
untokened file stands at its directory's original version -- whatever version
opened that vectors directory -- and for every later one until a tokened
sibling replaces it, so it declares that original version: at or below the
claim, and the same for every untokened file in the set. The claim must be the
highest version the set shows, by token or by declaration. A manifest with no
`contract_version` claims v1.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

import pytest

VECTORS = Path(__file__).resolve().parent / "vectors"
SPECS_REPOSITORY = "ori-platform/ori-specs"
ORIGINAL_VERSION = 1

#: Members that declare the corpus's own contract.
OWN_MEMBERS = ("contract", "vector_set")
#: Members whose contract citations are held to what this runtime vendors.
CITING_MEMBERS = ("contract", "vector_set", "canonicalisation", "canonical_form")

_TOKEN = re.compile(r"^(?P<stem>.+)-v(?P<version>[1-9][0-9]*)\.json$")
_OWN = re.compile(
    r"^(?:ori-specs[/ ])?(?P<name>[a-z][a-z0-9-]*)/v(?P<version>[1-9][0-9]*)"
    r"(?:\.md)?(?:\s|$)"
)
_CITED = re.compile(r"(?P<name>[a-z][a-z0-9-]*)/v(?P<version>[1-9][0-9]*)\b")
_CLAIM = re.compile(r"^v(?P<version>[1-9][0-9]*)$")

#: Vector directories that are not ori-specs corpora, and why.
NOT_SPECS_CORPORA = {
    "telemetry_refusals": (
        "Vendored from the product API, not ori-specs. Its `contract` and "
        "`contract_version` name that repository's fixture, which has no "
        "ori-specs version to match."
    ),
    "telemetry_delivery": (
        "Authored in this repository and carries no MANIFEST.json, so there is "
        "no vendored claim to hold it to."
    ),
}

_ARTIFACT_ONLY = (
    "Declares its `artifact` and signing domain; no member names a contract, so "
    "only its file-name version is held to the claim."
)
_WIRE_SCHEMA_ONLY = (
    "Declares its `artifact` and the wire `schema_version` it fixes, which is a "
    "payload value and not the contract's version; no member names a contract."
)

#: Corpora that declare no contract at all. The file-name rule still applies.
UNDECLARED = {
    ("commissioned_safety_binding", "revision-misreadings-v2.json"): (
        "Carries a table-format `v` and a prose note; no member names a contract."
    ),
    ("evidence", "canonical-form.json"): _WIRE_SCHEMA_ONLY,
    ("evidence", "chain-row-v3.json"): _WIRE_SCHEMA_ONLY,
    ("evidence", "event-id.json"): _WIRE_SCHEMA_ONLY,
    ("evidence", "genesis.json"): _WIRE_SCHEMA_ONLY,
    ("evidence", "key-rotation.json"): _WIRE_SCHEMA_ONLY,
    ("evidence_exchange", "anchor-registration-v2.json"): _ARTIFACT_ONLY,
    ("evidence_exchange", "checkpoint.json"): _ARTIFACT_ONLY,
    ("evidence_exchange", "commissioning-authorization.json"): _ARTIFACT_ONLY,
    ("evidence_exchange", "custody-acknowledgement.json"): _ARTIFACT_ONLY,
    ("evidence_exchange", "delivery-envelope.json"): _ARTIFACT_ONLY,
    ("evidence_exchange", "evidence-disposition-v2.json"): _ARTIFACT_ONLY,
    ("evidence_exchange_receiver_state", "anchor-quarantine.json"): _ARTIFACT_ONLY,
    (
        "evidence_exchange_receiver_state",
        "commissioning-resolution-v2.json",
    ): _ARTIFACT_ONLY,
    ("evidence_exchange_receiver_state", "custody-key-purpose.json"): _ARTIFACT_ONLY,
}

#: Vendored corpora whose own declaration is wrong at their pinned commit. Each
#: records the exact bytes of the wrong `contract`, so a re-vendor that changes
#: them fails until the entry is removed and the corpus is checked in full.
DECLARATION_DEFECTS = {
    ("commissioned_safety_binding", "binding-vectors-v2.json"): {
        "declares": "ori-specs/commissioned-safety-binding/v1.md",
        "reason": (
            "commissioned-safety-binding/v2.md names this file its authoritative "
            "corpus and pins its digest, but the file's `contract` still names "
            "v1.md. The defect is upstream on ori-specs main; correcting it "
            "moves the digest v2.md pins."
        ),
        "tracking": "ori-specs#248",
    },
    ("operator_socket", "tier-c-reconcile.json"): {
        "declares": (
            "cli-commands/v1 Tier C reconciliation (`evidence reconcile-tier-c`), "
            "replayed through the tier-c-approval/v1 admission"
        ),
        "reason": (
            "The pinned revision names cli-commands/v1 for a corpus held under "
            "operator-socket/vectors. ori-specs main declares operator-socket/v1 "
            "for it; re-vendoring the set removes this entry."
        ),
        "tracking": "the runtime's operator-socket/v2 claim re-vendors this set",
    },
}


def _claim(manifest: dict[str, Any]) -> int | None:
    raw = manifest.get("contract_version", f"v{ORIGINAL_VERSION}")
    match = _CLAIM.match(raw) if isinstance(raw, str) else None
    return int(match["version"]) if match else None


def _stem_and_token(name: str) -> tuple[str, int | None]:
    match = _TOKEN.match(name)
    return (match["stem"], int(match["version"])) if match else (name[:-5], None)


def _declared_version(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    match = _CLAIM.match(value) if isinstance(value, str) else None
    return int(match["version"]) if match else None


def _specs_sets(root: Path) -> dict[str, dict[str, Any]]:
    return {
        path.parent.name: json.loads(path.read_text())
        for path in sorted(root.glob("*/MANIFEST.json"))
        if json.loads(path.read_text()).get("source_repository") == SPECS_REPOSITORY
    }


def contract_violations(root: Path) -> list[str]:
    """Every disagreement between a vendored corpus and its manifest's claim."""
    problems: list[str] = []
    sets = _specs_sets(root)

    for directory in sorted(p for p in root.iterdir() if p.is_dir()):
        if directory.name not in sets and directory.name not in NOT_SPECS_CORPORA:
            problems.append(
                f"{directory.name}: not an ori-specs set and not in NOT_SPECS_CORPORA"
            )
    for name in sorted(set(NOT_SPECS_CORPORA) & set(sets)):
        problems.append(f"{name}: vendored from ori-specs but in NOT_SPECS_CORPORA")

    claims: dict[str, int] = {}
    for set_name, manifest in sets.items():
        contract = str(manifest.get("source_path", "")).split("/")[0]
        claim = _claim(manifest)
        if not contract or claim is None:
            problems.append(
                f"{set_name}: manifest names no contract ({contract!r}) or an "
                f"unreadable contract_version ({manifest.get('contract_version')!r})"
            )
            continue
        if claims.setdefault(contract, claim) != claim:
            problems.append(
                f"{set_name}: claims {contract}/v{claim}, another set claims "
                f"{contract}/v{claims[contract]}"
            )

    known = set(UNDECLARED) | set(DECLARATION_DEFECTS)
    seen: set[tuple[str, str]] = set()
    for set_name, manifest in sets.items():
        contract = str(manifest.get("source_path", "")).split("/")[0]
        claim = _claim(manifest)
        if not contract or claim is None:
            continue
        directory = root / set_name
        names = sorted(
            p.name for p in directory.glob("*.json") if p.name != "MANIFEST.json"
        )
        if set(names) != set(manifest.get("files", {})):
            problems.append(
                f"{set_name}: files {names} differ from the manifest's "
                f"{sorted(manifest.get('files', {}))}"
            )
        by_stem: dict[str, list[str]] = {}
        for name in names:
            by_stem.setdefault(_stem_and_token(name)[0], []).append(name)
        for stem, siblings in sorted(by_stem.items()):
            if len(siblings) > 1:
                problems.append(
                    f"{set_name}: {siblings} are one stem {stem!r}; the selection "
                    "vendors a single file per stem"
                )
        shown: list[int] = []
        originals: dict[int, list[str]] = {}
        for name in names:
            key = (set_name, name)
            seen.add(key)
            token = _stem_and_token(name)[1]
            label = f"{set_name}/{name}"
            if token is not None:
                shown.append(token)
            doc = json.loads((directory / name).read_text())
            if not isinstance(doc, dict):
                problems.append(f"{label}: not a JSON object")
                continue
            declaring = [m for m in (*OWN_MEMBERS, "contract_version") if m in doc]
            if key in UNDECLARED:
                if declaring:
                    problems.append(
                        f"{label}: now declares {declaring}; remove it from UNDECLARED"
                    )
                continue
            if not declaring:
                problems.append(
                    f"{label}: declares no contract; add it to UNDECLARED with a reason"
                )
                continue
            if key in DECLARATION_DEFECTS:
                recorded = DECLARATION_DEFECTS[key]["declares"]
                if doc.get("contract") != recorded:
                    problems.append(
                        f"{label}: declares {doc.get('contract')!r}, not the recorded "
                        f"defect {recorded!r}; remove it from DECLARATION_DEFECTS"
                    )
                continue
            # Citations are read after the own declaration, which is checked here.
            cited_from: dict[str, int] = {}
            declared: dict[str, int | None] = {}
            for member in OWN_MEMBERS:
                if member not in doc:
                    continue
                value = doc[member]
                own = _OWN.match(value) if isinstance(value, str) else None
                if own is None:
                    problems.append(f"{label}: {member} {value!r} names no contract")
                    continue
                cited_from[member] = own.end("version")
                declared[member] = int(own["version"])
                if own["name"] != contract:
                    problems.append(f"{label}: {member} {value!r} is not {contract}")
            if "contract_version" in doc:
                declared["contract_version"] = _declared_version(
                    doc["contract_version"]
                )
            if len(set(declared.values())) > 1:
                problems.append(f"{label}: its declarations disagree: {declared}")
                continue
            version = next(iter(declared.values()), None)
            if version is None or version < 1:
                problems.append(f"{label}: declares an unreadable version {declared}")
                continue
            if token is not None and version != token:
                problems.append(
                    f"{label}: declares {contract}/v{version}, not v{token}"
                )
            elif token is None:
                if version > claim:
                    problems.append(
                        f"{label}: declares {contract}/v{version}, above the "
                        f"claimed v{claim}"
                    )
                shown.append(version)
                originals.setdefault(version, []).append(name)
            for member in CITING_MEMBERS:
                value = doc.get(member)
                if not isinstance(value, str):
                    continue
                for cited in _CITED.finditer(value, cited_from.get(member, 0)):
                    other, cited_version = cited["name"], int(cited["version"])
                    if other == contract and cited_version != version:
                        problems.append(
                            f"{label}: {member} cites {other}/v{cited_version} "
                            f"in a v{version} corpus"
                        )
                    elif other in claims and cited_version > claims[other]:
                        problems.append(
                            f"{label}: {member} cites {other}/v{cited_version}, "
                            f"above the v{claims[other]} this runtime vendors"
                        )
        if len(originals) > 1:
            problems.append(
                f"{set_name}: untokened files declare different original versions "
                f"{dict(sorted(originals.items()))}; a directory opens at one version"
            )
        if max(shown, default=ORIGINAL_VERSION) != claim:
            problems.append(
                f"{set_name}: claims {contract}/v{claim} but the highest version "
                f"its files show is v{max(shown, default=ORIGINAL_VERSION)}"
            )

    for key in sorted(known - seen):
        problems.append(f"{key}: listed as exempt but not vendored")
    return problems


def test_every_vendored_corpus_declares_its_manifests_contract() -> None:
    problems = contract_violations(VECTORS)
    assert not problems, "vendored corpus declarations disagree:\n  " + "\n  ".join(
        problems
    )


def test_every_exemption_carries_a_reason() -> None:
    assert not set(UNDECLARED) & set(DECLARATION_DEFECTS)
    for key, reason in UNDECLARED.items():
        assert reason.strip(), f"{key}: no reason"
    for key, entry in DECLARATION_DEFECTS.items():
        assert set(entry) == {"declares", "reason", "tracking"}, key
        assert all(entry[field].strip() for field in entry), key


def _set_member(path: Path, member: str, value: Any) -> None:
    doc = json.loads(path.read_text())
    doc[member] = value
    path.write_text(json.dumps(doc))


MUTATIONS = {
    "tokened corpus names another version": (
        "runtime_evidence_anchor/runtime-anchor-v2.json",
        "contract",
        "ori-specs runtime-evidence-anchor/v1.md",
    ),
    "vector_set names another version": (
        "runtime_evidence_anchor/runtime-anchor-v2.json",
        "vector_set",
        "runtime-evidence-anchor/v1",
    ),
    "vector_set names another contract": (
        "evidence_exchange/authority-key-registry-v2.json",
        "vector_set",
        "gateway-mqtt-canonical-json/v2 authority key registry",
    ),
    "canonicalisation cites the vendored contract above its claim": (
        "runtime_evidence_anchor/runtime-anchor-v2.json",
        "canonicalisation",
        "evidence-exchange/v3.md canonical encoding",
    ),
    "untokened corpus names a later version": (
        "safety_profile/profiles.json",
        "contract",
        "safety-profile/v2",
    ),
    "tokened corpus alone names a version other than its token": (
        "offline_tokens/signing-domain-v2.json",
        "contract",
        "offline-tokens/v1 signature domain",
    ),
    "corpus names another contract": (
        "offline_tokens/signing-domain-v2.json",
        "contract",
        "cli-commands/v2 signature domain",
    ),
    "canonicalisation cites its own contract at another version": (
        "runtime_evidence_anchor/runtime-anchor-v2.json",
        "canonicalisation",
        "runtime-evidence-anchor/v1.md canonical encoding",
    ),
    "contract_version member names another version": (
        "offline_tokens/signing-domain-v2.json",
        "contract_version",
        1,
    ),
    "claim raised past every file": (
        "evidence_exchange/MANIFEST.json",
        "contract_version",
        "v3",
    ),
    "claim lowered below a tokened file": (
        "runtime_evidence_anchor/MANIFEST.json",
        "contract_version",
        "v1",
    ),
    "claim added where the files are original": (
        "gateway_api/MANIFEST.json",
        "contract_version",
        "v2",
    ),
    "undeclared corpus starts declaring": (
        "evidence/genesis.json",
        "contract",
        "evidence/v3",
    ),
    "recorded defect changes": (
        "operator_socket/tier-c-reconcile.json",
        "contract",
        "operator-socket/v1 Tier C reconciliation",
    ),
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
def test_each_mutation_of_a_declaration_or_claim_is_refused(
    mutation: str, tmp_path: Path
) -> None:
    root = tmp_path / "vectors"
    shutil.copytree(VECTORS, root)
    relative, member, value = MUTATIONS[mutation]
    assert not contract_violations(root)
    _set_member(root / relative, member, value)
    assert contract_violations(root), mutation


_TIER_B = "skills-package/v3 — Tier B execution policy"


def _with_untokened_v3_set(root: Path, files: dict[str, dict[str, Any]]) -> None:
    """A set opened at v3 without tokens, as ori-specs' skills-package vectors are."""
    directory = root / "skills_package"
    directory.mkdir()
    for name, doc in files.items():
        (directory / name).write_text(json.dumps(doc))
    manifest = {
        "source_repository": SPECS_REPOSITORY,
        "source_path": "skills-package/vectors",
        "source_commit": "0" * 40,
        "contract_version": "v3",
        "files": {name: "0" * 64 for name in files},
    }
    (directory / "MANIFEST.json").write_text(json.dumps(manifest))


def test_an_untokened_set_opened_above_v1_declares_its_opening_version(
    tmp_path: Path,
) -> None:
    root = tmp_path / "vectors"
    shutil.copytree(VECTORS, root)
    _with_untokened_v3_set(
        root,
        {
            "tier-b-policy.json": {"contract": _TIER_B, "cases": []},
            "tier-authority.json": {"contract": "skills-package/v3 — tier authority"},
        },
    )
    assert not contract_violations(root)


UNTOKENED_MUTATIONS: dict[str, tuple[dict[str, dict[str, Any]], str]] = {
    "declares above the claim": (
        {"tier-b-policy.json": {"contract": "skills-package/v4 — Tier B"}},
        "above the claimed v3",
    ),
    "declares another contract": (
        {"tier-b-policy.json": {"contract": "skills-registry/v3 — Tier B"}},
        "is not skills-package",
    ),
    "carried beside a tokened sibling": (
        {
            "tier-b-policy.json": {"contract": _TIER_B},
            "tier-b-policy-v3.json": {"contract": _TIER_B},
        },
        "one stem 'tier-b-policy'",
    ),
    "two tokened files of one stem": (
        {
            "tier-b-policy.json": {"contract": _TIER_B},
            "tier-authority-v2.json": {"contract": "skills-package/v2 — tier"},
            "tier-authority-v3.json": {"contract": "skills-package/v3 — tier"},
        },
        "one stem 'tier-authority'",
    ),
    "untokened files disagree on the opening version": (
        {
            "tier-b-policy.json": {"contract": _TIER_B},
            "tier-authority.json": {"contract": "skills-package/v2 — tier authority"},
        },
        "different original versions",
    ),
    "declares below a claim nothing else shows": (
        {"tier-b-policy.json": {"contract": "skills-package/v2 — Tier B"}},
        "the highest version its files show is v2",
    ),
    "declares a version below v1": (
        {
            "tier-b-policy-v3.json": {"contract": _TIER_B},
            "tier-authority.json": {"contract_version": 0},
        },
        "declares an unreadable version",
    ),
    "contract and contract_version disagree": (
        {"tier-b-policy.json": {"contract": _TIER_B, "contract_version": "v2"}},
        "its declarations disagree",
    ),
}


@pytest.mark.parametrize("mutation", sorted(UNTOKENED_MUTATIONS))
def test_each_untokened_misdeclaration_is_refused(
    mutation: str, tmp_path: Path
) -> None:
    root = tmp_path / "vectors"
    shutil.copytree(VECTORS, root)
    files, expected = UNTOKENED_MUTATIONS[mutation]
    _with_untokened_v3_set(root, files)
    problems = contract_violations(root)
    assert any(expected in problem for problem in problems), problems
