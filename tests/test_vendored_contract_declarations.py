# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Every vendored ori-specs corpus declares the contract version its manifest claims.

A manifest's `contract_version` is the version this runtime says it conforms to.
A corpus whose own `contract` or `vector_set` names another version cannot be
checked against that claim, so the two are held together here.

The version a file belongs to follows `scripts/refresh-evidence-vectors.sh`: a
`<stem>-v<N>.json` file belongs to version N, an untokened file to the
contract's original version, and a set claims the newest file it holds. A
manifest with no `contract_version` claims the original version.
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
    },
}


def _claim(manifest: dict[str, Any]) -> int | None:
    raw = manifest.get("contract_version", f"v{ORIGINAL_VERSION}")
    match = _CLAIM.match(raw) if isinstance(raw, str) else None
    return int(match["version"]) if match else None


def _file_version(name: str) -> int:
    match = _TOKEN.match(name)
    return int(match["version"]) if match else ORIGINAL_VERSION


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
        versions = [_file_version(name) for name in names]
        if not versions or max(versions) != claim:
            problems.append(
                f"{set_name}: claims {contract}/v{claim} but its newest file is "
                f"v{max(versions, default=0)}"
            )
        for name in names:
            key = (set_name, name)
            seen.add(key)
            version = _file_version(name)
            label = f"{set_name}/{name}"
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
            for member in OWN_MEMBERS:
                if member not in doc:
                    continue
                value = doc[member]
                own = _OWN.match(value) if isinstance(value, str) else None
                if own is None:
                    problems.append(f"{label}: {member} {value!r} names no contract")
                    continue
                cited_from[member] = own.end("version")
                if (own["name"], int(own["version"])) != (contract, version):
                    problems.append(
                        f"{label}: {member} {value!r} is not {contract}/v{version}"
                    )
            if "contract_version" in doc:
                if _declared_version(doc["contract_version"]) != version:
                    problems.append(
                        f"{label}: contract_version {doc['contract_version']!r} "
                        f"is not v{version}"
                    )
            for member in CITING_MEMBERS:
                value = doc.get(member)
                if not isinstance(value, str):
                    continue
                for cited in _CITED.finditer(value, cited_from.get(member, 0)):
                    name, cited_version = cited["name"], int(cited["version"])
                    if name == contract and cited_version != version:
                        problems.append(
                            f"{label}: {member} cites {name}/v{cited_version} "
                            f"in a v{version} corpus"
                        )
                    elif name in claims and cited_version > claims[name]:
                        problems.append(
                            f"{label}: {member} cites {name}/v{cited_version}, "
                            f"above the v{claims[name]} this runtime vendors"
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
        assert set(entry) == {"declares", "reason"}, key
        assert entry["declares"].strip() and entry["reason"].strip(), key


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
