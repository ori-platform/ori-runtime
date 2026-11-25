#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
"""Audit every shipped lock file against OSV, before anything is installed.

It reads the Python locks under `requirements/` and the Android payload's
`Cargo.lock` with the standard library alone, so CI can run it before any
dependency is installed or built. OSV carries the PyPI and RustSec advisories
and the OpenSSF malicious-package (`MAL-`) records.

Every record fails the audit, with one exception: a RustSec record whose every
affected entry is a crates.io notice that the crate is unmaintained is printed
and passes, as `cargo audit` treats it. The audit fails closed: an outage, an
answer of any other shape, a record that is not the one asked for, a package
from another registry, and a lock with nothing to audit all fail it.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

PYTHON_LOCKS = tuple(
    Path("requirements") / f"{name}.txt"
    for name in ("runtime", "dev", "pi", "phone", "phone-growatt", "phone-victron")
)
CARGO_LOCK = Path("mobile/ori-runtime-mobile/Cargo.lock")
OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
#: crates.io as Cargo.lock records it, through the git index or the sparse one.
CRATES_IO = frozenset(
    {
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
    }
)
#: OSV's limit on queries in one batch.
BATCH = 1000
#: One pinned requirement as pip-compile writes it: name, extras, `==` version.
#: The version is one exact release; a wildcard (`1.26.*`) or `===` is not.
PIN_RE = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?"
    r"==([0-9A-Za-z][0-9A-Za-z.+!_-]*)(?=\s|;|\\|$)"
)

#: Fetches a URL: POSTs the body when one is given, else GETs.
Fetch = Callable[[str, bytes | None], bytes]
Package = tuple[str, str, str]


def python_pins(lock_text: str) -> list[Package]:
    """Each pinned requirement of a pip-compile lock as (ecosystem, name, version).

    A requirement line that is not an exact pin is refused: it could not be
    audited at the version that installs.
    """
    pins: list[Package] = []
    for raw in lock_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "--hash")):
            continue
        match = PIN_RE.match(line)
        if match is None:
            raise ValueError(f"not an exact pin: {line}")
        name = re.sub(r"[-_.]+", "-", match.group(1)).lower()
        pins.append(("PyPI", name, match.group(2)))
    if not pins:
        raise ValueError("the lock holds no pinned requirement to audit")
    return pins


def locked_crates(lock_text: str) -> list[Package]:
    """Each crates.io package in *lock_text* as (ecosystem, name, version).

    A package from any other registry, and a lock with no crates.io package,
    are refused: neither can be audited here, and neither may pass as clean.
    """
    crates: list[Package] = []
    for package in tomllib.loads(lock_text).get("package", []):
        source = str(package.get("source", ""))
        if source in CRATES_IO:
            crates.append(("crates.io", str(package["name"]), str(package["version"])))
        elif source.startswith(("registry+", "sparse+")):
            raise ValueError(f"{package['name']} is from another registry: {source}")
    if not crates:
        raise ValueError("Cargo.lock holds no crates.io package to audit")
    return crates


def _fetch(url: str, body: bytes | None) -> bytes:
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310
        return bytes(response.read())


def _record_ids(packages: list[Package], fetch: Fetch) -> list[list[str]]:
    """The OSV record ids naming each package's locked version, in order."""
    ids: list[list[str]] = []
    for start in range(0, len(packages), BATCH):
        chunk = packages[start : start + BATCH]
        queries = [
            {"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk
        ]
        answer = json.loads(
            fetch(OSV_QUERYBATCH, json.dumps({"queries": queries}).encode())
        )
        results = answer.get("results") if isinstance(answer, dict) else None
        if not isinstance(results, list) or len(results) != len(chunk):
            raise ValueError("OSV answered a different number of queries")
        for result in results:
            if not isinstance(result, dict) or set(result) - {"vulns"}:
                raise ValueError(f"OSV answered a query as {result!r}")
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list) or not all(
                isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]
                for v in vulns
            ):
                raise ValueError(f"OSV answered a query with records {vulns!r}")
            ids.append(sorted(str(v["id"]) for v in vulns))
    return ids


def _unmaintained_crate(record_id: str, record: dict[str, Any]) -> bool:
    """Whether *record* is a RustSec notice that a crates.io crate is unmaintained."""
    affected = record.get("affected")
    return (
        record_id.startswith("RUSTSEC-")
        and isinstance(affected, list)
        and bool(affected)
        and all(
            isinstance(a, dict)
            and isinstance(a.get("package"), dict)
            and a["package"].get("ecosystem") == "crates.io"
            and isinstance(a.get("database_specific"), dict)
            and a["database_specific"].get("informational") == "unmaintained"
            for a in affected
        )
    )


def audit(
    packages: list[Package], fetch: Fetch = _fetch
) -> tuple[list[str], list[str]]:
    """The records that fail the audit, and the unmaintained-crate notices."""
    failing: list[str] = []
    notices: list[str] = []
    for (ecosystem, name, version), ids in zip(
        packages, _record_ids(packages, fetch), strict=True
    ):
        for record_id in ids:
            record = json.loads(fetch(OSV_VULN + record_id, None))
            if not isinstance(record, dict) or record.get("id") != record_id:
                raise ValueError(f"OSV answered {record_id} with another record")
            line = (
                f"{ecosystem} {name} {version}: {record_id} {record.get('summary', '')}"
            )
            notice = ecosystem == "crates.io" and _unmaintained_crate(record_id, record)
            (notices if notice else failing).append(line.strip())
    return failing, notices


def shipped_packages() -> list[Package]:
    """Every package of every shipped lock, each lock read and refused on its own."""
    packages: list[Package] = []
    for lock in PYTHON_LOCKS:
        packages += python_pins(lock.read_text(encoding="utf-8"))
    packages += locked_crates(CARGO_LOCK.read_text(encoding="utf-8"))
    return sorted(set(packages))


def main() -> int:
    try:
        packages = shipped_packages()
        failing, notices = audit(packages)
    except Exception as exc:  # noqa: BLE001 - any failure fails the audit
        print(f"Lock audit could not complete: {exc!r}", file=sys.stderr)
        return 1
    for line in notices:
        print(f"Lock audit notice (unmaintained crate, not failing): {line}")
    if failing:
        print("Lock audit found OSV records:", file=sys.stderr)
        for line in failing:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(f"Lock audit: {len(packages)} packages, no failing OSV records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
