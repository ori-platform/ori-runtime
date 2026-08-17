#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""The bindings the host evidence harness kept getting wrong.

Five review rounds found the same defect in five variables: a value checked in
one place and used in another, with the two free to disagree. A target verified
but not enforced. Tooling hash-locked but not used. An interpreter selected but
not applied. A boot recorded but its version ignored. Each was a shell variable,
and each was defended by a test that matched text rather than behaviour — which
is how a comment containing a flag's name came to satisfy an assertion about
the flag.

Here they are function arguments. Selecting the interpreter and returning it is
one act; a caller cannot verify one thing and use another without saying so.
The tests exercise these functions rather than reading the script that calls
them.

Shell keeps what shell is for: `sudo`, `systemctl`, and dispatching phases.

Only the standard library is used. This runs on an operator's machine before
anything is installed, so it cannot depend on the package it is about to test.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

SUPPORTED_PYTHON = ("3.11", "3.12")
SIGNATURE_DOMAIN = b"ori.runtime_release_bundle_signature.v1\0"
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

# `ori/security/release_bundles.py` refuses a key that is not purpose-bound, and
# refuses a revoked one at verification. Checking less here would let this
# report a signature verified for an artifact the installer then refuses —
# a PASS recorded for a claim that is not true.
RELEASE_KEY_PURPOSE = "runtime_release_bundle"
TRUSTED_KEY_STATUS = frozenset({"active", "verify_only"})

# uname reports these; the tuple names the left-hand form.
_ARCH_ALIASES = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}


class EvidenceError(Exception):
    """A claim could not be established. The message is for an operator."""


def _read_bytes(path: Path, description: str) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise EvidenceError(f"{description} is unreadable: {exc}") from exc


def _required_field(mapping: dict[str, object], field: str, description: str) -> str:
    """A registry is untrusted input; a missing field is an operator message."""
    value = mapping.get(field)
    if not isinstance(value, str) or not value:
        raise EvidenceError(f"{description} declares no {field}")
    return value


def _decode_base64(value: str, description: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise EvidenceError(f"{description} is not valid base64: {exc}") from exc


def _run_openssl(arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run openssl, reporting its absence as a prerequisite rather than a crash.

    This is the tooling that predates the artifact, so a host without it cannot
    verify at all — an operator needs to be told that, not shown a traceback
    from deep inside subprocess.
    """
    try:
        return subprocess.run(
            ["openssl", *arguments], capture_output=True, text=True, check=False
        )
    except OSError as exc:
        raise EvidenceError(f"openssl could not be run: {exc}") from exc


def _read_json(path: Path, description: str) -> dict[str, object]:
    """Read JSON as an operator error rather than a traceback.

    A mistyped path and a truncated download are the two most likely things to
    go wrong on the host, and the shell branches on the exit status: a
    traceback is not a contract.
    """
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise EvidenceError(f"{description} is unreadable: {exc}") from exc
    if not isinstance(document, dict):
        raise EvidenceError(f"{description} is not a JSON object")
    return document


@dataclass(frozen=True)
class Target:
    """A release target tuple, parsed rather than pattern-matched in shell."""

    architecture: str
    python: str

    @classmethod
    def parse(cls, value: str) -> Target:
        match = re.fullmatch(r"linux-(x86_64|aarch64)-python(3\.\d+)", value)
        if match is None:
            raise EvidenceError(f"unsupported target tuple: {value}")
        architecture, python = match.group(1), match.group(2)
        if python not in SUPPORTED_PYTHON:
            raise EvidenceError(f"unsupported Python in target: {value}")
        return cls(architecture=architecture, python=python)

    def __str__(self) -> str:
        return f"linux-{self.architecture}-python{self.python}"

    def require_host_architecture(self, machine: str) -> None:
        """Refuse a target this machine cannot honestly build or install."""
        actual = _ARCH_ALIASES.get(machine, machine)
        if actual != self.architecture:
            raise EvidenceError(
                f"target is for {self.architecture}, this host is {actual}"
            )


def interpreter_for(target: Target, *, which=shutil.which) -> Path:
    """Return the interpreter *target* names, having asked it its own version.

    A name on PATH is not evidence: `python3.12` may be a wrapper, a shim, or a
    link to something else entirely. Selecting and validating happen together
    so a caller cannot end up building with one and claiming another.
    """
    located = which(f"python{target.python}")
    if located is None:
        raise EvidenceError(f"target needs python{target.python}, which is not on PATH")
    try:
        reported = subprocess.run(
            [
                located,
                "-c",
                "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        # A name on PATH that is a directory, a broken symlink, or a file
        # without an interpreter line. This is the check that catches it.
        raise EvidenceError(f"{located} could not be run: {exc}") from exc
    if reported.returncode != 0:
        raise EvidenceError(f"{located} could not be run: {reported.stderr.strip()}")
    version = reported.stdout.strip()
    if version != target.python:
        raise EvidenceError(f"{located} reports {version}, not {target.python}")
    return Path(located)


def envelope_target(signature: Path) -> Target:
    """The target the artifact was signed for, from the envelope itself.

    Taking it from anywhere else lets a 3.12 artifact be driven by a 3.10
    installer, which refuses before installation is attempted — a failure about
    the harness wearing the appearance of a failure about the release.
    """
    document = _read_json(signature, "signature envelope")
    if "target" not in document:
        raise EvidenceError("signature envelope declares no target")
    return Target.parse(str(document["target"]))


def verify_artifact(
    *,
    bundle: Path,
    signature: Path,
    registry: Path,
    expected_sha256: str,
    expected_version: str,
    workspace: Path,
) -> str:
    """Verify digest and signature with tooling that predates the artifact.

    Installing first and letting the newly installed code check its own source
    inverts the trust boundary; this runs as root, so it uses openssl and
    hashlib against a registry the caller supplies.
    """
    payload = _read_bytes(bundle, f"the artifact {bundle.name}")
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected_sha256:
        raise EvidenceError(
            f"artifact digest is {actual}, the record says {expected_sha256}"
        )

    envelope = _read_json(signature, "signature envelope")
    required = {
        "artifact",
        "artifact_sha256",
        "artifact_size",
        "key_id",
        "runtime_version",
        "schema",
        "signature",
        "target",
    }
    missing = sorted(required - set(envelope))
    if missing:
        raise EvidenceError(f"signature envelope is missing {', '.join(missing)}")
    if envelope["runtime_version"] != expected_version:
        raise EvidenceError(
            f"envelope names {envelope['runtime_version']}, expected {expected_version}"
        )
    if envelope["artifact"] != bundle.name:
        raise EvidenceError(f"envelope names {envelope['artifact']}, got {bundle.name}")
    if envelope["artifact_size"] != len(payload):
        raise EvidenceError("artifact size does not match the envelope")
    if envelope["artifact_sha256"] != f"sha256:{actual}":
        raise EvidenceError("artifact digest does not match the envelope")

    entries = _read_json(registry, "key registry").get("keys")
    if not isinstance(entries, list):
        raise EvidenceError("key registry declares no keys")
    keys = {entry.get("key_id"): entry for entry in entries if isinstance(entry, dict)}
    key = keys.get(envelope["key_id"])
    if key is None:
        raise EvidenceError(
            f"envelope names key {envelope['key_id']}, absent from the registry"
        )
    if key.get("purpose") != RELEASE_KEY_PURPOSE:
        raise EvidenceError(f"key {envelope['key_id']} is not a release-bundle key")
    if key.get("status") not in TRUSTED_KEY_STATUS:
        raise EvidenceError(
            f"key {envelope['key_id']} has status {key.get('status')!r}, not trusted"
        )

    scheme, _, encoded = str(envelope["signature"]).partition(":")
    if scheme != "ed25519":
        raise EvidenceError(f"unsupported signature scheme: {scheme}")

    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    message = (
        SIGNATURE_DOMAIN
        + json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    )

    public_key = _decode_base64(
        _required_field(key, "public_key_b64", f"key {envelope['key_id']}"),
        f"public key for {envelope['key_id']}",
    )
    signature_bytes = _decode_base64(encoded, "signature")

    public = workspace / "public.der"
    try:
        workspace.mkdir(parents=True, exist_ok=True)
        public.write_bytes(_ED25519_SPKI_PREFIX + public_key)
        (workspace / "message.bin").write_bytes(message)
        (workspace / "signature.bin").write_bytes(signature_bytes)
    except OSError as exc:
        raise EvidenceError(f"verification workspace is unusable: {exc}") from exc

    result = _run_openssl(
        [
            "pkeyutl",
            "-verify",
            "-pubin",
            "-inkey",
            str(public),
            "-keyform",
            "DER",
            "-rawin",
            "-in",
            str(workspace / "message.bin"),
            "-sigfile",
            str(workspace / "signature.bin"),
        ]
    )
    if result.returncode != 0:
        raise EvidenceError(
            f"signature did not verify: {result.stdout.strip()} {result.stderr.strip()}"
        )
    return f"{bundle.name} verified against {envelope['key_id']}"


@dataclass(frozen=True)
class InstallRecord:
    """What an install phase proved, for a later phase to rely on."""

    boot_id: str
    version: str

    def render(self) -> str:
        return f"boot_id={self.boot_id}\nversion={self.version}\n"

    @classmethod
    def parse(cls, text: str) -> InstallRecord:
        fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        if "boot_id" not in fields or "version" not in fields:
            raise EvidenceError("install record is incomplete")
        return cls(boot_id=fields["boot_id"], version=fields["version"])


def write_record(path: Path, record: InstallRecord) -> None:
    """Write via a staged rename, so no reader sees a half-written record.

    The record's own mode is what keeps it private. Its directory is not this
    function's to reassign: the real path is `/var/lib/ori-evidence-state`, and
    tightening `/var/lib` on an operator's host would break every account on
    the machine to protect one file that is already 0600.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, staged = tempfile.mkstemp(dir=path.parent, prefix=".record-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(record.render())
        os.chmod(staged, 0o600)
        os.replace(staged, path)
    except BaseException:
        Path(staged).unlink(missing_ok=True)
        raise


def require_reboot_since(
    record_path: Path, *, expected_version: str, current_boot: str | None = None
) -> InstallRecord:
    """Establish that this host rebooted since *that* installation.

    Uptime cannot: installing shortly after an ordinary boot and running the
    next phase immediately satisfies any bound while nothing has restarted. And
    a record left by an earlier candidate would otherwise let this vouch for
    whichever release happens to be active now.
    """
    try:
        record = InstallRecord.parse(record_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise EvidenceError(f"no install record at {record_path}: {exc}") from exc
    if record.version != expected_version:
        raise EvidenceError(
            f"the record is for {record.version}, asked about {expected_version}"
        )
    if current_boot is None:
        current_boot = current_boot_id()
    if not current_boot:
        raise EvidenceError("the current boot id is empty; cannot establish a reboot")
    if record.boot_id == current_boot:
        raise EvidenceError(
            f"still boot {current_boot}; reboot before running this phase"
        )
    return record


def current_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise EvidenceError(f"boot id is unavailable: {exc}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    choose = sub.add_parser("select-python", help="resolve the artifact's interpreter")
    choose.add_argument("--signature", type=Path, required=True)

    check = sub.add_parser("verify", help="verify digest and signature")
    check.add_argument("--bundle", type=Path, required=True)
    check.add_argument("--signature", type=Path, required=True)
    check.add_argument("--registry", type=Path, required=True)
    check.add_argument("--sha256", required=True)
    check.add_argument("--version", required=True)
    check.add_argument("--workspace", type=Path, required=True)

    record = sub.add_parser("record", help="record a passing installation")
    record.add_argument("--path", type=Path, required=True)
    record.add_argument("--version", required=True)

    persisted = sub.add_parser("require-reboot", help="require a later boot")
    persisted.add_argument("--path", type=Path, required=True)
    persisted.add_argument("--version", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "select-python":
            target = envelope_target(args.signature)
            target.require_host_architecture(os.uname().machine)
            print(interpreter_for(target))
        elif args.command == "verify":
            print(
                verify_artifact(
                    bundle=args.bundle,
                    signature=args.signature,
                    registry=args.registry,
                    expected_sha256=args.sha256,
                    expected_version=args.version,
                    workspace=args.workspace,
                )
            )
        elif args.command == "record":
            write_record(
                args.path,
                InstallRecord(boot_id=current_boot_id(), version=args.version),
            )
            print(f"recorded {args.version}")
        elif args.command == "require-reboot":
            found = require_reboot_since(args.path, expected_version=args.version)
            print(f"rebooted since {found.boot_id}")
    except EvidenceError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
