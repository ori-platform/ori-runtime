#!/usr/bin/env bash
# This file is a bash/Python polyglot: bash runs the preamble below, selects an
# interpreter, and `exec`s it before reaching any Python. `bash -n` parses the
# whole file at once and therefore reports a syntax error on the first
# Python-only construct — that is expected, and is not a defect to repair by
# restructuring this preamble. What must hold is that bash never falls through
# into the Python: every path here ends in `exec` or `exit`, which
# `test_the_preamble_always_hands_off_before_python_begins` pins. Both dispatch
# modes are exercised by `test_shell_polyglot_help_runs_without_importing_runtime`.
""":"
if [ -z "${BASH_VERSION:-}" ]; then
  echo "unsupported_target: install-linux.sh must be run with bash; use curl ... | bash -s -- ..." >&2
  exit 2
fi
# Find an interpreter this installer can actually use. Bundles are published
# for 3.11, 3.12 and 3.13 only, and `python3` is whatever the distribution
# chose: on Pop!_OS it is 3.10 while a perfectly good python3.12 sits alongside
# it. Using `python3` alone reports the host as unsupported when it is not.
#
# Each candidate is asked its own version rather than trusted for its name. A
# `python3.13` on PATH may be a wrapper, a shim, or a broken symlink, and the
# name proves nothing about what running it produces.
ori_python=""
for ori_candidate in python3.13 python3.12 python3.11 python3; do
  command -v "${ori_candidate}" >/dev/null 2>&1 || continue
  if "${ori_candidate}" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] in ((3, 11), (3, 12), (3, 13)) else 1)' >/dev/null 2>&1; then
    ori_python="${ori_candidate}"
    break
  fi
done
if [ -z "${ori_python}" ]; then
  # Name a package only after confirming this host can install it. The previous
  # message hardcoded `python3.12`, which does not exist on Trixie at any
  # version, so the one instruction given to an operator whose host was
  # genuinely unsupported was an apt invocation guaranteed to fail. Telling
  # someone to run a command that cannot work is worse than telling them
  # nothing: it costs them a round of debugging before they reach the docs.
  ori_hint=""
  if command -v apt-cache >/dev/null 2>&1; then
    for ori_package in python3.13 python3.12 python3.11; do
      # `apt-cache policy` prints a Candidate line for a package the configured
      # sources can actually supply, and `Candidate: (none)` for one merely
      # referenced by some dependency. Only the former is installable.
      #
      # Matched with a bash `case` rather than piped through grep. This runs
      # before anything is installed, on a host whose state is unknown, and the
      # fewer external commands the failure path needs the fewer ways it has to
      # fail while explaining a failure. `case` is a shell builtin.
      ori_policy="$(apt-cache policy "${ori_package}" 2>/dev/null)"
      case "${ori_policy}" in
        *"Candidate: (none)"*) continue ;;
        *"Candidate: "*)
          ori_hint="install it with 'sudo apt install ${ori_package}'"
          break
          ;;
      esac
    done
  fi
  if [ -z "${ori_hint}" ]; then
    ori_hint="see docs/linux-install.md for a supported interpreter route"
  fi
  echo "unsupported_target: no supported Python found on PATH. Ori requires Python 3.11, 3.12 or 3.13; ${ori_hint}, then run this again." >&2
  exit 2
fi

# Dispatch on execution mode, not on filename. BASH_SOURCE[0] is the script
# path when a file is executed and unset when bash reads the program from
# stdin, so it distinguishes the two without consulting $0 — which is merely
# "bash" for piped runs and would match a readable file of that name sitting
# in the working directory.
ori_source="${BASH_SOURCE[0]-}"
if [ -n "${ori_source}" ] && [ -f "${ori_source}" ] && [ -r "${ori_source}" ]; then
  exec "${ori_python}" "${ori_source}" "$@"
fi
# No file to run, so the program must arrive on stdin. If stdin is a terminal
# there is nothing to read, and exiting quietly would look like success.
if [ -t 0 ]; then
  echo "unsupported_target: no installer source found; run the downloaded file, or pipe it with 'curl -fsSL ... | bash -s -- ...'" >&2
  exit 2
fi
exec "${ori_python}" - "$@"
":"""
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

SIGNATURE_SCHEMA = "ori.runtime_release_bundle_signature.v1"
SIGNATURE_DOMAIN = b"ori.runtime_release_bundle_signature.v1\0"
KEY_ID = "ori-runtime-release-2026-01"
PUBLIC_KEY_B64 = "aDlW3MqinQM8y96szEqNske2ytKkxbmMDl87CuLbAQ8="
PUBLIC_KEY_SHA256 = "d4f44308d60fb78a33f709eebc85271f2b8c0d4e59e50bb77bf08f5864918c90"
RELEASE_ORIGIN = "https://github.com/ori-platform/ori-runtime/releases/download"
MAX_JSON_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_EXTRACTED_BYTES = 4 * 1024 * 1024 * 1024
MAX_MEMBER_PATH_BYTES = 512
FIELDS = {
    "artifact",
    "artifact_sha256",
    "artifact_size",
    "key_id",
    "runtime_version",
    "schema",
    "signature",
    "target",
}
MANIFEST_FIELDS = {"files", "python", "runtime_version", "schema", "target"}
MANIFEST_SCHEMA = "ori.runtime_release_bundle_manifest.v1"
VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class BootstrapError(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def fail(code: str, detail: str) -> NoReturn:
    raise BootstrapError(code, detail)


def detected_target() -> str:
    if platform.system() != "Linux":
        fail("unsupported_target", "installer requires Linux")
    architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(platform.machine().lower())
    python_version = f"{sys.version_info.major}.{sys.version_info.minor}"
    if architecture is None or python_version not in {"3.11", "3.12", "3.13"}:
        fail(
            "unsupported_target",
            "Linux architecture or Python version is unsupported",
        )
    return f"linux-{architecture}-python{python_version}"


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail("invalid_signature_envelope", "signature envelope has duplicate fields")
        value[key] = item
    return value


def _canonical_b64(value: str, length: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise BootstrapError(
            "invalid_signature_envelope", f"{label} is malformed"
        ) from exc
    if len(decoded) != length or base64.b64encode(decoded).decode("ascii") != value:
        fail("invalid_signature_envelope", f"{label} is malformed")
    return decoded


def _validate_json(value: Any) -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        return
    if isinstance(value, float):
        if math.isfinite(value):
            return
        fail("invalid_signature_envelope", "signature envelope has non-finite data")
    if isinstance(value, list):
        for item in value:
            _validate_json(item)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _validate_json(item)
        return
    fail("invalid_signature_envelope", "signature envelope has unsupported data")


def load_envelope(path: Path, version: str, target: str) -> dict[str, Any]:
    try:
        if path.stat().st_size > MAX_JSON_BYTES:
            fail("invalid_signature_envelope", "signature envelope is outside bounds")
        raw = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _value: fail(
                "invalid_signature_envelope", "signature envelope has non-finite data"
            ),
        )
    except BootstrapError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(
            "invalid_signature_envelope", "signature envelope could not be read"
        ) from exc
    if not isinstance(raw, dict) or set(raw) != FIELDS:
        fail("invalid_signature_envelope", "signature envelope fields are invalid")
    _validate_json(raw)
    strings = FIELDS - {"artifact_size"}
    if any(not isinstance(raw.get(field), str) for field in strings):
        fail("invalid_signature_envelope", "signature envelope field type is invalid")
    if raw["schema"] != SIGNATURE_SCHEMA:
        fail("invalid_signature_envelope", "signature envelope schema is unsupported")
    if raw["key_id"] != KEY_ID:
        fail("untrusted_release_key", "signature envelope names an untrusted key")
    if raw["runtime_version"] != version:
        fail("artifact_integrity_mismatch", "signed release identity does not match request")
    if raw["target"] != target:
        fail("unsupported_target", "bundle target does not match detected target")
    artifact = f"ori-runtime-{version}-{target}.tar.gz"
    if raw["artifact"] != artifact:
        fail("artifact_integrity_mismatch", "artifact filename is not bound to request")
    size = raw["artifact_size"]
    if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_ARTIFACT_BYTES:
        fail("invalid_signature_envelope", "artifact size is outside bounds")
    if not SHA256_RE.fullmatch(raw["artifact_sha256"]):
        fail("invalid_signature_envelope", "artifact digest is malformed")
    if not raw["signature"].startswith("ed25519:"):
        fail("invalid_signature_envelope", "signature profile is unsupported")
    _canonical_b64(raw["signature"].removeprefix("ed25519:"), 64, "signature")
    return raw


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        parsed = urllib.parse.urlsplit(newurl)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not (
            host == "github.com" or host.endswith(".githubusercontent.com")
        ):
            fail(
                "artifact_integrity_mismatch",
                "release download redirected to an untrusted origin",
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, destination: Path, limit: int) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        fail(
            "artifact_integrity_mismatch",
            "release URL must use the approved HTTPS origin",
        )
    request = urllib.request.Request(url, headers={"User-Agent": "ori-linux-bootstrap/1"})
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        with opener.open(request, timeout=30) as response:
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > limit:
                fail(
                    "artifact_integrity_mismatch",
                    "release download is outside bounds",
                )
            fd = os.open(destination, flags, 0o600)
            try:
                total = 0
                with os.fdopen(fd, "wb") as output:
                    fd = -1
                    while chunk := response.read(1024 * 1024):
                        total += len(chunk)
                        if total > limit:
                            fail(
                                "artifact_integrity_mismatch",
                                "release download is outside bounds",
                            )
                        output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
            finally:
                if fd != -1:
                    os.close(fd)
    except BootstrapError:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, ValueError, urllib.error.URLError) as exc:
        destination.unlink(missing_ok=True)
        raise BootstrapError(
            "artifact_integrity_mismatch", "release download failed"
        ) from exc


def verify_signature(envelope: dict[str, Any], artifact: Path, workspace: Path) -> None:
    digest = hashlib.sha256()
    size = 0
    try:
        with artifact.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
    except OSError as exc:
        raise BootstrapError(
            "artifact_integrity_mismatch", "release artifact could not be read"
        ) from exc
    if size != envelope["artifact_size"] or f"sha256:{digest.hexdigest()}" != envelope["artifact_sha256"]:
        fail("artifact_integrity_mismatch", "artifact size or SHA-256 mismatch")

    public_key = _canonical_b64(PUBLIC_KEY_B64, 32, "pinned public key")
    if hashlib.sha256(public_key).hexdigest() != PUBLIC_KEY_SHA256:
        fail("untrusted_release_key", "embedded release key fingerprint is invalid")
    signature = _canonical_b64(envelope["signature"].removeprefix("ed25519:"), 64, "signature")
    unsigned = {key: value for key, value in envelope.items() if key != "signature"}
    message = SIGNATURE_DOMAIN + json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    key_path = workspace / "release-key.der"
    message_path = workspace / "signed-message"
    signature_path = workspace / "release-signature"
    try:
        version_result = subprocess.run(
            ["openssl", "version"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
            timeout=30,
        )
        version_match = re.match(r"^OpenSSL ([0-9]+)\.", version_result.stdout)
        if (
            version_result.returncode != 0
            or version_match is None
            or int(version_match.group(1)) < 3
        ):
            fail(
                "crypto_unavailable",
                "OpenSSL 3 or newer with Ed25519 pkeyutl support is required",
            )
        key_path.write_bytes(bytes.fromhex("302a300506032b6570032100") + public_key)
        message_path.write_bytes(message)
        signature_path.write_bytes(signature)
        completed = subprocess.run(
            [
                "openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path),
                "-keyform", "DER", "-rawin", "-in", str(message_path),
                "-sigfile", str(signature_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BootstrapError(
            "crypto_unavailable", "OpenSSL Ed25519 verification is unavailable"
        ) from exc
    if completed.returncode != 0:
        fail("signature_verification_failed", "release bundle signature verification failed")


def extract_verified_bundle(artifact: Path, destination: Path, expected_root: str) -> Path:
    try:
        destination.mkdir(mode=0o700)
        with tarfile.open(artifact, mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > MAX_ARCHIVE_MEMBERS:
                fail("unsafe_bundle_archive", "archive member count is outside bounds")
            names: set[str] = set()
            folded: set[str] = set()
            total = 0
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    not member.name
                    or len(member.name.encode("utf-8")) > MAX_MEMBER_PATH_BYTES
                    or path.is_absolute()
                    or ".." in path.parts
                    or path.parts[0] != expected_root
                    or member.name in names
                    or member.name.casefold() in folded
                    or not (member.isdir() or member.isreg())
                    or member.mode & 0o6000
                ):
                    fail("unsafe_bundle_archive", "archive contains an unsafe member")
                names.add(member.name)
                folded.add(member.name.casefold())
                if member.isreg():
                    total += member.size
                    if member.size < 0 or total > MAX_EXTRACTED_BYTES:
                        fail("unsafe_bundle_archive", "archive content is outside bounds")
            for member in members:
                _extract_member(archive, member, destination)
    except BootstrapError:
        raise
    except (OSError, EOFError, tarfile.TarError, ValueError, TypeError) as exc:
        raise BootstrapError(
            "unsafe_bundle_archive", "verified bundle could not be extracted"
        ) from exc
    return destination / expected_root


def _extract_member(
    archive: tarfile.TarFile, member: tarfile.TarInfo, destination: Path
) -> None:
    """Write one validated member explicitly.

    Every member has already been checked for traversal, absolute paths,
    duplicates, special files, and setuid bits, so extracting them one at a
    time is equivalent to `filter="data"` and works on every supported
    interpreter.
    """
    target = destination.joinpath(*PurePosixPath(member.name).parts)
    if member.isdir():
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        return
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = archive.extractfile(member)
    if source is None:
        fail("unsafe_bundle_archive", f"cannot read archive member {member.name!r}")
    written = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags, 0o600)
    with source, os.fdopen(descriptor, "wb") as output:
        while chunk := source.read(1024 * 1024):
            written += len(chunk)
            if written > member.size:
                fail("unsafe_bundle_archive", "archive member exceeded its declared size")
            output.write(chunk)
    if written != member.size:
        fail("unsafe_bundle_archive", "archive member size did not match its header")


def verify_manifest(root: Path, version: str, target: str) -> None:
    manifest_path = root / "BUNDLE-MANIFEST.json"
    try:
        if manifest_path.stat().st_size > MAX_JSON_BYTES:
            fail("bundle_manifest_mismatch", "bundle manifest is outside bounds")
        manifest = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _value: fail(
                "bundle_manifest_mismatch", "bundle manifest has non-finite data"
            ),
        )
    except BootstrapError as exc:
        if exc.code == "invalid_signature_envelope":
            fail("bundle_manifest_mismatch", "bundle manifest has duplicate fields")
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BootstrapError(
            "bundle_manifest_mismatch", "bundle manifest could not be read"
        ) from exc
    expected_python = target.rsplit("python", 1)[1]
    if (
        not isinstance(manifest, dict)
        or set(manifest) != MANIFEST_FIELDS
        or manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("runtime_version") != version
        or manifest.get("target") != target
        or manifest.get("python") != expected_python
        or not isinstance(manifest.get("files"), dict)
    ):
        fail(
            "bundle_manifest_mismatch",
            "bundle manifest identity or fields are invalid",
        )
    declared = manifest["files"]
    try:
        actual_paths = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path != manifest_path
        }
    except OSError as exc:
        raise BootstrapError(
            "bundle_manifest_mismatch", "bundle file set could not be inspected"
        ) from exc
    if set(declared) != actual_paths:
        fail("bundle_manifest_mismatch", "bundle manifest file set mismatch")
    for relative, expected_digest in declared.items():
        if not isinstance(relative, str) or not isinstance(expected_digest, str):
            fail("bundle_manifest_mismatch", "bundle manifest entry is malformed")
        if not SHA256_RE.fullmatch(expected_digest):
            fail("bundle_manifest_mismatch", "bundle manifest digest is malformed")
        digest = hashlib.sha256()
        try:
            with (root / relative).open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
        except OSError as exc:
            raise BootstrapError(
                "bundle_manifest_mismatch", "bundle manifest file could not be read"
            ) from exc
        if f"sha256:{digest.hexdigest()}" != expected_digest:
            fail("bundle_manifest_mismatch", "bundle manifest digest mismatch")


def bootstrap_install(
    root: Path,
    artifact: Path,
    signature: Path,
    version: str,
    forwarded: list[str],
) -> int:
    wheelhouse = root / "wheelhouse"
    requirements = wheelhouse / "requirements.txt"
    runtime_wheels = sorted(wheelhouse.glob("ori_runtime-*.whl"))
    if not requirements.is_file() or len(runtime_wheels) != 1:
        fail("unsafe_bundle_archive", "verified wheelhouse is incomplete")
    environment = root.parent / "bootstrap-venv"
    commands = [
        [sys.executable, "-m", "venv", str(environment)],
        [
            str(environment / "bin" / "python"), "-m", "pip", "install",
            "--disable-pip-version-check", "--no-index", "--find-links", str(wheelhouse),
            "--require-hashes", "-r", str(requirements),
        ],
        [
            str(environment / "bin" / "python"), "-m", "pip", "install",
            "--disable-pip-version-check", "--no-index", "--no-deps", str(runtime_wheels[0]),
        ],
    ]
    try:
        for command in commands:
            subprocess.run(command, check=True, stdin=subprocess.DEVNULL)
        command = [
            str(environment / "bin" / "ori-install-linux"),
            "install",
            "--bundle",
            str(artifact),
            "--signature",
            str(signature),
            "--expected-version",
            version,
            *forwarded,
        ]
        if "--unattended" in forwarded:
            completed = subprocess.run(command, check=False)
        else:
            try:
                with open("/dev/tty", "rb", buffering=0) as terminal:
                    completed = subprocess.run(command, check=False, stdin=terminal)
            except OSError as exc:
                raise BootstrapError(
                    "config_validation_failed",
                    "interactive install requires a terminal; pass "
                    "-- --unattended --scope system (or --scope user), "
                    "or download the script and run it from a terminal",
                ) from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise BootstrapError(
            "offline_install_failed", "offline installer bootstrap failed"
        ) from exc
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authenticate and install an Ori Runtime Linux release.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", required=True, help="immutable Runtime release version")
    parser.add_argument("installer_arguments", nargs=argparse.REMAINDER, help="arguments forwarded to ori-install-linux after --")
    return parser


def validate_forwarded(arguments: list[str]) -> None:
    bootstrap_owned = {"--bundle", "--signature", "--expected-version"}
    for argument in arguments:
        option = argument.split("=", 1)[0]
        if len(option) > 2 and any(
            owned.startswith(option) for owned in bootstrap_owned
        ):
            fail(
                "artifact_integrity_mismatch",
                f"{option} is controlled by the authenticated bootstrap",
            )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        version = args.version
        if not VERSION_RE.fullmatch(version):
            fail("invalid_release_version", "requested runtime version is malformed")
        forwarded = list(args.installer_arguments)
        if forwarded[:1] == ["--"]:
            forwarded.pop(0)
        validate_forwarded(forwarded)
        target = detected_target()
        artifact_name = f"ori-runtime-{version}-{target}.tar.gz"
        signature_name = f"{artifact_name}.signature.json"
        base = f"{RELEASE_ORIGIN}/v{version}"
        with tempfile.TemporaryDirectory(prefix="ori-bootstrap-") as temporary_name:
            workspace = Path(temporary_name)
            os.chmod(workspace, 0o700)
            artifact = workspace / artifact_name
            signature = workspace / signature_name
            download(f"{base}/{signature_name}", signature, MAX_JSON_BYTES)
            envelope = load_envelope(signature, version, target)
            download(f"{base}/{artifact_name}", artifact, envelope["artifact_size"])
            verify_signature(envelope, artifact, workspace)
            root = extract_verified_bundle(
                artifact, workspace / "verified", artifact_name.removesuffix(".tar.gz")
            )
            verify_manifest(root, version, target)
            return bootstrap_install(root, artifact, signature, version, forwarded)
    except BootstrapError as exc:
        print(f"{exc.code}: {exc.detail}", file=sys.stderr)
        return 2
    except OSError:
        print(
            "unsafe_install_root: secure bootstrap workspace is unavailable",
            file=sys.stderr,
        )
        return 2
    except Exception as exc:  # noqa: BLE001 - operators must never see a traceback
        # Truthfully generic: an unexpected fault may come from download,
        # argument handling, or environment preparation, so it must not be
        # attributed to the archive. Suppress the traceback, keep exit 2.
        print(
            f"bootstrap_failed: installer failed unexpectedly "
            f"({type(exc).__name__})",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
