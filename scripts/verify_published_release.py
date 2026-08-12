#!/usr/bin/env python3
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""Verify the complete v1 published release set for every target.

The same verification runs twice in the release pipeline. Before publication it
checks assets already staged on disk, so unverifiable bytes are never made
public. After publication it re-downloads over HTTPS from the approved release
origin rather than reusing workflow artifacts, because publication is only
trustworthy if what an operator actually fetches verifies.

The reviewed registry in this checkout is the trust anchor that authenticates a
bundle. Authenticating a bundle with a key carried inside that same bundle
would be circular, so instead this proves the reverse direction: once a bundle
is authenticated, the Runtime wheel it contains must ship a byte-identical
registry, which is what makes the installed anchor trustworthy.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from http.client import HTTPMessage
from importlib import resources
from pathlib import Path
from typing import IO, Callable, Sequence

from ori.security.release_bundles import (
    ReleaseBundleError,
    extract_verified_bundle,
    load_release_key_registry,
    release_artifact_name,
    verify_release_bundle,
)

RELEASE_ORIGIN = "https://github.com/ori-platform/ori-runtime/releases/download"
BOOTSTRAP_NAME = "install-linux.sh"
PACKAGED_REGISTRY = "ori/installer/release-keys.json"
_VERSION_RE = re.compile(
    r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$"
)
_MAX_ASSET_BYTES = 4 * 1024 * 1024 * 1024
_MAX_TEXT_BYTES = 1024 * 1024
_MAX_REGISTRY_BYTES = 64 * 1024
_CHECKSUM_RE = re.compile(r"^(?P<digest>[0-9a-f]{64}) [ *](?P<name>\S+)$")
_RETRY_STATUS = frozenset({404, 408, 425, 429, 500, 502, 503, 504})
_RETRY_DEADLINE_SECONDS = 300.0
_RETRY_BASE_DELAY_SECONDS = 2.0


class PublicationError(Exception):
    """Stable publication-verification failure safe to surface in logs."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Permit redirects only to GitHub-controlled HTTPS asset hosts."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        parsed = urllib.parse.urlsplit(newurl)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not (
            host == "github.com" or host.endswith(".githubusercontent.com")
        ):
            raise PublicationError(
                "artifact_integrity_mismatch",
                "published asset redirected to an untrusted origin",
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch_once(url: str, destination: Path, limit: int) -> None:
    request = urllib.request.Request(
        url, headers={"User-Agent": "ori-release-reverify/1"}
    )
    opener = urllib.request.build_opener(_HttpsOnlyRedirect())
    total = 0
    with opener.open(request, timeout=60) as response, destination.open("wb") as output:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise PublicationError(
                    "artifact_integrity_mismatch", "published asset is outside bounds"
                )
            output.write(chunk)


def download_asset(
    url: str,
    destination: Path,
    limit: int,
    *,
    sleeper: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
) -> None:
    """Fetch one asset, retrying only transient delivery failures.

    Freshly published assets can 404 briefly while GitHub's CDN catches up, so
    transient transport failures are retried under a total deadline. Integrity
    failures are never retried: a wrong digest or an untrusted redirect is an
    answer, not a hiccup.
    """
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        raise PublicationError(
            "artifact_integrity_mismatch",
            "published asset URL must use the approved HTTPS origin",
        )
    deadline = monotonic() + _RETRY_DEADLINE_SECONDS
    attempt = 0
    while True:
        attempt += 1
        try:
            _fetch_once(url, destination, limit)
            return
        except PublicationError:
            destination.unlink(missing_ok=True)
            raise
        except urllib.error.HTTPError as exc:
            destination.unlink(missing_ok=True)
            transient = exc.code in _RETRY_STATUS
            failure: Exception = exc
        except (OSError, urllib.error.URLError) as exc:
            destination.unlink(missing_ok=True)
            transient = True
            failure = exc
        delay = min(_RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), 30.0)
        if not transient or monotonic() + delay >= deadline:
            raise PublicationError(
                "artifact_integrity_mismatch", f"published asset download failed: {url}"
            ) from failure
        sleeper(delay)


def parse_checksum_file(text: str, expected_name: str) -> str:
    """Return the digest a ``sha256sum -c`` compatible file binds to one name."""
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise PublicationError(
            "artifact_integrity_mismatch", "checksum file must contain exactly one entry"
        )
    match = _CHECKSUM_RE.fullmatch(lines[0])
    if match is None or match.group("name") != expected_name:
        raise PublicationError(
            "artifact_integrity_mismatch", "checksum file entry is malformed"
        )
    return match.group("digest")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


Resolver = Callable[[str, int], Path]


def origin_resolver(base: str, workspace: Path) -> Resolver:
    """Resolve assets by downloading them from the approved release origin."""

    def resolve(name: str, limit: int) -> Path:
        destination = workspace / name
        download_asset(f"{base}/{name}", destination, limit)
        return destination

    return resolve


def staged_resolver(source: Path) -> Resolver:
    """Resolve assets already staged on disk, before they are published."""

    def resolve(name: str, limit: int) -> Path:
        path = source / name
        try:
            if not path.is_file() or path.is_symlink():
                raise PublicationError(
                    "artifact_integrity_mismatch", f"staged asset is missing: {name}"
                )
            if path.stat().st_size > limit:
                raise PublicationError(
                    "artifact_integrity_mismatch", f"staged asset is oversized: {name}"
                )
        except OSError as exc:
            raise PublicationError(
                "artifact_integrity_mismatch", f"staged asset is unreadable: {name}"
            ) from exc
        return path

    return resolve


def verify_checksum_pair(resolve: Resolver, name: str, limit: int) -> Path:
    """Require an asset to match the ``.sha256`` published beside it."""
    asset = resolve(name, limit)
    checksum = resolve(f"{name}.sha256", _MAX_TEXT_BYTES)
    try:
        declared = parse_checksum_file(checksum.read_text(encoding="utf-8"), name)
    except (OSError, UnicodeError) as exc:
        raise PublicationError(
            "artifact_integrity_mismatch", f"checksum file could not be read: {name}"
        ) from exc
    if declared != _digest(asset):
        raise PublicationError(
            "artifact_integrity_mismatch",
            f"{name} does not match its published checksum",
        )
    return asset


def reviewed_anchor_bytes() -> bytes:
    """Return the reviewed registry this checkout uses to authenticate bundles."""
    resource = resources.files("ori.installer").joinpath("release-keys.json")
    with resources.as_file(resource) as path:
        return path.read_bytes()


def verify_packaged_anchor(root: Path, anchor: bytes) -> None:
    """Prove the authenticated bundle ships the reviewed anchor verbatim.

    A Runtime installed from this bundle trusts the registry inside its own
    wheel, so that registry must be byte-identical to the reviewed one.
    """
    wheels = sorted((root / "wheelhouse").glob("ori_runtime-*.whl"))
    if len(wheels) != 1:
        raise PublicationError(
            "bundle_manifest_mismatch",
            f"expected exactly one Runtime wheel, found {len(wheels)}",
        )
    try:
        with zipfile.ZipFile(wheels[0]) as wheel:
            entries = [
                info
                for info in wheel.infolist()
                if info.filename == PACKAGED_REGISTRY and not info.is_dir()
            ]
            if len(entries) != 1:
                raise PublicationError(
                    "untrusted_release_key",
                    f"Runtime wheel must contain exactly one {PACKAGED_REGISTRY},"
                    f" found {len(entries)}",
                )
            if entries[0].file_size > _MAX_REGISTRY_BYTES:
                raise PublicationError(
                    "untrusted_release_key", "packaged release registry is oversized"
                )
            packaged = wheel.read(entries[0])
    except PublicationError:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise PublicationError(
            "untrusted_release_key", "Runtime wheel could not be inspected"
        ) from exc
    if packaged != anchor:
        raise PublicationError(
            "untrusted_release_key",
            "packaged release registry does not match the reviewed anchor",
        )


def verify_bootstrap(resolve: Resolver) -> None:
    """Require the bootstrap to match the checksum shipped beside it."""
    verify_checksum_pair(resolve, BOOTSTRAP_NAME, _MAX_TEXT_BYTES)


def verify_target(resolve: Resolver, version: str, target: str) -> None:
    """Authenticate one release bundle and prove its packaged anchor."""
    artifact_name = release_artifact_name(version, target)
    artifact = verify_checksum_pair(resolve, artifact_name, _MAX_ASSET_BYTES)
    envelope = resolve(f"{artifact_name}.signature.json", _MAX_TEXT_BYTES)
    anchor = reviewed_anchor_bytes()
    with resources.as_file(
        resources.files("ori.installer").joinpath("release-keys.json")
    ) as registry_path:
        registry = load_release_key_registry(registry_path)
    verified = verify_release_bundle(
        artifact_path=artifact,
        envelope_path=envelope,
        key_registry=registry,
        expected_version=version,
        expected_target=target,
    )
    with tempfile.TemporaryDirectory(prefix="ori-anchor-") as temporary:
        extracted = extract_verified_bundle(
            verified, destination=Path(temporary) / "verified"
        )
        verify_packaged_anchor(extracted.root, anchor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify Ori Runtime release assets against the reviewed trust anchor."
    )
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True, action="append", dest="targets")
    parser.add_argument(
        "--workspace",
        required=True,
        type=Path,
        help="staged asset directory with --from-staged, download workspace otherwise",
    )
    parser.add_argument(
        "--from-staged",
        action="store_true",
        help="verify assets already on disk instead of downloading them",
    )
    args = parser.parse_args(argv)

    try:
        if not _VERSION_RE.fullmatch(args.version):
            raise PublicationError(
                "invalid_release_version", "release version is malformed"
            )
        workspace = args.workspace
        if not workspace.is_absolute() or not workspace.is_dir():
            raise PublicationError(
                "unsafe_install_root", "verification workspace is unavailable"
            )
        if args.from_staged:
            resolve = staged_resolver(workspace)
            source = "staged"
        else:
            resolve = origin_resolver(f"{RELEASE_ORIGIN}/v{args.version}", workspace)
            source = "published"
        verify_bootstrap(resolve)
        for target in args.targets:
            verify_target(resolve, args.version, target)
    except (PublicationError, ReleaseBundleError) as exc:
        print(f"{exc.code}: {exc.detail}", file=sys.stderr)
        return 2
    print(
        f"verified {source} release v{args.version} for {len(args.targets)} target(s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
