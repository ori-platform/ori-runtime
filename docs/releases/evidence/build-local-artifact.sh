#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Build and development-sign a release artifact from a named commit.
#
# The artifact this produces is behaviourally the one the release workflow would
# build from the same commit, with the trust anchor substituted. It is not
# byte-identical: the packaged key registry is part of the source, so replacing
# it changes the wheel and the bundle as well as the signature. What it
# reproduces is installation behaviour; what it cannot speak to is signing
# custody or anything downstream of publication.
#
# The production trust root is never modified. The substitution happens inside
# an extracted copy of the commit under a temporary directory, which is removed
# when the run ends; the checkout and the installed runtime on this host are
# untouched.
#
# Usage: build-local-artifact.sh <commit> <target> <release-version> [outdir]
#   e.g. build-local-artifact.sh HEAD linux-x86_64-python3.12 2.4.0-rc.5
#
# Prints the values an evidence record has to carry: source commit, archive
# digest, artifact digest, and the fingerprint of the key that signed it.
set -euo pipefail

COMMIT="${1:?usage: build-local-artifact.sh <commit> <target> <release-version> [outdir]}"
TARGET="${2:?target tuple required, e.g. linux-x86_64-python3.12}"
RELEASE_VERSION="${3:?release version required, e.g. 2.4.0-rc.5}"
# Resolved before any `cd`. A relative path would otherwise be interpreted from
# the extracted source inside the temporary tree, and the cleanup trap would
# delete the artifact this run exists to produce.
OUTDIR="${4:-$PWD/ori-local-artifact}"
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"

REPO_ROOT="$(git rev-parse --show-toplevel)"
FULL_COMMIT="$(git -C "$REPO_ROOT" rev-parse "$COMMIT^{commit}")"

digest_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/ori-build-XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT
SOURCE="$WORKDIR/source"
mkdir -p "$SOURCE"

# From the commit, not the working tree: an artifact built from uncommitted
# edits cannot be reproduced by anyone reading the record.
ARCHIVE="$WORKDIR/source.tar"
git -C "$REPO_ROOT" archive --format=tar --output="$ARCHIVE" "$FULL_COMMIT"
ARCHIVE_SHA256="$(digest_of "$ARCHIVE")"
tar -C "$SOURCE" -xf "$ARCHIVE"
cd "$SOURCE"

# --- the target tuple is a claim about this machine, so prove it ------------
# `$TARGET` otherwise only labels the artifact: a 3.10 build on x86_64 would
# happily be named python3.12-aarch64, and nothing downstream would notice
# until the bundle failed on a device.
TUPLE_ARCH="$(printf '%s' "$TARGET" | cut -d- -f2)"
TUPLE_PYTHON="$(printf '%s' "$TARGET" | sed 's/.*python//')"
case "$TARGET" in
    linux-x86_64-python3.1[12]|linux-aarch64-python3.1[12]) ;;
    *) echo "unsupported target tuple: $TARGET" >&2; exit 1 ;;
esac

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64|amd64) HOST_ARCH=x86_64 ;;
    aarch64|arm64) HOST_ARCH=aarch64 ;;
esac
[ "$HOST_ARCH" = "$TUPLE_ARCH" ] \
    || { echo "target says $TUPLE_ARCH, this machine is $HOST_ARCH" >&2; exit 1; }

# The exact interpreter the tuple names, not the host default.
BUILD_PYTHON="$(command -v "python$TUPLE_PYTHON" || true)"
[ -n "$BUILD_PYTHON" ] \
    || { echo "target needs python$TUPLE_PYTHON; not on PATH" >&2; exit 1; }
BUILD_PYTHON_VERSION="$("$BUILD_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
[ "$BUILD_PYTHON_VERSION" = "$TUPLE_PYTHON" ] \
    || { echo "python$TUPLE_PYTHON reports $BUILD_PYTHON_VERSION" >&2; exit 1; }

# The version under test must be the version this commit declares. Run with
# the interpreter the tuple names: the host default may be older than the
# source supports, and failing there says nothing about the release.
"$BUILD_PYTHON" - "$RELEASE_VERSION" <<'PYIDENT'
import pathlib
import sys
import tomllib

sys.path.insert(0, ".")
from ori.security.release_bundles import ReleaseBundleError, distribution_version

requested = sys.argv[1]
declared = tomllib.loads(
    pathlib.Path("pyproject.toml").read_text(encoding="utf-8")
)["project"]["version"]
try:
    expected = distribution_version(requested)
except ReleaseBundleError as exc:
    sys.exit(f"{requested} is not a canonical release identity: {exc.detail}")
if expected != declared:
    sys.exit(f"{requested} needs pyproject version {expected!r}, found {declared!r}")
PYIDENT

"$BUILD_PYTHON" -m venv "$WORKDIR/venv" >/dev/null
# Hash-locked, from the same development requirements CI installs. Live PyPI
# resolution would put unpinned code into the tooling that signs the artifact.
"$WORKDIR/venv/bin/pip" install --quiet --require-hashes \
    -r "$SOURCE/requirements/dev.txt" >/dev/null
"$WORKDIR/venv/bin/pip" install --quiet --no-deps -e . >/dev/null
PY="$WORKDIR/venv/bin/python"

# --- ephemeral signing key, and the trust root that accepts it --------------
KEY="$WORKDIR/dev-key.pem"
"$PY" - "$KEY" "$SOURCE" <<'PYKEY'
import base64
import hashlib
import json
import pathlib
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

key_path, source = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
key = Ed25519PrivateKey.generate()  # ephemeral; never a release key
key_path.write_bytes(
    key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
)
public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
encoded = base64.b64encode(public).decode()

# Only in the extracted copy: the checkout's trust root is not touched.
registry = source / "ori" / "installer" / "release-keys.json"
document = json.loads(registry.read_text())
for entry in document["keys"]:
    entry["public_key_b64"] = encoded
registry.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
print(f"sha256:{hashlib.sha256(public).hexdigest()}")
PYKEY
KEY_FINGERPRINT="$("$PY" -c "
import base64, hashlib
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat
key = load_pem_private_key(open('$KEY','rb').read(), password=None)
raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
print('sha256:' + hashlib.sha256(raw).hexdigest())
")"
chmod 600 "$KEY"

# --- build, then sign -------------------------------------------------------
ORI_PYTHON="$PY" \
ORI_WHEELHOUSE_OUT="$WORKDIR/wheelhouse" ORI_WHEELHOUSE_TARGET=generic \
ORI_RELEASE_BUNDLE_VERSION="$RELEASE_VERSION" ORI_RELEASE_BUNDLE_TARGET="$TARGET" \
ORI_RELEASE_BUNDLE_OUT="$WORKDIR/bundle" \
SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" show -s --format=%ct "$FULL_COMMIT")" \
    bash scripts/build-wheelhouse.sh >"$WORKDIR/build.log" 2>&1 \
    || { tail -20 "$WORKDIR/build.log" >&2; exit 1; }

ARTIFACT_NAME="ori-runtime-$RELEASE_VERSION-$TARGET.tar.gz"
ARTIFACT="$WORKDIR/bundle/$ARTIFACT_NAME"
[ -f "$ARTIFACT" ] || { echo "bundle not produced: $ARTIFACT" >&2; exit 1; }

"$PY" scripts/sign-release-bundle.py \
    --artifact "$ARTIFACT" \
    --runtime-version "$RELEASE_VERSION" --target "$TARGET" \
    --key-id ori-runtime-release-2026-01 \
    --key-registry "$SOURCE/ori/installer/release-keys.json" \
    --private-key-file "$KEY" \
    --output "$ARTIFACT.signature.json" >/dev/null

cp "$ARTIFACT" "$ARTIFACT.signature.json" "$OUTDIR/"
cp "$SOURCE/ori/installer/release-keys.json" "$OUTDIR/release-keys.dev.json"

cat <<SUMMARY
=== LOCAL ARTIFACT ===
  source commit     $FULL_COMMIT
  archive sha256    $ARCHIVE_SHA256
  release version   $RELEASE_VERSION
  target            $TARGET
  build interpreter $BUILD_PYTHON ($BUILD_PYTHON_VERSION on $HOST_ARCH)
  artifact          $OUTDIR/$ARTIFACT_NAME
  artifact sha256   $(digest_of "$ARTIFACT")
  signature         $OUTDIR/$ARTIFACT_NAME.signature.json
  dev key           $KEY_FINGERPRINT  (ephemeral, discarded with this run)
  reproduce with    git archive --format=tar $FULL_COMMIT | sha256sum

  This artifact is development-signed. It proves nothing about KMS custody,
  the production trust root, publication, or authenticated download.
SUMMARY
