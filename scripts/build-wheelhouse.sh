#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Build a signed Ori runtime wheelhouse for offline device deployment.
#
# The wheelhouse is the offline package store that install-phone.sh and
# install-pi.sh pull from.  It contains every wheel that Ori needs plus
# a hash-locked requirements.txt.  Devices install from the wheelhouse
# with --no-index --require-hashes, never from live PyPI.
#
# Usage:
#   bash scripts/build-wheelhouse.sh                        # default output: dist/ori-wheelhouse/
#   ORI_WHEELHOUSE_OUT=/tmp/wh bash scripts/build-wheelhouse.sh
#   ORI_PYTHON=python3.12 bash scripts/build-wheelhouse.sh  # pin Python version
#
# The resulting directory can be:
#   - Copied to a device over SSH/USB
#   - Archived and signed with GPG before distribution
#   - Hosted on an internal artefact server
#
# Requirements:
#   pip>=23.0, pip-tools>=7.0 (both are in requirements-dev.txt)
#
# Supply-chain posture:
#   - All wheels are downloaded with --require-hashes from requirements.txt.
#   - The hash-locked requirements.txt is bundled into the wheelhouse so
#     install-phone.sh can re-verify on every device install.
#   - This script must only be run in a clean, trusted environment.
#     Never run it in a workflow that restores a dependency cache or has
#     id-token: write.  See AGENTS.md Supply Chain Invariant 4.

set -euo pipefail

PYTHON="${ORI_PYTHON:-python3}"
OUT="${ORI_WHEELHOUSE_OUT:-$(pwd)/dist/ori-wheelhouse}"
REQUIREMENTS="requirements.txt"
PACKAGE_NAME="ori-runtime"

# ── Preflight ─────────────────────────────────────────────────────────────────

if [ ! -f "${REQUIREMENTS}" ]; then
  echo "ERROR: ${REQUIREMENTS} not found. Run from the repo root." >&2
  exit 1
fi

if ! grep -q "sha256:" "${REQUIREMENTS}"; then
  echo "ERROR: ${REQUIREMENTS} does not contain hashes." >&2
  echo "Regenerate with: pip-compile --generate-hashes requirements.in" >&2
  exit 1
fi

"${PYTHON}" -m pip --version >/dev/null 2>&1 || { echo "ERROR: ${PYTHON} not found." >&2; exit 1; }

# ── Build ─────────────────────────────────────────────────────────────────────

echo "Building Ori wheelhouse → ${OUT}"
echo "  Python: $("${PYTHON}" --version)"
echo "  Source: ${REQUIREMENTS}"
echo ""

rm -rf "${OUT}"
mkdir -p "${OUT}"

# 1. Download all dependency wheels with hash verification
echo "Downloading dependency wheels (hash-locked)..."
"${PYTHON}" -m pip download \
  --require-hashes \
  --only-binary=:all: \
  --dest "${OUT}" \
  -r "${REQUIREMENTS}"

# 2. Build the ori-runtime wheel itself
echo "Building ${PACKAGE_NAME} wheel..."
"${PYTHON}" -m pip wheel \
  --no-deps \
  --wheel-dir "${OUT}" \
  .

# 3. Bundle the hash-locked requirements so the device can verify on install
cp "${REQUIREMENTS}" "${OUT}/requirements.txt"

# 4. Write a manifest so operators can verify the wheelhouse contents
echo "Writing wheelhouse manifest..."
{
  echo "# Ori Runtime Wheelhouse Manifest"
  echo "# Built: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "# Python: $("${PYTHON}" --version 2>&1)"
  echo "# Source: ${REQUIREMENTS}"
  echo ""
  echo "# SHA256 checksums of all wheel files:"
  for wheel in "${OUT}"/*.whl; do
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "${wheel}"
    elif command -v shasum >/dev/null 2>&1; then
      shasum -a 256 "${wheel}"
    fi
  done
} > "${OUT}/MANIFEST.sha256"

echo ""
echo "Wheelhouse built successfully: ${OUT}"
echo "  $(find "${OUT}" -name "*.whl" | wc -l | tr -d ' ') wheels"
echo "  MANIFEST.sha256 — verify before shipping to devices"
echo ""
echo "Deploy to a device:"
echo "  rsync -av ${OUT}/ pi@device:~/ori-wheelhouse/"
echo "  ORI_WHEELHOUSE_DIR=~/ori-wheelhouse bash scripts/install-phone.sh"
