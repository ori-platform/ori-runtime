#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Build a signed Ori runtime wheelhouse for offline device deployment.
#
# The wheelhouse is the offline package store that install-phone.sh and
# install-pi.sh pull from.  It contains every wheel that Ori needs plus
# hash-locked requirements files.  Devices install from the wheelhouse
# with --no-index --require-hashes, never from live PyPI.
#
# Usage:
#   bash scripts/build-wheelhouse.sh                        # default output: dist/ori-wheelhouse/
#   ORI_WHEELHOUSE_OUT=/tmp/wh bash scripts/build-wheelhouse.sh
#   ORI_PYTHON=python3.12 bash scripts/build-wheelhouse.sh  # pin Python version
#   ORI_WHEELHOUSE_TARGET=pi bash scripts/build-wheelhouse.sh
#
# Pi wheelhouses include platform-specific GPIO wheels. Build them on a
# Pi-compatible trusted Linux builder rather than on a phone or macOS host.
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
#   - All wheels are downloaded with --require-hashes from requirements files.
#   - Hash-locked requirements are bundled into the wheelhouse so device
#     installers can re-verify on every install.
#   - This script must only be run in a clean, trusted environment.
#     Never run it in a workflow that restores a dependency cache or has
#     id-token: write.  See AGENTS.md Supply Chain Invariant 4.

set -euo pipefail

PYTHON="${ORI_PYTHON:-python3}"
TARGET="${ORI_WHEELHOUSE_TARGET:-phone}"
if [ "${TARGET}" = "pi" ]; then
  DEFAULT_OUT="$(pwd)/dist/ori-pi-wheelhouse"
else
  DEFAULT_OUT="$(pwd)/dist/ori-wheelhouse"
fi
OUT="${ORI_WHEELHOUSE_OUT:-${DEFAULT_OUT}}"
REQUIREMENTS="requirements.txt"
PI_REQUIREMENTS="requirements-pi.txt"
PACKAGE_NAME="ori-runtime"

# ── Preflight ─────────────────────────────────────────────────────────────────

if [ ! -f "${REQUIREMENTS}" ]; then
  echo "ERROR: ${REQUIREMENTS} not found. Run from the repo root." >&2
  exit 1
fi

case "${TARGET}" in
  phone|generic)
    ;;
  pi)
    if [ ! -f "${PI_REQUIREMENTS}" ]; then
      echo "ERROR: ${PI_REQUIREMENTS} not found. Run from the repo root." >&2
      exit 1
    fi
    ;;
  *)
    echo "ERROR: unknown ORI_WHEELHOUSE_TARGET=${TARGET}; expected phone, generic, or pi." >&2
    exit 1
    ;;
esac

if ! grep -q "sha256:" "${REQUIREMENTS}"; then
  echo "ERROR: ${REQUIREMENTS} does not contain hashes." >&2
  echo "Regenerate with: pip-compile --generate-hashes requirements.in" >&2
  exit 1
fi

if [ "${TARGET}" = "pi" ] && ! grep -q "sha256:" "${PI_REQUIREMENTS}"; then
  echo "ERROR: ${PI_REQUIREMENTS} does not contain hashes." >&2
  echo "Regenerate with: pip-compile --generate-hashes requirements-pi.in" >&2
  exit 1
fi

"${PYTHON}" -m pip --version >/dev/null 2>&1 || { echo "ERROR: ${PYTHON} not found." >&2; exit 1; }

# ── Build ─────────────────────────────────────────────────────────────────────

echo "Building Ori wheelhouse → ${OUT}"
echo "  Target: ${TARGET}"
echo "  Python: $("${PYTHON}" --version)"
echo "  Source: ${REQUIREMENTS}"
if [ "${TARGET}" = "pi" ]; then
  echo "  Pi source: ${PI_REQUIREMENTS}"
fi
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

if [ "${TARGET}" = "pi" ]; then
  echo "Downloading Raspberry Pi hardware wheels (hash-locked)..."
  "${PYTHON}" -m pip download \
    --require-hashes \
    --only-binary=:all: \
    --dest "${OUT}" \
    -r "${PI_REQUIREMENTS}"
fi

# 2. Build the ori-runtime wheel itself
echo "Building ${PACKAGE_NAME} wheel..."
"${PYTHON}" -m pip wheel \
  --no-deps \
  --wheel-dir "${OUT}" \
  .

# 3. Bundle the hash-locked requirements so the device can verify on install
cp "${REQUIREMENTS}" "${OUT}/requirements.txt"
if [ "${TARGET}" = "pi" ]; then
  cp "${PI_REQUIREMENTS}" "${OUT}/requirements-pi.txt"
fi

# 4. Write a manifest so operators can verify the wheelhouse contents
echo "Writing wheelhouse manifest..."
{
  echo "# Ori Runtime Wheelhouse Manifest"
  echo "# Built: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "# Python: $("${PYTHON}" --version 2>&1)"
  echo "# Target: ${TARGET}"
  echo "# Source: ${REQUIREMENTS}"
  if [ "${TARGET}" = "pi" ]; then
    echo "# Pi source: ${PI_REQUIREMENTS}"
  fi
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
if [ "${TARGET}" = "pi" ]; then
  echo "  rsync -av ${OUT}/ pi@device:~/ori-wheelhouse/"
  echo "  ORI_WHEELHOUSE_DIR=~/ori-wheelhouse bash scripts/install-pi.sh"
else
  echo "  rsync -av ${OUT}/ phone:~/ori-wheelhouse/"
  echo "  ORI_WHEELHOUSE_DIR=~/ori-wheelhouse bash scripts/install-phone.sh"
fi
