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
#   ORI_WHEELHOUSE_TARGET=generic bash scripts/build-wheelhouse.sh
#   ORI_WHEELHOUSE_TARGET=phone-growatt bash scripts/build-wheelhouse.sh
#   ORI_WHEELHOUSE_TARGET=phone-victron bash scripts/build-wheelhouse.sh
#   ORI_WHEELHOUSE_TARGET=pi bash scripts/build-wheelhouse.sh
#   ORI_RELEASE_BUNDLE_VERSION=2.3.0 ORI_WHEELHOUSE_TARGET=generic \
#     bash scripts/build-wheelhouse.sh  # also build deterministic unsigned bundle
#
# Phone wheelhouses use requirements/phone.txt so Android/Termux deployments
# do not carry gateway MQTT, industrial protocol, Pi GPIO, or PC-control deps.
# Build production phone wheelhouses on Termux or a compatible trusted Android
# builder; wheels downloaded on macOS/Linux are useful for smoke tests only.
# Pi wheelhouses include platform-specific GPIO wheels. Build them on a
# Pi-compatible trusted Linux builder rather than on a phone or macOS host.
#
# The resulting directory can be:
#   - Copied to a device over SSH/USB
#   - Archived and signed with GPG before distribution
#   - Hosted on an internal artefact server
#
# Requirements:
#   pip>=23.0, pip-tools>=7.0 (both are in requirements/dev.txt)
#   Phone source-wheel builds also require local build tooling on the trusted
#   Termux/Android builder for native packages such as cryptography or aiohttp.
#
# Supply-chain posture:
#   - All dependency inputs are resolved with --require-hashes from requirements files.
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
elif [ "${TARGET}" = "phone" ]; then
  DEFAULT_OUT="$(pwd)/dist/ori-phone-wheelhouse"
elif [ "${TARGET}" = "phone-growatt" ]; then
  DEFAULT_OUT="$(pwd)/dist/ori-phone-growatt-wheelhouse"
elif [ "${TARGET}" = "phone-victron" ]; then
  DEFAULT_OUT="$(pwd)/dist/ori-phone-victron-wheelhouse"
else
  DEFAULT_OUT="$(pwd)/dist/ori-wheelhouse"
fi
OUT="${ORI_WHEELHOUSE_OUT:-${DEFAULT_OUT}}"
REQUIREMENTS="requirements/runtime.txt"
PHONE_REQUIREMENTS="requirements/phone.txt"
PHONE_GROWATT_REQUIREMENTS="requirements/phone-growatt.txt"
PHONE_VICTRON_REQUIREMENTS="requirements/phone-victron.txt"
PI_REQUIREMENTS="requirements/pi.txt"
PACKAGE_NAME="ori-runtime"
PROFILE_REQUIREMENTS=""

# ── Preflight ─────────────────────────────────────────────────────────────────

case "${TARGET}" in
  phone)
    ACTIVE_REQUIREMENTS="${PHONE_REQUIREMENTS}"
    ;;
  phone-growatt)
    ACTIVE_REQUIREMENTS="${PHONE_REQUIREMENTS}"
    PROFILE_REQUIREMENTS="${PHONE_GROWATT_REQUIREMENTS}"
    ;;
  phone-victron)
    ACTIVE_REQUIREMENTS="${PHONE_REQUIREMENTS}"
    PROFILE_REQUIREMENTS="${PHONE_VICTRON_REQUIREMENTS}"
    ;;
  generic)
    ACTIVE_REQUIREMENTS="${REQUIREMENTS}"
    ;;
  pi)
    ACTIVE_REQUIREMENTS="${REQUIREMENTS}"
    if [ ! -f "${PI_REQUIREMENTS}" ]; then
      echo "ERROR: ${PI_REQUIREMENTS} not found. Run from the repo root." >&2
      exit 1
    fi
    ;;
  *)
    echo "ERROR: unknown ORI_WHEELHOUSE_TARGET=${TARGET}; expected phone, phone-growatt, phone-victron, generic, or pi." >&2
    exit 1
    ;;
esac

if [ ! -f "${ACTIVE_REQUIREMENTS}" ]; then
  echo "ERROR: ${ACTIVE_REQUIREMENTS} not found. Run from the repo root." >&2
  exit 1
fi

if ! grep -q "sha256:" "${ACTIVE_REQUIREMENTS}"; then
  echo "ERROR: ${ACTIVE_REQUIREMENTS} does not contain hashes." >&2
  if [ "${ACTIVE_REQUIREMENTS}" = "${PHONE_REQUIREMENTS}" ]; then
    echo "Regenerate with: pip-compile --generate-hashes --output-file=requirements/phone.txt requirements/phone.in" >&2
  else
    echo "Regenerate with: pip-compile --generate-hashes requirements/runtime.in" >&2
  fi
  exit 1
fi

if [ -n "${PROFILE_REQUIREMENTS}" ]; then
  if [ ! -f "${PROFILE_REQUIREMENTS}" ]; then
    echo "ERROR: ${PROFILE_REQUIREMENTS} not found. Run from the repo root." >&2
    exit 1
  fi
  if ! grep -q "sha256:" "${PROFILE_REQUIREMENTS}"; then
    echo "ERROR: ${PROFILE_REQUIREMENTS} does not contain hashes." >&2
    echo "Regenerate with: pip-compile --generate-hashes --output-file=${PROFILE_REQUIREMENTS} ${PROFILE_REQUIREMENTS%.txt}.in" >&2
    exit 1
  fi
fi

if [ "${TARGET}" = "pi" ] && ! grep -q "sha256:" "${PI_REQUIREMENTS}"; then
  echo "ERROR: ${PI_REQUIREMENTS} does not contain hashes." >&2
  echo "Regenerate with: pip-compile --generate-hashes requirements/pi.in" >&2
  exit 1
fi

"${PYTHON}" -m pip --version >/dev/null 2>&1 || { echo "ERROR: ${PYTHON} not found." >&2; exit 1; }

# ── Build ─────────────────────────────────────────────────────────────────────

echo "Building Ori wheelhouse → ${OUT}"
echo "  Target: ${TARGET}"
echo "  Python: $("${PYTHON}" --version)"
echo "  Source: ${ACTIVE_REQUIREMENTS}"
if [ "${TARGET}" = "pi" ]; then
  echo "  Pi source: ${PI_REQUIREMENTS}"
elif [ -n "${PROFILE_REQUIREMENTS}" ]; then
  echo "  Profile source: ${PROFILE_REQUIREMENTS}"
fi
echo ""

rm -rf "${OUT}"
mkdir -p "${OUT}"

# 1. Build or download all dependency wheels with hash verification.
#
# Generic/Pi targets intentionally require upstream binary wheels. Phone
# wheelhouses are different: Android/Termux often has no compatible PyPI wheel
# for native packages, so the trusted phone builder must be allowed to compile
# platform-local wheels from the hash-locked source distributions.
if [[ "${TARGET}" == phone* ]]; then
  echo "Building phone dependency wheels from hash-locked inputs..."
  "${PYTHON}" -m pip wheel \
    --require-hashes \
    --no-build-isolation \
    --wheel-dir "${OUT}" \
    -r "${ACTIVE_REQUIREMENTS}"
  if [ -n "${PROFILE_REQUIREMENTS}" ]; then
    echo "Building phone profile dependency wheels from hash-locked inputs..."
    "${PYTHON}" -m pip wheel \
      --require-hashes \
      --no-build-isolation \
      --wheel-dir "${OUT}" \
      -r "${PROFILE_REQUIREMENTS}"
  fi
else
  echo "Downloading dependency wheels (hash-locked, binary-only)..."
  "${PYTHON}" -m pip download \
    --require-hashes \
    --only-binary=:all: \
    --dest "${OUT}" \
    -r "${ACTIVE_REQUIREMENTS}"
fi

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

# 3. Bundle the hash-locked requirements so the device can verify on install.
#
# For phone builds, requirements/phone.txt is the source/build lockfile. If a
# Termux builder compiles a local wheel from a hashed sdist, the resulting wheel
# has a new SHA256. The install requirements must therefore be generated from
# the actual wheelhouse contents, while the source lockfile is copied alongside
# it for provenance.
if [[ "${TARGET}" == phone* ]]; then
  echo "Writing phone install requirements from built wheels..."
  "${PYTHON}" - "${OUT}" "${PACKAGE_NAME}" > "${OUT}/requirements.txt" <<'PY'
import hashlib
import sys
import zipfile
from pathlib import Path

wheelhouse = Path(sys.argv[1])
package_name = sys.argv[2].lower().replace("_", "-")


def _metadata_for_wheel(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as zf:
        metadata_name = next(
            (name for name in zf.namelist() if name.endswith(".dist-info/METADATA")),
            "",
        )
        if not metadata_name:
            raise SystemExit(f"ERROR: missing METADATA in wheel: {path.name}")
        metadata = zf.read(metadata_name).decode("utf-8")

    name = ""
    version = ""
    for line in metadata.splitlines():
        if line.startswith("Name: "):
            name = line.removeprefix("Name: ").strip()
        elif line.startswith("Version: "):
            version = line.removeprefix("Version: ").strip()
    if not name or not version:
        raise SystemExit(f"ERROR: missing Name/Version metadata in wheel: {path.name}")
    return name, version


rows: list[tuple[str, str, str]] = []
for wheel in sorted(wheelhouse.glob("*.whl")):
    name, version = _metadata_for_wheel(wheel)
    if name.lower().replace("_", "-") == package_name:
        continue
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    rows.append((name, version, digest))

if not rows:
    raise SystemExit("ERROR: no dependency wheels found for phone requirements.")

print("#")
print("# This file is generated by scripts/build-wheelhouse.sh for this")
print("# phone wheelhouse. It hashes the actual built/downloaded wheels,")
print("# not the source distributions in requirements/phone.txt.")
print("#")
for name, version, digest in rows:
    print(f"{name}=={version} \\")
    print(f"    --hash=sha256:{digest}")
PY
else
  cp "${ACTIVE_REQUIREMENTS}" "${OUT}/requirements.txt"
fi
if [[ "${TARGET}" == phone* ]]; then
  cp "${PHONE_REQUIREMENTS}" "${OUT}/requirements-phone.txt"
  if [ -n "${PROFILE_REQUIREMENTS}" ]; then
    if [ "${PROFILE_REQUIREMENTS}" = "${PHONE_GROWATT_REQUIREMENTS}" ]; then
      cp "${PROFILE_REQUIREMENTS}" "${OUT}/requirements-phone-growatt.txt"
    elif [ "${PROFILE_REQUIREMENTS}" = "${PHONE_VICTRON_REQUIREMENTS}" ]; then
      cp "${PROFILE_REQUIREMENTS}" "${OUT}/requirements-phone-victron.txt"
    fi
  fi
fi
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
  echo "# Source: ${ACTIVE_REQUIREMENTS}"
  if [ "${TARGET}" = "pi" ]; then
    echo "# Pi source: ${PI_REQUIREMENTS}"
  elif [ -n "${PROFILE_REQUIREMENTS}" ]; then
    echo "# Profile source: ${PROFILE_REQUIREMENTS}"
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

# 5. Optionally assemble the exact unsigned Linux release bundle. Signing is a
# separate purpose-bound operation performed only by the approved release
# signing environment; this build path never reads private key material.
if [ -n "${ORI_RELEASE_BUNDLE_VERSION:-}" ]; then
  if [ "${TARGET}" != "generic" ] && [ "${TARGET}" != "pi" ]; then
    echo "ERROR: Linux release bundles require ORI_WHEELHOUSE_TARGET=generic or pi." >&2
    exit 1
  fi

  MACHINE_ARCH="$(uname -m)"
  case "${MACHINE_ARCH}" in
    x86_64|amd64)
      RELEASE_ARCH="x86_64"
      ;;
    aarch64|arm64)
      RELEASE_ARCH="aarch64"
      ;;
    *)
      echo "ERROR: unsupported Linux release architecture: ${MACHINE_ARCH}" >&2
      exit 1
      ;;
  esac
  PYTHON_MINOR="$(${PYTHON} -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
  RELEASE_TARGET="${ORI_RELEASE_BUNDLE_TARGET:-linux-${RELEASE_ARCH}-python${PYTHON_MINOR}}"
  RELEASE_OUT="${ORI_RELEASE_BUNDLE_OUT:-$(pwd)/dist/releases}"

  echo "Building deterministic unsigned Runtime release bundle..."
  "${PYTHON}" scripts/build_release_bundle.py \
    --wheelhouse "${OUT}" \
    --runtime-version "${ORI_RELEASE_BUNDLE_VERSION}" \
    --target "${RELEASE_TARGET}" \
    --config-template ori.linux.yaml.example \
    --service-template packaging/systemd/ori-runtime.service.in \
    --output-dir "${RELEASE_OUT}"
  echo "Unsigned bundle built. Sign only in the approved release signing environment."
fi
