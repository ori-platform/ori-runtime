#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

# Ori Raspberry Pi Edge Node Setup Script
set -euo pipefail

if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y python3 python3-pip python3-venv sqlite3 curl i2c-tools
else
  echo "WARNING: apt-get not found; install Python, SQLite, curl, and I2C tools manually." >&2
fi

WHEELHOUSE_DIR="${ORI_WHEELHOUSE_DIR:-${HOME}/ori-wheelhouse}"
if [ ! -d "${WHEELHOUSE_DIR}" ]; then
  echo "ERROR: Signed Pi wheelhouse not found: ${WHEELHOUSE_DIR}" >&2
  echo "Production Pi installs must use a signed Ori wheelhouse, not live PyPI resolution." >&2
  echo "Set ORI_WHEELHOUSE_DIR to a directory containing wheels, requirements.txt, and requirements-pi.txt." >&2
  exit 1
fi

if [ ! -f "${WHEELHOUSE_DIR}/requirements.txt" ]; then
  echo "ERROR: ${WHEELHOUSE_DIR}/requirements.txt missing from wheelhouse." >&2
  exit 1
fi

if [ ! -f "${WHEELHOUSE_DIR}/requirements-pi.txt" ]; then
  echo "ERROR: ${WHEELHOUSE_DIR}/requirements-pi.txt missing from Pi wheelhouse." >&2
  echo "Build with: ORI_WHEELHOUSE_TARGET=pi bash scripts/build-wheelhouse.sh" >&2
  exit 1
fi

python3 -m pip --version
python3 -m pip install --break-system-packages --no-index --find-links "${WHEELHOUSE_DIR}" --require-hashes -r "${WHEELHOUSE_DIR}/requirements.txt"
python3 -m pip install --break-system-packages --no-index --find-links "${WHEELHOUSE_DIR}" --require-hashes -r "${WHEELHOUSE_DIR}/requirements-pi.txt"
python3 -m pip install --break-system-packages --no-index --find-links "${WHEELHOUSE_DIR}" --no-deps ori-runtime

echo "Setup complete. Run: ori-runtime --config ori.yaml"
