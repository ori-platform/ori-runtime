#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

if [[ -n "${VIRTUAL_ENV:-}" ]]; then
  PYTHON_BIN="${VIRTUAL_ENV}/bin/python"
else
  PYTHON_BIN="${PYTHON_BIN:-python3}"
fi

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "Error: Python executable not found: ${PYTHON_BIN}" >&2
  exit 1
fi

echo "Using Python: $(${PYTHON_BIN} --version)"

echo "Installing hash-locked project dependencies..."
"${PYTHON_BIN}" -m pip --version
"${PYTHON_BIN}" -m pip install --require-hashes -r requirements-dev.txt
"${PYTHON_BIN}" -m pip install --no-deps -e .

echo "Installing git hooks..."
"${PYTHON_BIN}" -m pre_commit install --install-hooks --hook-type pre-commit --hook-type pre-push --hook-type commit-msg

echo "Running pre-commit baseline pass..."
if ! "${PYTHON_BIN}" -m pre_commit run --all-files; then
  echo "pre-commit reported fixes or issues; re-running to verify clean state..."
  "${PYTHON_BIN}" -m pre_commit run --all-files
fi

cat <<'MSG'
Bootstrap complete.

Next steps:
  1) Run tests: pytest tests/ -v
  2) Start runtime: python -m ori.runtime --config ori.yaml
MSG
