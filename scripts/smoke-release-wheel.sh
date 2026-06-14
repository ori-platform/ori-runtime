#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Build the ori-runtime wheel, install it into a clean virtualenv, and verify
# the public integration boundary works from the installed artifact.
#
# This catches release-only failures that editable installs hide, especially
# missing bundled skill data needed by ori-energy/demo FastAPI consumers.

set -euo pipefail

PYTHON="${ORI_PYTHON:-python3}"
KEEP_TMP="${ORI_RELEASE_SMOKE_KEEP_TMP:-false}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "${ROOT}/pyproject.toml" ] || [ ! -f "${ROOT}/requirements.txt" ]; then
  echo "ERROR: run from a complete ori-runtime checkout." >&2
  exit 1
fi

if ! grep -q "sha256:" "${ROOT}/requirements.txt"; then
  echo "ERROR: requirements.txt must be hash-locked for release smoke tests." >&2
  exit 1
fi

"${PYTHON}" - <<'PY'
import importlib.util
import sys

if importlib.util.find_spec("build") is None:
    print("ERROR: Python package 'build' is required. Install requirements-dev.txt.", file=sys.stderr)
    raise SystemExit(1)
PY

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ori-release-smoke.XXXXXX")"
if [ "${KEEP_TMP}" != "true" ]; then
  trap 'rm -rf "${TMP_DIR}"' EXIT
else
  echo "Keeping release smoke temp dir: ${TMP_DIR}"
fi

DIST_DIR="${TMP_DIR}/dist"
VENV_DIR="${TMP_DIR}/venv"
RUN_DIR="${TMP_DIR}/run"
mkdir -p "${DIST_DIR}" "${RUN_DIR}"

echo "Building ori-runtime wheel..."
(cd "${ROOT}" && "${PYTHON}" -m build --wheel --no-isolation --outdir "${DIST_DIR}")

WHEEL="$(find "${DIST_DIR}" -maxdepth 1 -type f -name 'ori_runtime-*.whl' | head -n 1)"
if [ -z "${WHEEL}" ]; then
  echo "ERROR: ori-runtime wheel not found in ${DIST_DIR}" >&2
  exit 1
fi

echo "Creating clean install environment..."
"${PYTHON}" -m venv "${VENV_DIR}"
if [ -x "${VENV_DIR}/bin/python" ]; then
  VENV_PYTHON="${VENV_DIR}/bin/python"
else
  VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"
fi

echo "Installing hash-locked runtime dependencies..."
"${VENV_PYTHON}" -m pip install --require-hashes -r "${ROOT}/requirements.txt"

echo "Installing built wheel without dependency resolution..."
"${VENV_PYTHON}" -m pip install --no-deps "${WHEEL}"

echo "Verifying installed integration boundary and bundled skills..."
(
  cd "${RUN_DIR}"
  PYTHONPATH="" "${VENV_PYTHON}" - <<'PY'
import asyncio
import json
from pathlib import Path

import ori

from ori.integration import (
    RuleEvaluationRequest,
    bundled_skill_path,
    evaluate_sensor_reading,
)


async def main() -> None:
    typed_marker = Path(ori.__file__).resolve().parent / "py.typed"
    if not typed_marker.is_file():
        raise AssertionError(f"missing packaged PEP 561 marker: {typed_marker}")

    skill_path = bundled_skill_path("energy-anomaly-detector")
    path_text = str(skill_path)
    if "share/ori-runtime/skills/energy-anomaly-detector" not in path_text:
        raise AssertionError(f"bundled skill did not resolve from installed data files: {skill_path}")
    if not (skill_path / "skill.yaml").is_file():
        raise AssertionError(f"missing packaged skill.yaml: {skill_path}")
    if not (skill_path / "hooks.py").is_file():
        raise AssertionError(f"missing packaged hooks.py: {skill_path}")

    result = await evaluate_sensor_reading(
        RuleEvaluationRequest(
            sensor_id="main-circuit-current",
            sensor_type="current_clamp",
            value=52.0,
            unit="ampere",
            timestamp_ms=1_710_000_000_123,
            quality=1.0,
            device_id="release-smoke-device",
            metadata={"source": "release-wheel-smoke"},
        )
    )
    if not result.matched:
        raise AssertionError("expected dangerous_overcurrent rule to match")
    if result.action_tier != "D":
        raise AssertionError(f"expected Tier D, got {result.action_tier!r}")
    if result.trigger_name != "dangerous_overcurrent":
        raise AssertionError(f"unexpected trigger: {result.trigger_name!r}")
    if result.proof_threshold != 20.0:
        raise AssertionError(f"unexpected threshold: {result.proof_threshold!r}")

    print(json.dumps({
        "skill_path": path_text,
        "typed_marker": str(typed_marker),
        "trigger": result.trigger_name,
        "tier": result.action_tier,
        "threshold": result.proof_threshold,
        "latency_ms": result.latency_ms,
    }, sort_keys=True))


asyncio.run(main())
PY
)

echo "Release wheel smoke test passed: ${WHEEL}"
