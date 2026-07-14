#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Build the ori-runtime wheel, install it into a clean virtualenv, and verify
# the public integration boundary works from the installed artifact.
#
# This catches release-only failures that editable installs hide, especially
# missing bundled skill data needed by downstream API consumers.

set -euo pipefail

PYTHON="${ORI_PYTHON:-python3}"
KEEP_TMP="${ORI_RELEASE_SMOKE_KEEP_TMP:-false}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ ! -f "${ROOT}/pyproject.toml" ] || [ ! -f "${ROOT}/requirements/runtime.txt" ]; then
  echo "ERROR: run from a complete ori-runtime checkout." >&2
  exit 1
fi

if ! grep -q "sha256:" "${ROOT}/requirements/runtime.txt"; then
  echo "ERROR: requirements/runtime.txt must be hash-locked for release smoke tests." >&2
  exit 1
fi

"${PYTHON}" - <<'PY'
import importlib.util
import sys

if importlib.util.find_spec("build") is None:
    print("ERROR: Python package 'build' is required. Install requirements/dev.txt.", file=sys.stderr)
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

echo "Verifying wheel dependency metadata..."
"${PYTHON}" - "${WHEEL}" <<'PY'
import sys
import zipfile
from pathlib import Path
import re

wheel = Path(sys.argv[1])
metadata_name = ""
with zipfile.ZipFile(wheel) as zf:
    for name in zf.namelist():
        if name.endswith(".dist-info/METADATA"):
            metadata_name = name
            break
    if not metadata_name:
        raise AssertionError(f"missing METADATA in {wheel}")
    metadata = zf.read(metadata_name).decode("utf-8")

requires = [
    line.removeprefix("Requires-Dist: ").strip()
    for line in metadata.splitlines()
    if line.startswith("Requires-Dist: ")
]
base_requires = [req for req in requires if "extra ==" not in req]
dep_name_re = re.compile(r"^[A-Za-z0-9_.-]+")


def dependency_name(requirement):
    match = dep_name_re.match(requirement)
    if match is None:
        raise AssertionError(f"could not parse dependency name from {requirement!r}")
    return match.group(0).lower()


base_names = {dependency_name(req) for req in base_requires}
if base_names != {"pyyaml"}:
    raise AssertionError(
        "base ori-runtime install must stay slim for downstream API consumers; "
        f"got base dependencies: {base_requires}"
    )

for forbidden in (
    "paho-mqtt",
    "psutil",
    "pyserial",
    "asyncua",
    "cryptography",
    "twilio",
    "africastalking",
    "httpx",
):
    if forbidden in base_names:
        raise AssertionError(f"{forbidden} must not be a base dependency")

runtime_extra = [
    req
    for req in requires
    if 'extra == "runtime"' in req or "extra == 'runtime'" in req
]
for expected in ("paho-mqtt", "cryptography", "africastalking"):
    if not any(req.lower().startswith(expected) for req in runtime_extra):
        raise AssertionError(
            f"runtime extra is missing {expected!r}; got {runtime_extra}"
        )

print(
    "Wheel dependency metadata ok:",
    {
        "base": sorted(base_requires),
        "runtime_extra_count": len(runtime_extra),
    },
)
PY

echo "Creating clean install environment..."
"${PYTHON}" -m venv "${VENV_DIR}"
if [ -x "${VENV_DIR}/bin/python" ]; then
  VENV_PYTHON="${VENV_DIR}/bin/python"
else
  VENV_PYTHON="${VENV_DIR}/Scripts/python.exe"
fi

echo "Installing hash-locked runtime dependencies..."
"${VENV_PYTHON}" -m pip install --require-hashes -r "${ROOT}/requirements/runtime.txt"

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
