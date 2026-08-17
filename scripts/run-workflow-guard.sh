#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
# Launch the supply-chain guard with an interpreter that has the repository's
# hash-installed dependencies.
#
# pre-commit's `system` language runs whatever `python` the PATH resolves to,
# which locally is often not the virtualenv. Declaring the dependency in the
# hook instead would make pre-commit resolve it live and unhashed on every run.
# So the interpreter is selected here, and nothing is ever downloaded:
#
#   .venv/bin/python  — local development, where dependencies were installed
#                       from requirements/dev.txt
#   python            — CI, which installs the same file with --require-hashes
#                       before running pre-commit
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -x "${REPO_ROOT}/.venv/bin/python" ]; then
    INTERPRETER="${REPO_ROOT}/.venv/bin/python"
elif [ -n "${VIRTUAL_ENV:-}" ] && [ -x "${VIRTUAL_ENV}/bin/python" ]; then
    INTERPRETER="${VIRTUAL_ENV}/bin/python"
else
    INTERPRETER="python"
fi

if ! "${INTERPRETER}" -c "import yaml" >/dev/null 2>&1; then
    echo "supply-chain guard: PyYAML is unavailable to ${INTERPRETER}." >&2
    echo "Install the development dependencies first:" >&2
    echo "    bash scripts/bootstrap.sh" >&2
    echo "or, matching CI:" >&2
    echo "    pip install --require-hashes -r requirements/dev.txt" >&2
    echo "The guard will not install anything itself." >&2
    exit 1
fi

exec "${INTERPRETER}" "${REPO_ROOT}/scripts/check_workflows.py" "$@"
