#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

FROM_REF="${1:-}"
TO_REF="${2:-}"
PR_BODY_TEXT="${GUARD_CAP_MATRIX_BYPASS_TEXT:-}"

if [[ -z "${FROM_REF}" || -z "${TO_REF}" ]]; then
  echo "Capability matrix guard: missing refs. Usage:"
  echo "  scripts/guard-capability-matrix.sh <from_ref> <to_ref>"
  exit 0
fi

if ! git cat-file -e "${FROM_REF}^{commit}" 2>/dev/null || ! git cat-file -e "${TO_REF}^{commit}" 2>/dev/null; then
  echo "Capability matrix guard: refs unavailable (from=${FROM_REF} to=${TO_REF}); skipping."
  exit 0
fi

changed_files="$(git diff --name-only "${FROM_REF}" "${TO_REF}")"

if [[ -z "${changed_files}" ]]; then
  echo "Capability matrix guard: no file changes detected."
  exit 0
fi

capability_touched="$(echo "${changed_files}" | grep -E '^(ori/reasoning/|ori/actions/|ori/runtime\.py$|ori/skills/loader\.py$|ori/config\.py$)' || true)"
matrix_touched="$(echo "${changed_files}" | grep -E '^docs/CAPABILITY_MATRIX\.md$' || true)"
bypass_requested=""

if [[ -n "${PR_BODY_TEXT}" ]] && printf '%s' "${PR_BODY_TEXT}" | grep -Eiq '\[skip-cap-matrix\]'; then
  bypass_requested="1"
fi

if [[ -n "${capability_touched}" && -z "${matrix_touched}" ]]; then
  if [[ -n "${bypass_requested}" ]]; then
    echo "Capability matrix guard: bypassed via PR body token [skip-cap-matrix]."
    echo
    echo "Changed capability-impacting files:"
    echo "${capability_touched}" | sed 's/^/  - /'
    exit 0
  fi

  echo "ERROR: Capability-impacting files changed, but docs/CAPABILITY_MATRIX.md was not updated."
  echo
  echo "Changed capability-impacting files:"
  echo "${capability_touched}" | sed 's/^/  - /'
  echo
  echo "Please update docs/CAPABILITY_MATRIX.md in the same PR."
  echo "If this PR is truly non-capability-impacting, add [skip-cap-matrix] to the PR body."
  exit 1
fi

echo "Capability matrix guard: OK."
