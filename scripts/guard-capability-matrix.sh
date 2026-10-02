#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

FROM_REF="${1:-}"
TO_REF="${2:-}"
PR_BODY_TEXT="${GUARD_CAP_MATRIX_BYPASS_TEXT:-}"

# Code whose behaviour the capability matrix describes.
CAPABILITY_PATHS='^(ori/reasoning/|ori/actions/|ori/security/|ori/safety/|ori/policy/|ori/runtime\.py$|ori/skills/loader\.py$|ori/config\.py$)'

# A bypass is a line of its own: the token first, then a rationale of at least
# twenty characters. The token quoted anywhere else, as the pull request
# template does, is not a bypass.
BYPASS_LINE='^[[:space:]]*\[skip-cap-matrix\][[:space:]]*[:-]?[[:space:]]*[^[:space:]].{19,}$'

if [[ -z "${FROM_REF}" || -z "${TO_REF}" ]]; then
  echo "ERROR: Capability matrix guard needs two refs:" >&2
  echo "  scripts/guard-capability-matrix.sh <from_ref> <to_ref>" >&2
  exit 2
fi

for ref in "${FROM_REF}" "${TO_REF}"; do
  if ! git cat-file -e "${ref}^{commit}" 2>/dev/null; then
    echo "ERROR: Capability matrix guard: ${ref} is not a commit in this checkout." >&2
    echo "Fetch it (CI checks out with fetch-depth: 0) rather than skipping the guard." >&2
    exit 2
  fi
done

changed_files="$(git diff --name-only "${FROM_REF}" "${TO_REF}")"

if [[ -z "${changed_files}" ]]; then
  echo "Capability matrix guard: no file changes detected."
  exit 0
fi

capability_touched="$(echo "${changed_files}" | grep -E "${CAPABILITY_PATHS}" || true)"
matrix_touched="$(echo "${changed_files}" | grep -E '^docs/CAPABILITY_MATRIX\.md$' || true)"
bypass_line=""
if [[ -n "${PR_BODY_TEXT}" ]]; then
  bypass_line="$(printf '%s\n' "${PR_BODY_TEXT}" | tr -d '\r' | grep -Ei -m1 "${BYPASS_LINE}" || true)"
fi

if [[ -n "${capability_touched}" && -z "${matrix_touched}" ]]; then
  if [[ -n "${bypass_line}" ]]; then
    echo "Capability matrix guard: bypassed by the PR body:"
    echo "  ${bypass_line}"
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
  echo "If the change truly does not alter a capability, start a line of the PR body"
  echo "with the bypass token followed by at least twenty characters saying why."
  echo "The token quoted inside other text, such as the template checklist, does not count."
  exit 1
fi

echo "Capability matrix guard: OK."
