#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Refresh the vendored ori-specs evidence vectors.
#
# The vectors are vendored rather than fetched at test time so the suite is
# hermetic and works offline, which is the same reason the firmware repository
# carries its own copies. The cost of vendoring is drift: upstream can change
# without anything here noticing. This script is how that is detected, and it
# reports rather than silently overwrites.
#
# Two sets are vendored, and they move together — an envelope wraps a chain
# row, so a change to one is usually a change to both.
#
# Usage:
#   bash scripts/refresh-evidence-vectors.sh            # report drift only
#   ORI_VECTORS_APPLY=1 bash scripts/refresh-evidence-vectors.sh   # update
#
# ORI_SPECS_DIR points at a local ori-specs checkout; otherwise the public
# repository is cloned into a temporary directory.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY="${ORI_VECTORS_APPLY:-0}"
CLEANUP=""

# "<path in ori-specs>:<path in this repo>"
SETS=(
  "evidence/vectors:tests/vectors/evidence_v2"
  "evidence-exchange/vectors:tests/vectors/evidence_exchange"
  "runtime-evidence-anchor/vectors:tests/vectors/runtime_evidence_anchor"
  # Receiver-state vectors are a separate set because the copy loop below is a
  # flat glob. They cover the rules a wire artifact cannot express -- the ones
  # a byte-level suite silently omits, and therefore the ones most worth
  # drift-checking.
  "evidence-exchange/vectors/receiver-state:tests/vectors/evidence_exchange_receiver_state"
)

if [ -n "${ORI_SPECS_DIR:-}" ]; then
  SPECS="${ORI_SPECS_DIR}"
else
  SPECS="$(mktemp -d)"
  CLEANUP="${SPECS}"
  git clone --quiet --depth 1 https://github.com/ori-platform/ori-specs.git "${SPECS}"
fi
trap '[ -n "${CLEANUP}" ] && rm -rf "${CLEANUP}"' EXIT

COMMIT="$(git -C "${SPECS}" rev-parse HEAD)"
overall_drift=0

write_manifest() {
  python3 - "$1" "$2" "$3" <<'PY'
import hashlib, json, pathlib, sys
commit, source, dest = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
(dest / "MANIFEST.json").write_text(json.dumps({
    "source_repository": "ori-platform/ori-specs",
    "source_path": source,
    "source_commit": commit,
    "note": ("Vendored copies of the normative vectors. The runtime must produce and "
             "accept the bytes they describe, so they are its conformance fixtures. "
             "Digests detect a local edit; the source commit is the provenance trail."),
    "files": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(dest.glob("*.json")) if p.name != "MANIFEST.json"},
}, indent=2) + "\n")
PY
}

for entry in "${SETS[@]}"; do
  SRC="${SPECS}/${entry%%:*}"
  DEST="${REPO}/${entry##*:}"
  label="${entry%%:*}"
  test -d "${SRC}" || { echo "no vectors at ${SRC}" >&2; exit 1; }
  mkdir -p "${DEST}"

  drift=0
  for file in "${SRC}"/*.json; do
    name="$(basename "${file}")"
    if [ ! -f "${DEST}/${name}" ]; then
      echo "NEW      ${label}/${name}"; drift=1; continue
    fi
    cmp -s "${file}" "${DEST}/${name}" || { echo "CHANGED  ${label}/${name}"; drift=1; }
  done
  for file in "${DEST}"/*.json; do
    name="$(basename "${file}")"
    [ "${name}" = "MANIFEST.json" ] && continue
    [ -f "${SRC}/${name}" ] || { echo "REMOVED  ${label}/${name}"; drift=1; }
  done

  # Contents matching is not the whole story. The manifest also records which
  # ori-specs commit the vectors came from, and that pin is the cross-repository
  # provenance trail. A squash merge rewrites the commit while leaving every
  # byte identical, so a contents-only check reports "match" and leaves the
  # manifest naming a commit that no longer exists on main — provenance
  # pointing at nothing, which is worse than no pin because it looks
  # authoritative.
  PINNED=""
  if [ -f "${DEST}/MANIFEST.json" ]; then
    PINNED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_commit"])' \
      "${DEST}/MANIFEST.json" 2>/dev/null || echo "")"
  fi

  if [ "${drift}" -eq 0 ] && [ "${PINNED}" = "${COMMIT}" ]; then
    echo "${label}: vectors match ori-specs at ${COMMIT}"
    continue
  fi

  if [ "${APPLY}" != "1" ]; then
    if [ "${drift}" -eq 0 ]; then
      echo "${label}: contents match, but the manifest pins ${PINNED:-<none>}" >&2
      echo "  and ori-specs is now at ${COMMIT}." >&2
    fi
    overall_drift=1
    continue
  fi

  # Reconcile the whole set, not just additions and changes. Copying alone
  # would leave a vector upstream had deleted sitting in the destination,
  # where it would be re-recorded in the manifest and reported again forever.
  for file in "${DEST}"/*.json; do
    name="$(basename "${file}")"
    [ "${name}" = "MANIFEST.json" ] && continue
    [ -f "${SRC}/${name}" ] || { rm -f "${file}"; echo "deleted  ${label}/${name}"; }
  done
  cp "${SRC}"/*.json "${DEST}/"
  write_manifest "${COMMIT}" "${entry%%:*}" "${DEST}"
  echo "${label}: updated to ${COMMIT}"
done

if [ "${overall_drift}" -ne 0 ]; then
  echo >&2
  echo "Vendored vectors differ from ori-specs at ${COMMIT}." >&2
  echo "Re-run with ORI_VECTORS_APPLY=1 to update, then review the diff:" >&2
  echo "  a vector change is a contract change, not a refresh." >&2
  exit 1
fi
