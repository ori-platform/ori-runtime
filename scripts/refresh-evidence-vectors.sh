#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Refresh the vendored ori-specs evidence/v2 vectors.
#
# The vectors are vendored rather than fetched at test time so the suite is
# hermetic and works offline, which is the same reason the firmware repository
# carries its own copies. The cost of vendoring is drift: upstream can change
# without anything here noticing. This script is how that is detected, and it
# reports rather than silently overwrites.
#
# Usage:
#   bash scripts/refresh-evidence-vectors.sh            # report drift only
#   ORI_VECTORS_APPLY=1 bash scripts/refresh-evidence-vectors.sh   # update
#
# ORI_SPECS_DIR points at a local ori-specs checkout; otherwise the public
# repository is cloned into a temporary directory.

set -euo pipefail

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tests/vectors/evidence_v2"
APPLY="${ORI_VECTORS_APPLY:-0}"
CLEANUP=""

if [ -n "${ORI_SPECS_DIR:-}" ]; then
  SPECS="${ORI_SPECS_DIR}"
else
  SPECS="$(mktemp -d)"
  CLEANUP="${SPECS}"
  git clone --quiet --depth 1 https://github.com/ori-platform/ori-specs.git "${SPECS}"
fi
trap '[ -n "${CLEANUP}" ] && rm -rf "${CLEANUP}"' EXIT

SRC="${SPECS}/evidence/vectors"
test -d "${SRC}" || { echo "no vectors at ${SRC}" >&2; exit 1; }
COMMIT="$(git -C "${SPECS}" rev-parse HEAD)"

drift=0
for file in "${SRC}"/*.json; do
  name="$(basename "${file}")"
  if [ ! -f "${DEST}/${name}" ]; then
    echo "NEW      ${name}"; drift=1; continue
  fi
  if ! cmp -s "${file}" "${DEST}/${name}"; then
    echo "CHANGED  ${name}"; drift=1
  fi
done
for file in "${DEST}"/*.json; do
  name="$(basename "${file}")"
  [ "${name}" = "MANIFEST.json" ] && continue
  [ -f "${SRC}/${name}" ] || { echo "REMOVED  ${name}"; drift=1; }
done

# Contents matching is not the whole story. The manifest also records which
# ori-specs commit the vectors came from, and that pin is the cross-repository
# provenance trail. A squash merge rewrites the commit while leaving every byte
# identical, so a contents-only check reports "match" and leaves the manifest
# naming a commit that no longer exists on main — provenance pointing at
# nothing, which is worse than no pin because it looks authoritative.
PINNED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_commit"])'   "${DEST}/MANIFEST.json" 2>/dev/null || echo "")"

if [ "${drift}" -eq 0 ] && [ "${PINNED}" = "${COMMIT}" ]; then
  echo "vendored vectors match ori-specs at ${COMMIT}"
  exit 0
fi

if [ "${drift}" -eq 0 ]; then
  if [ "${APPLY}" != "1" ]; then
    echo "vector contents match, but the manifest pins ${PINNED:-<none>}" >&2
    echo "and ori-specs is now at ${COMMIT}." >&2
    echo "Re-run with ORI_VECTORS_APPLY=1 to update the provenance pin." >&2
    exit 1
  fi
  echo "contents unchanged; updating the provenance pin to ${COMMIT}"
fi

if [ "${APPLY}" != "1" ]; then
  echo
  echo "Vendored vectors differ from ori-specs at ${COMMIT}." >&2
  echo "Re-run with ORI_VECTORS_APPLY=1 to update, then review the diff:" >&2
  echo "  a vector change is a contract change, not a refresh." >&2
  exit 1
fi

# Reconcile the whole set, not just additions and changes. Copying alone would
# leave a vector upstream had deleted sitting in the destination, where it would
# be re-recorded in the manifest and reported as drift again on every run.
for file in "${DEST}"/*.json; do
  name="$(basename "${file}")"
  [ "${name}" = "MANIFEST.json" ] && continue
  if [ ! -f "${SRC}/${name}" ]; then
    rm -f "${file}"
    echo "deleted  ${name}"
  fi
done
cp "${SRC}"/*.json "${DEST}/"
python3 - "${COMMIT}" "${DEST}" <<'PY'
import hashlib, json, pathlib, sys
commit, dest = sys.argv[1], pathlib.Path(sys.argv[2])
manifest = json.loads((dest / "MANIFEST.json").read_text())
manifest["source_commit"] = commit
manifest["files"] = {
    p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(dest.glob("*.json"))
    if p.name != "MANIFEST.json"
}
(dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"updated {len(manifest['files'])} vectors to {commit}")
PY
