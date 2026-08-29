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
# The evidence sets move together — an envelope wraps a chain row, so a change
# to one is usually a change to both. The transport set does not: it belongs to
# a contract with its own version.
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
  # Transport rather than artifact: gateway-api fixes how an inbound artifact
  # travels, and versions independently of the evidence contracts. Vendored
  # here so the same drift check covers it, and pinned separately because it
  # has no reason to move when the evidence vectors do.
  "gateway-api/vectors:tests/vectors/gateway_api"
  # Commissioned safety binding: a separate contract again, and the only
  # vendored set whose vectors describe physical commissioning rather than
  # evidence carriage. It pins independently because it has no reason to move
  # when the evidence contracts do.
  "commissioned-safety-binding:tests/vectors/commissioned_safety_binding"
  # Safety profiles ship with the release and their corpus proves the loader,
  # activation, evaluation and lifecycle rules; the binding verifier reads the
  # profile set for its trip-point bound. Pinned on its own like the binding.
  "safety-profile/vectors:tests/vectors/safety_profile"
  # Sensor configuration is its own contract and changes independently of the
  # evidence sets. Its consumer is the loader, not the evidence subsystem, so
  # it needs an independent provenance pin as well.
  "sensor-configuration/vectors:tests/vectors/sensor_configuration"
)

if [ -n "${ORI_SPECS_DIR:-}" ]; then
  SPECS="${ORI_SPECS_DIR}"
else
  SPECS="$(mktemp -d)"
  CLEANUP="${SPECS}"
  # Full history, blobs fetched on demand. --depth 1 makes ancestry
  # unanswerable, and ancestry is what the pin means.
  git clone --quiet --filter=blob:none \
    https://github.com/ori-platform/ori-specs.git "${SPECS}"
fi
trap '[ -n "${CLEANUP}" ] && rm -rf "${CLEANUP}"' EXIT

# Provenance is defined against ori-specs main, so main is what the pin is
# resolved and compared against -- never HEAD. A local checkout supplied
# through ORI_SPECS_DIR can be on any branch, and an unmerged one would
# otherwise let --apply vendor its vectors and pin its commit, which every
# later ancestry check would then accept.
MAIN_REF=""
for candidate in refs/remotes/origin/main refs/heads/main refs/heads/master; do
  if git -C "${SPECS}" rev-parse --verify --quiet "${candidate}" >/dev/null; then
    MAIN_REF="${candidate}"
    break
  fi
done
if [ -z "${MAIN_REF}" ]; then
  echo "no main branch found in ${SPECS}; cannot establish provenance" >&2
  exit 1
fi
COMMIT="$(git -C "${SPECS}" rev-parse "${MAIN_REF}")"

# Vectors are copied from the working tree, so the tree itself has to be main.
# Comparing the pin against main while copying bytes from somewhere else would
# record a provenance those files do not have.
if [ -n "${ORI_SPECS_DIR:-}" ]; then
  head_commit="$(git -C "${SPECS}" rev-parse HEAD)"
  if [ "${head_commit}" != "${COMMIT}" ]; then
    echo "ORI_SPECS_DIR is not on ${MAIN_REF}." >&2
    echo "  checkout is at ${head_commit}" >&2
    echo "  ${MAIN_REF} is at ${COMMIT}" >&2
    echo "Vectors are copied from the working tree, so vendoring from an" >&2
    echo "unmerged branch would pin a commit that is not on main." >&2
    exit 1
  fi
  # Refused, not warned. The vectors are copied from the working tree while the
  # manifest is pinned to the committed main SHA, so a dirty checkout writes a
  # pin that names a commit which did not produce the bytes beside it -- false
  # provenance without ever leaving main, and a second run over the same dirty
  # tree reports success. A warning cannot prevent that; only refusing can.
  #
  # The stronger form is to read the vectors from the resolved main commit
  # rather than from the working tree, which removes the class instead of
  # guarding it. That is a larger change than this rule needs.
  if [ -n "$(git -C "${SPECS}" status --porcelain 2>/dev/null)" ]; then
    echo "ORI_SPECS_DIR has uncommitted changes." >&2
    git -C "${SPECS}" status --porcelain 2>/dev/null | sed 's/^/  /' >&2
    echo "Vectors are copied from the working tree while the pin records the" >&2
    echo "committed ${MAIN_REF}, so a dirty checkout would record provenance" >&2
    echo "those bytes do not have. Commit or stash, or unset ORI_SPECS_DIR to" >&2
    echo "vendor from a fresh clone of main." >&2
    exit 1
  fi
fi
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
  # byte identical, so a contents-only check cannot tell a live pin from one
  # naming a commit that never landed — provenance pointing at nothing, which
  # is worse than no pin because it looks authoritative.
  #
  # What the pin asserts is "these bytes came from that commit", and that stays
  # true as main advances. So the test is reachability, not equality with the
  # tip. Requiring equality made every ori-specs merge stale every consumer,
  # including documentation-only merges that touched no vector, and a check
  # that fires when nothing relevant changed trains people to re-pin without
  # reading the diff.
  PINNED=""
  if [ -f "${DEST}/MANIFEST.json" ]; then
    PINNED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_commit"])' \
      "${DEST}/MANIFEST.json" 2>/dev/null || echo "")"
  fi

  # A pin is live when the commit it names is an ancestor of main. An unknown
  # commit is not an ancestor, so a rewritten or never-merged SHA fails here.
  reachable=0
  if [ -n "${PINNED}" ] && git -C "${SPECS}" merge-base --is-ancestor \
      "${PINNED}" "${COMMIT}" 2>/dev/null; then
    reachable=1
  fi

  if [ "${drift}" -eq 0 ] && [ "${reachable}" -eq 1 ]; then
    if [ "${PINNED}" = "${COMMIT}" ]; then
      echo "${label}: vectors match ori-specs at ${COMMIT}"
    else
      echo "${label}: vectors match; pinned at ${PINNED} (an ancestor of ${COMMIT})"
    fi
    continue
  fi

  if [ "${APPLY}" != "1" ]; then
    if [ "${drift}" -eq 0 ]; then
      echo "${label}: contents match, but the manifest pins ${PINNED:-<none>}," >&2
      echo "  which is not an ancestor of ori-specs main at ${COMMIT}." >&2
      echo "  That commit never landed on main, so the pin names nothing." >&2
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
