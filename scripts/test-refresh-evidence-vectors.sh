#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Tests for the vendored-vector provenance rule in refresh-evidence-vectors.sh.
#
# The rule decides when a consumer must re-vendor, so getting it wrong costs
# either false CI failures on every unrelated specs merge, or a pin that names
# a commit nobody can find. Both were reachable from the previous version, and
# neither is visible by reading the script.
#
# Each case builds a real throwaway ori-specs git repository, points the script
# at it with ORI_SPECS_DIR, and drives the real script.
#
#   bash scripts/test-refresh-evidence-vectors.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO}/scripts/refresh-evidence-vectors.sh"
PASS=0
FAIL=0

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

ok()  { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

# A minimal ori-specs with one vendored set, plus a consumer that vendors it.
# The script iterates a fixed SETS list, so the fixture provides every path it
# looks for; only commissioned-safety-binding carries content that matters here.
new_fixture() {
  local box="${WORK}/$1"
  local specs="${box}/specs" consumer="${box}/consumer"
  mkdir -p "${specs}" "${consumer}/scripts" "${consumer}/tests/vectors"

  git -C "${specs}" init -q -b main
  git -C "${specs}" config user.email t@example.com
  git -C "${specs}" config user.name t
  for d in evidence/vectors evidence-exchange/vectors evidence-exchange/vectors/receiver-state \
           runtime-evidence-anchor/vectors gateway-api/vectors commissioned-safety-binding; do
    mkdir -p "${specs}/${d}"
    printf '{"set":"%s","v":1}\n' "${d}" > "${specs}/${d}/vectors.json"
  done
  git -C "${specs}" add -A >/dev/null
  git -C "${specs}" commit -qm "initial vectors"

  cp "${SCRIPT}" "${consumer}/scripts/"
  chmod +x "${consumer}/scripts/refresh-evidence-vectors.sh"
  echo "${box}"
}

vendor() {  # vendor the current specs state into the consumer
  local box="$1"
  ORI_SPECS_DIR="${box}/specs" ORI_VECTORS_APPLY=1 \
    bash "${box}/consumer/scripts/refresh-evidence-vectors.sh" >/dev/null 2>&1
}

check() {   # run the drift check; echo output, return its exit code
  local box="$1"
  ORI_SPECS_DIR="${box}/specs" bash "${box}/consumer/scripts/refresh-evidence-vectors.sh" 2>&1
}

pinned_commit() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_commit"])' \
    "$1/consumer/tests/vectors/commissioned_safety_binding/MANIFEST.json"
}

# ── 1. a later documentation-only specs commit must pass ─────────────────────
#
# This is the case that made the previous rule unusable: main moves, no vector
# changes, and every consumer fails CI.

box="$(new_fixture docs-only)"
vendor "${box}"
before="$(pinned_commit "${box}")"
echo "notes" > "${box}/specs/README.md"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "docs: unrelated to any vector"
after_head="$(git -C "${box}/specs" rev-parse HEAD)"

out="$(check "${box}")"; code=$?
if [ "${code}" -eq 0 ]; then
  ok "a later docs-only specs commit passes"
else
  bad "a later docs-only specs commit passes" "exit ${code}: ${out}"
fi
if [ "${before}" != "${after_head}" ]; then
  ok "the pin is genuinely behind main, not equal to it"
else
  bad "the pin is genuinely behind main, not equal to it" "fixture did not advance main"
fi
if grep -q "an ancestor of" <<< "${out}"; then
  ok "the report says the pin is an ancestor rather than claiming equality"
else
  bad "the report says the pin is an ancestor rather than claiming equality" "${out}"
fi

# ── 2. a pin not reachable from main must fail ───────────────────────────────
#
# A commit that never landed: the shape a squash merge leaves behind, and the
# reason a contents-only check is not enough.

box="$(new_fixture unreachable)"
vendor "${box}"
git -C "${box}/specs" checkout -q -b sidebranch
echo "side" > "${box}/specs/side.md"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "never merged"
orphan="$(git -C "${box}/specs" rev-parse HEAD)"
git -C "${box}/specs" checkout -q -
python3 - "${box}" "${orphan}" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]) / "consumer/tests/vectors/commissioned_safety_binding/MANIFEST.json"
d = json.loads(p.read_text()); d["source_commit"] = sys.argv[2]
p.write_text(json.dumps(d, indent=2) + "\n")
PY

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "not an ancestor" <<< "${out}"; then
  ok "a pin that never landed on main fails"
else
  bad "a pin that never landed on main fails" "exit ${code}: ${out}"
fi

# ── 3. changed vector bytes must fail even when the pin is reachable ─────────
#
# Reachability must not become a way to ignore content drift.

box="$(new_fixture bytes-changed)"
vendor "${box}"
reachable_pin="$(pinned_commit "${box}")"
printf '{"set":"commissioned-safety-binding","v":2}\n' \
  > "${box}/specs/commissioned-safety-binding/vectors.json"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "vectors: a real contract change"

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "CHANGED" <<< "${out}"; then
  ok "a vector byte change fails even though the pin is reachable"
else
  bad "a vector byte change fails even though the pin is reachable" "exit ${code}: ${out}"
fi
if git -C "${box}/specs" merge-base --is-ancestor "${reachable_pin}" HEAD; then
  ok "precondition: that pin really was reachable"
else
  bad "precondition: that pin really was reachable" "fixture is wrong"
fi

# ── 4. the pin moves only when the bytes move ────────────────────────────────
#
# Re-pinning a set whose contents did not change would claim those bytes came
# from a commit that did not produce them. Provenance is about where the bytes
# came from, so a live pin is left alone even under --apply.

box="$(new_fixture apply-noop)"
vendor "${box}"
original="$(pinned_commit "${box}")"
echo "more" > "${box}/specs/README.md"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "docs again"
vendor "${box}"
if [ "$(pinned_commit "${box}")" = "${original}" ]; then
  ok "--apply leaves a reachable, content-matching pin alone"
else
  bad "--apply leaves a reachable, content-matching pin alone" \
      "pin advanced to a commit that did not produce these bytes"
fi

box="$(new_fixture apply-moves)"
vendor "${box}"
printf '{"set":"commissioned-safety-binding","v":3}\n' \
  > "${box}/specs/commissioned-safety-binding/vectors.json"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "vectors: real change"
vendor "${box}"
if [ "$(pinned_commit "${box}")" = "$(git -C "${box}/specs" rev-parse HEAD)" ]; then
  ok "--apply re-pins when the vectors actually changed"
else
  bad "--apply re-pins when the vectors actually changed" "pin did not advance"
fi
if grep -q '"v":3' "${box}/consumer/tests/vectors/commissioned_safety_binding/vectors.json"; then
  ok "the new bytes were copied, not just the pin"
else
  bad "the new bytes were copied, not just the pin" "vendored content is stale"
fi


# ── 5. a supplied checkout that is not main must be refused ──────────────────
#
# ORI_SPECS_DIR points at a working tree, and the vectors are copied from it.
# On an unmerged branch, --apply would vendor that branch's bytes and pin its
# commit; every later run would then find the pin reachable and report success.
# Case 2 does not cover this -- it puts an orphan pin in the manifest while the
# checkout is back on main, so the copy path is never exercised off-main.

box="$(new_fixture unmerged-branch)"
vendor "${box}"
git -C "${box}/specs" checkout -q -b feature/new-vectors
printf '{"set":"commissioned-safety-binding","v":99}\n' \
  > "${box}/specs/commissioned-safety-binding/vectors.json"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "vectors: not merged to main"
branch_commit="$(git -C "${box}/specs" rev-parse HEAD)"

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "is not on refs/heads/main" <<< "${out}"; then
  ok "check refuses a supplied checkout that is not on main"
else
  bad "check refuses a supplied checkout that is not on main" "exit ${code}: ${out}"
fi

vendor "${box}"
if [ "$(pinned_commit "${box}")" = "${branch_commit}" ]; then
  bad "apply refuses to vendor from an unmerged branch" "it pinned the branch commit"
else
  ok "apply refuses to vendor from an unmerged branch"
fi
if grep -q '"v":99' "${box}/consumer/tests/vectors/commissioned_safety_binding/vectors.json"; then
  bad "apply did not copy the unmerged branch bytes" "branch bytes were vendored"
else
  ok "apply did not copy the unmerged branch bytes"
fi

git -C "${box}/specs" checkout -q main
out="$(check "${box}")"; code=$?
if [ "${code}" -eq 0 ]; then
  ok "the same checkout passes once it is back on main"
else
  bad "the same checkout passes once it is back on main" "exit ${code}: ${out}"
fi


echo
printf '%d passed, %d failed\n' "${PASS}" "${FAIL}"
[ "${FAIL}" -eq 0 ]
