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

# A minimal ori-specs with every vendored set, plus a consumer that vendors it.
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
           runtime-evidence-anchor/vectors gateway-api/vectors commissioned-safety-binding \
           safety-profile/vectors sensor-configuration/vectors; do
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

repin() {   # repin <box> <commit> [vendored set, default the binding one]
  python3 -c 'import json, pathlib, sys
p = pathlib.Path(sys.argv[1]) / "consumer/tests/vectors" / sys.argv[3] / "MANIFEST.json"
d = json.loads(p.read_text()); d["source_commit"] = sys.argv[2]
p.write_text(json.dumps(d, indent=2) + "\n")' "$1" "$2" "${3:-commissioned_safety_binding}"
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
if grep -q "STALE PIN" <<< "${out}"; then
  bad "a correct pin behind main is not called stale" "${out}"
else
  ok "a correct pin behind main is not called stale"
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
repin "${box}" "${orphan}"

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "not an ancestor" <<< "${out}"; then
  ok "a pin that never landed on main fails"
else
  bad "a pin that never landed on main fails" "exit ${code}: ${out}"
fi
# The bytes match main, so telling the operator the vectors differ would send
# them to read a vector diff that does not exist.
if grep -q "Vendored vectors differ from ori-specs" <<< "${out}"; then
  bad "an unresolvable pin is not reported as content drift" "${out}"
else
  ok "an unresolvable pin is not reported as content drift"
fi
if grep -q "does not name a commit this check can resolve" <<< "${out}"; then
  ok "an unresolvable pin is reported as a pin problem"
else
  bad "an unresolvable pin is reported as a pin problem" "${out}"
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


# ── 6. a dirty supplied checkout must be refused ─────────────────────────────
#
# The branch gate is not enough on its own. On a clean main with an uncommitted
# vector edit, the script would copy the dirty working-tree bytes while pinning
# the committed main SHA -- false provenance without ever leaving main, and a
# second run over the same tree reports success because contents now match.

box="$(new_fixture dirty-tree)"
vendor "${box}"
clean_pin="$(pinned_commit "${box}")"
printf '{"set":"commissioned-safety-binding","v":66}\n' \
  > "${box}/specs/commissioned-safety-binding/vectors.json"

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "uncommitted changes" <<< "${out}"; then
  ok "check refuses a dirty supplied checkout"
else
  bad "check refuses a dirty supplied checkout" "exit ${code}: ${out}"
fi

vendor "${box}"
if grep -q '"v":66' "${box}/consumer/tests/vectors/commissioned_safety_binding/vectors.json"; then
  bad "apply does not copy uncommitted vector bytes" "dirty bytes were vendored"
else
  ok "apply does not copy uncommitted vector bytes"
fi
if [ "$(pinned_commit "${box}")" = "${clean_pin}" ]; then
  ok "apply leaves the pin untouched for a dirty checkout"
else
  bad "apply leaves the pin untouched for a dirty checkout" "the pin moved"
fi

# An untracked file in a vendored directory is copied by the glob, so it counts
# as dirt even though nothing tracked changed.
box="$(new_fixture untracked-file)"
vendor "${box}"
printf '{"stray":true}\n' > "${box}/specs/commissioned-safety-binding/stray.json"
out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "uncommitted changes" <<< "${out}"; then
  ok "an untracked file in a vendored directory is refused"
else
  bad "an untracked file in a vendored directory is refused" "exit ${code}: ${out}"
fi

git -C "${box}/specs" clean -qfd
out="$(check "${box}")"; code=$?
if [ "${code}" -eq 0 ]; then
  ok "the same checkout passes once it is clean"
else
  bad "the same checkout passes once it is clean" "exit ${code}: ${out}"
fi


# ── 7. a reachable pin that carries different bytes must fail ────────────────
#
# Reachability answers "did that commit land?", not "did these bytes come from
# it". A vendored file brought up to main out of band matches every byte
# upstream while the manifest still names the commit from before it moved, and
# contents go on matching, so the false provenance would report success forever.

box="$(new_fixture stale-pin)"
vendor "${box}"
stale_pin="$(pinned_commit "${box}")"
printf '{"set":"commissioned-safety-binding","v":7}\n' \
  > "${box}/specs/commissioned-safety-binding/vectors.json"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "vectors: a contract change"
# The out-of-band copy: the bytes are brought up to main, the manifest is not.
cp "${box}/specs/commissioned-safety-binding/vectors.json" \
   "${box}/consumer/tests/vectors/commissioned_safety_binding/vectors.json"

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "STALE PIN" <<< "${out}"; then
  ok "bytes matching main under a pin carrying different bytes fails"
else
  bad "bytes matching main under a pin carrying different bytes fails" "exit ${code}: ${out}"
fi
if git -C "${box}/specs" merge-base --is-ancestor "${stale_pin}" HEAD; then
  ok "precondition: the stale pin really is reachable from main"
else
  bad "precondition: the stale pin really is reachable from main" "fixture is wrong"
fi
if grep -q "CHANGED" <<< "${out}"; then
  bad "precondition: the contents check cannot see this" "contents differ, so this is not the case under test"
else
  ok "precondition: the contents check cannot see this"
fi
if grep -q "Vendored vectors differ from ori-specs" <<< "${out}"; then
  bad "a stale pin is not reported as a content difference" "${out}"
else
  ok "a stale pin is not reported as a content difference"
fi

vendor "${box}"
if [ "$(pinned_commit "${box}")" = "$(git -C "${box}/specs" rev-parse HEAD)" ]; then
  ok "--apply repairs a stale pin"
else
  bad "--apply repairs a stale pin" "pin is still $(pinned_commit "${box}")"
fi
out="$(check "${box}")"; code=$?
if [ "${code}" -eq 0 ]; then
  ok "the repaired set passes"
else
  bad "the repaired set passes" "exit ${code}: ${out}"
fi

# ── 8. the pinned commit must carry the same set of files ────────────────────
#
# The same false provenance arrives through additions and deletions, not only
# through edited bytes: a set that gained or lost a vector out of band still
# matches main file for file while the pin names a commit with a different set.

box="$(new_fixture pin-lacks-a-file)"
vendor "${box}"
printf '{"extra":true}\n' > "${box}/specs/commissioned-safety-binding/extra.json"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "vectors: a second file"
cp "${box}/specs/commissioned-safety-binding/extra.json" \
   "${box}/consumer/tests/vectors/commissioned_safety_binding/extra.json"

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "extra.json: vendored here but not at" <<< "${out}"; then
  ok "a vector the pinned commit never carried fails"
else
  bad "a vector the pinned commit never carried fails" "exit ${code}: ${out}"
fi

box="$(new_fixture pin-carries-a-file)"
printf '{"extra":true}\n' > "${box}/specs/commissioned-safety-binding/extra.json"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "vectors: a second file"
vendor "${box}"
git -C "${box}/specs" rm -q "${box}/specs/commissioned-safety-binding/extra.json"
git -C "${box}/specs" commit -qm "vectors: drop the second file"
rm -f "${box}/consumer/tests/vectors/commissioned_safety_binding/extra.json"

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "extra.json: at .* but not vendored here" <<< "${out}"; then
  ok "a vector dropped out of band that the pin still carries fails"
else
  bad "a vector dropped out of band that the pin still carries fails" "exit ${code}: ${out}"
fi


# ── 9. a pin that is not a full commit object name must fail ─────────────────
#
# Both of these pass an ancestry test while carrying no provenance: a branch
# resolves to whatever it points at whenever the check runs, so it can never be
# found stale, and an abbreviation names a commit today and turns ambiguous as
# history grows.

box="$(new_fixture branch-pin)"
vendor "${box}"
repin "${box}" main
out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "not a full commit object name" <<< "${out}"; then
  ok "a manifest pinning a branch name fails"
else
  bad "a manifest pinning a branch name fails" "exit ${code}: ${out}"
fi
if grep -q "Vendored vectors differ from ori-specs" <<< "${out}"; then
  bad "a branch pin is not reported as content drift" "${out}"
else
  ok "a branch pin is not reported as content drift"
fi

box="$(new_fixture abbreviated-pin)"
vendor "${box}"
repin "${box}" "$(git -C "${box}/specs" rev-parse --short HEAD)"
out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "not a full commit object name" <<< "${out}"; then
  ok "a manifest pinning an abbreviated commit fails"
else
  bad "a manifest pinning an abbreviated commit fails" "exit ${code}: ${out}"
fi
if grep -q "Vendored vectors differ from ori-specs" <<< "${out}"; then
  bad "an abbreviated pin is not reported as content drift" "${out}"
else
  ok "an abbreviated pin is not reported as content drift"
fi
if grep -q "only the pin moves" <<< "${out}"; then
  ok "the remedy offered is a pin repair, not a vector review"
else
  bad "the remedy offered is a pin repair, not a vector review" "${out}"
fi

# The remedy has to be true: applying moves the pin and leaves the bytes alone.
vendored="${box}/consumer/tests/vectors/commissioned_safety_binding/vectors.json"
before="$(cat "${vendored}")"
vendor "${box}"
if [ "$(cat "${vendored}")" = "${before}" ] \
   && [ "$(pinned_commit "${box}")" = "$(git -C "${box}/specs" rev-parse HEAD)" ]; then
  ok "--apply repairs a malformed pin without touching the bytes"
else
  bad "--apply repairs a malformed pin without touching the bytes" \
      "pin $(pinned_commit "${box}")"
fi

# A manifest with no source commit at all is the third way a pin fails to
# resolve, and it must not claim a commit that never landed.
box="$(new_fixture no-pin)"
vendor "${box}"
repin "${box}" ""
out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] && grep -q "records no source" <<< "${out}"; then
  ok "a manifest with no source commit says so"
else
  bad "a manifest with no source commit says so" "exit ${code}: ${out}"
fi
if grep -q "Vendored vectors differ from ori-specs" <<< "${out}"; then
  bad "a missing pin is not reported as content drift" "${out}"
else
  ok "a missing pin is not reported as content drift"
fi

# The rule must reject the shape, not merely fail to resolve it: the full SHA
# of the very same commit passes.
repin "${box}" "$(git -C "${box}/specs" rev-parse HEAD)"
out="$(check "${box}")"; code=$?
if [ "${code}" -eq 0 ]; then
  ok "the same commit spelled in full passes"
else
  bad "the same commit spelled in full passes" "exit ${code}: ${out}"
fi

# ── 10. two sets failing differently must each be named ──────────────────────
#
# The buckets are per set, so a run that finds drifted bytes in one and an
# unresolvable pin in another has to report both. Collapsing to whichever came
# first would either send the operator to read a vector diff that does not
# exist, or hide one that does.

box="$(new_fixture two-failures)"
vendor "${box}"
printf '{"set":"commissioned-safety-binding","v":10}\n' \
  > "${box}/specs/commissioned-safety-binding/vectors.json"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "vectors: a contract change"
repin "${box}" main safety_profile

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] \
   && grep -q "Vendored vectors differ from ori-specs" <<< "${out}" \
   && grep -q "does not name a commit this check can resolve" <<< "${out}"; then
  ok "drifted bytes in one set and a bad pin in another are both reported"
else
  bad "drifted bytes in one set and a bad pin in another are both reported" "exit ${code}: ${out}"
fi

box="$(new_fixture drift-and-stale)"
vendor "${box}"
printf '{"set":"commissioned-safety-binding","v":11}\n' \
  > "${box}/specs/commissioned-safety-binding/vectors.json"
printf '{"set":"safety-profile/vectors","v":11}\n' \
  > "${box}/specs/safety-profile/vectors/vectors.json"
git -C "${box}/specs" add -A >/dev/null
git -C "${box}/specs" commit -qm "vectors: change two sets"
# One set is left behind, the other is brought up to main without its pin.
cp "${box}/specs/safety-profile/vectors/vectors.json" \
   "${box}/consumer/tests/vectors/safety_profile/vectors.json"

out="$(check "${box}")"; code=$?
if [ "${code}" -ne 0 ] \
   && grep -q "Vendored vectors differ from ori-specs" <<< "${out}" \
   && grep -q "does not carry the bytes vendored beside" <<< "${out}"; then
  ok "drifted bytes in one set and a stale pin in another are both reported"
else
  bad "drifted bytes in one set and a stale pin in another are both reported" "exit ${code}: ${out}"
fi

echo
printf '%d passed, %d failed\n' "${PASS}" "${FAIL}"
[ "${FAIL}" -eq 0 ]
