#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Tests for the provenance rule in refresh-telemetry-refusal-fixture.sh.
#
# The source repository is private, so the drift run itself cannot execute in
# public CI. The script's logic can: each case builds a real throwaway git
# repository, points the script at it, and drives the real script. A pin that
# names a commit which never carried the vendored bytes reads as authoritative
# while proving nothing, and that is not visible by reading the script.
#
#   bash scripts/test-refresh-telemetry-refusal-fixture.sh

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO}/scripts/refresh-telemetry-refusal-fixture.sh"
SRC_PATH="apps/api/tests/fixtures/runtime_contracts/telemetry_refusals.json"
PASS=0
FAIL=0

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

ok()  { PASS=$((PASS + 1)); printf '  \033[32mPASS\033[0m  %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  \033[31mFAIL\033[0m  %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; }

digest() {
  python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$1"
}

# A throwaway product-API repository: one commit that predates the fixture, one
# that introduces it, and one after it that leaves it untouched.
SRC="${WORK}/src"
mkdir -p "${SRC}/$(dirname "${SRC_PATH}")"
git -C "${SRC}" init --quiet -b main 2>/dev/null || { mkdir -p "${SRC}"; git -C "${SRC}" init --quiet; }
git -C "${SRC}" config user.email t@example.test
git -C "${SRC}" config user.name t
echo "before" > "${SRC}/README"
git -C "${SRC}" add -A && git -C "${SRC}" commit --quiet -m "before the fixture"
BEFORE="$(git -C "${SRC}" rev-parse HEAD)"
cat > "${SRC}/${SRC_PATH}" <<'JSON'
{"contract":"x","contract_version":1,"cases":[]}
JSON
printf '%s  telemetry_refusals.json\n' "$(digest "${SRC}/${SRC_PATH}")" > "${SRC}/${SRC_PATH}.sha256"
git -C "${SRC}" add -A && git -C "${SRC}" commit --quiet -m "add the fixture"
INTRODUCED="$(git -C "${SRC}" rev-parse HEAD)"
echo "after" >> "${SRC}/README"
git -C "${SRC}" add -A && git -C "${SRC}" commit --quiet -m "unrelated change"
TIP="$(git -C "${SRC}" rev-parse HEAD)"

# A consumer tree holding only what the script reads and writes.
DEST="${WORK}/dest/tests/vectors/telemetry_refusals"
mkdir -p "${DEST}" "${WORK}/dest/scripts"
cp "${SCRIPT}" "${WORK}/dest/scripts/"
cp "${SRC}/${SRC_PATH}" "${DEST}/telemetry_refusals.json"

manifest() {
  python3 - "$1" "${DEST}" <<'PY'
import hashlib, json, pathlib, sys
commit, dest = sys.argv[1], pathlib.Path(sys.argv[2])
(dest / "MANIFEST.json").write_text(json.dumps({
    "source_repository": "x", "source_path": "y", "source_commit": commit,
    "files": {"telemetry_refusals.json": hashlib.sha256(
        (dest / "telemetry_refusals.json").read_bytes()).hexdigest()},
}, indent=2) + "\n")
PY
}

drive() {
  ORI_SKIP_FETCH=1 ORI_ENERGY_DIR="${SRC}" \
    bash "${WORK}/dest/scripts/$(basename "${SCRIPT}")" 2>&1
}

check() { # name, expected-rc, expected-substring
  local name="$1" want_rc="$2" want="$3" out rc
  out="$(drive)"; rc=$?
  if [ "${rc}" != "${want_rc}" ]; then
    bad "${name}" "expected rc ${want_rc}, got ${rc}: ${out}"
  elif [ -n "${want}" ] && ! printf '%s' "${out}" | grep -q "${want}"; then
    bad "${name}" "expected /${want}/ in: ${out}"
  else
    ok "${name}"
  fi
}

echo "refresh-telemetry-refusal-fixture.sh"

manifest "${INTRODUCED}"
check "a pin at the introducing commit is accepted" 0 "up to date"

manifest "${TIP}"
check "a later commit carrying the same bytes is accepted" 0 "up to date"

# The hole this test exists for: an ancestor that never held the file.
manifest "${BEFORE}"
check "a pin predating the file is refused" 1 "does not exist at pinned commit"

manifest "0000000000000000000000000000000000000000"
check "a pin naming no known commit is refused" 1 "is not in"

manifest "${INTRODUCED:0:7}"
check "an abbreviated pin is refused" 1 "not a full commit id"

python3 -c "
import json,pathlib
p=pathlib.Path('${DEST}/MANIFEST.json'); d=json.loads(p.read_text()); d.pop('source_commit')
p.write_text(json.dumps(d,indent=2))"
check "a manifest with no pin is refused" 1 "not a full commit id"

manifest "${INTRODUCED}"
printf '{"contract":"x","contract_version":2,"cases":[]}\n' > "${DEST}/telemetry_refusals.json"
check "vendored bytes edited locally are refused" 1 "CHANGED"

cp "${SRC}/${SRC_PATH}" "${DEST}/telemetry_refusals.json"
manifest "${INTRODUCED}"
check "restoring the bytes is accepted again" 0 "up to date"

out="$(ORI_SKIP_FETCH=1 bash "${WORK}/dest/scripts/$(basename "${SCRIPT}")" 2>&1)"; rc=$?
if [ "${rc}" = "2" ]; then ok "a missing source checkout is refused"; else bad "a missing source checkout is refused" "rc=${rc}: ${out}"; fi

echo
echo "${PASS} passed, ${FAIL} failed"
[ "${FAIL}" -eq 0 ]
