#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Run the test job of .github/workflows/ci.yml on this machine, inside a
# container that matches the hosted runner, with the same two changed-paths
# decisions the workflow makes. Every command below is the CI command; when the
# two drift, fix ci.yml and this file together.
#
# The decisions are not re-implemented here. The action's own script is read
# out of .github/actions/changed-paths/action.yml and run against the base you
# name, and the patterns are read out of ci.yml, so what runs here is what the
# workflow would run for the same diff. --decide prints the two answers and
# stops, which is the quickest way to see which checks a change reaches.
#
# Differences from the hosted run, all deliberate:
#   - One interpreter, the one .python-version pins, so the steps the matrix
#     runs on one lane only run once here and the other lanes are not proved.
#   - The container is the host's architecture by default; CI runs amd64. The
#     suite is sensitive to Linux against macOS, not to the architecture, but
#     a native run is reported as not CI-equivalent (exit 3). --amd64 emulates.
#   - The coverage upload and the runner hardening are hosted-runner concerns
#     with no local equivalent; the payload job needs a Rust image and is not
#     run here.
#   - The pip cache lives in a named volume so a second run installs from it;
#     CI starts cold. --clean discards the image and the volume.
#
# Usage:
#   scripts/ci_local.sh                 # the test job, decided against origin/main
#   scripts/ci_local.sh --decide        # print the two decisions and stop
#   scripts/ci_local.sh --base REF      # decide against another base
#   scripts/ci_local.sh --all           # run every step regardless of the decisions
#   scripts/ci_local.sh --amd64         # CI's architecture, under emulation on arm64
#   scripts/ci_local.sh --clean         # discard the cached image and pip volume
#
# Exit status: 0 every step passed and the run was CI-equivalent, 1 a step
# failed, 2 bad arguments or no Docker, 3 every step passed but the run is not
# the proof you asked for (native architecture). 3 is never a defect in the
# code under test, and it is never success either.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_REF="origin/main"
DECIDE_ONLY=0
FORCE_ALL=0
CLEAN=0
PLATFORM="native"
NOT_PROOF=()

while [ $# -gt 0 ]; do
  case "$1" in
    --decide) DECIDE_ONLY=1; shift ;;
    --all) FORCE_ALL=1; shift ;;
    --base) BASE_REF="${2:-}"; [ -z "$BASE_REF" ] && { echo "--base needs a ref" >&2; exit 2; }; shift 2 ;;
    --amd64) PLATFORM="linux/amd64"; shift ;;
    --clean) CLEAN=1; shift ;;
    -h|--help) awk 'NR > 3 && /^$/ { exit } NR > 3 { sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if ! docker info >/dev/null 2>&1; then
  echo "docker is not available; this script runs CI in a container" >&2
  exit 2
fi

# A git worktree keeps its .git as a file pointing into another repository,
# which the container cannot follow; the copy needs the whole repository.
if [ ! -d "$ROOT/.git" ]; then
  echo "this checkout is a git worktree; run from a full clone" >&2
  exit 2
fi
BASE_SHA="$(git -C "$ROOT" rev-parse --verify "${BASE_REF}^{commit}" 2>/dev/null)" || {
  echo "base ${BASE_REF} is not a commit here" >&2
  exit 2
}
HEAD_SHA="$(git -C "$ROOT" rev-parse HEAD)"
# A pull request is decided against the base branch's head, and the diff the
# workflow sees is base..head. Locally the base may have moved past the branch
# point; the merge base is what a pull request would be compared to.
BASE_SHA="$(git -C "$ROOT" merge-base "$BASE_SHA" "$HEAD_SHA")"

# --platform is always passed, host architecture included: omitting it reuses
# whichever architecture of the base image the cache holds.
if [ "$PLATFORM" = "native" ]; then
  case "$(docker info --format '{{.Architecture}}')" in
    aarch64|arm64) PLATFORM="linux/arm64" ;;
    x86_64|amd64)  PLATFORM="linux/amd64" ;;
    *) echo "unrecognised docker host architecture; pass --amd64" >&2; exit 2 ;;
  esac
  [ "$PLATFORM" != "linux/amd64" ] && NOT_PROOF+=("architecture is ${PLATFORM##*/}, not the amd64 CI uses (--amd64 emulates it)")
fi
ARCH_SUFFIX="${PLATFORM##*/}"
PY_VERSION="$(tr -d '[:space:]' < "$ROOT/.python-version")"
BASE_IMAGE="python:${PY_VERSION}-bookworm"
IMAGE="ori-runtime-ci-local-${ARCH_SUFFIX}"
CACHE_VOLUME="ori-runtime-ci-pip-${ARCH_SUFFIX}"
echo "interpreter from .python-version: ${PY_VERSION} (base ${BASE_IMAGE}); platform ${PLATFORM}"
echo "deciding ${BASE_SHA:0:12}..${HEAD_SHA:0:12} (base ${BASE_REF})"

if [ "$CLEAN" -eq 1 ]; then
  docker rmi -f "$IMAGE" >/dev/null 2>&1
  docker volume rm -f "$CACHE_VOLUME" >/dev/null 2>&1
  echo "cleared the cached image and pip volume"
fi

# Built once and reused: the base plus what the ubuntu runner has and a slim
# image does not. Committed from a run rather than `docker build` so the
# platform is honoured on a Docker without buildx.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "preparing the runner image once (${BASE_IMAGE} + sudo, zip)..."
  docker rm -f "${IMAGE}-build" >/dev/null 2>&1
  # The hosted runner is an unprivileged user with passwordless sudo, and the
  # installer tests depend on that: root ignores the permission bits they
  # assert on. The interpreter's whole prefix is handed to that user, as the
  # setup-python tool cache is on the runner.
  docker run --name "${IMAGE}-build" --platform "$PLATFORM" "$BASE_IMAGE" bash -eo pipefail -c '
      export DEBIAN_FRONTEND=noninteractive
      apt-get update >/dev/null
      # The distribution python3 as well: the system-scope installer
      # tests build a venv from a root-controlled interpreter under /usr/bin,
      # which the hosted runner has beside its tool cache.
      apt-get install -y --no-install-recommends sudo zip python3 python3-venv >/dev/null
      rm -rf /var/lib/apt/lists/*
      useradd -m -s /bin/bash runner
      echo "runner ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/runner
      chmod 0440 /etc/sudoers.d/runner
      chown -R runner:runner /usr/local' || {
    echo "could not prepare the runner image" >&2
    docker rm -f "${IMAGE}-build" >/dev/null 2>&1
    exit 1
  }
  docker commit "${IMAGE}-build" "$IMAGE" >/dev/null
  docker rm -f "${IMAGE}-build" >/dev/null 2>&1
  echo "runner image ready; later runs reuse it"
else
  echo "reusing the prepared runner image"
fi

# The container script is a single-quoted literal that this shell never
# re-parses; every expansion in it happens in the container. Host values cross
# over as environment variables.
CONTAINER_SCRIPT='
set -uo pipefail
# Copied rather than built in place: the mount is read-only, and CI builds a
# fresh checkout. .git is carried because the decision and several tests read
# it; the action fetches the base from origin, which is pointed at the mount.
mkdir -p /work
tar -C /src -cf - \
  --exclude=./.venv --exclude=./build --exclude=./dist --exclude=./coverage.xml \
  --exclude="./*.db" --exclude="./*.log" --exclude=__pycache__ . \
  | tar -C /work --no-same-owner -xf -
cd /work
# A bind mount that resolves empty (colima does this for /tmp) would copy
# nothing and every check would then run against nothing.
[ -f pyproject.toml ] || { echo "the source mount is empty: keep the checkout under \$HOME, not /tmp" >&2; exit 1; }
git config --global --add safe.directory "*"
git remote set-url origin /src
# A pull request is decided on committed changes. Uncommitted work is what a
# developer runs this on, so the copy commits it here, in the throwaway copy
# only, and the decision sees the diff the pull request would.
# An untracked file outside every tracked top-level entry is a stray of this
# machine, not part of the change: a pull request would never carry it.
git ls-files --others --exclude-standard | while read -r stray; do
  top="${stray%%/*}"
  if ! git ls-tree --name-only HEAD | grep -qx -- "$top"; then
    echo "left out of the copy (untracked, outside every tracked top-level entry): $stray"
    rm -rf -- "$stray"
  fi
done
if [ -n "$(git status --porcelain)" ]; then
  git add -A
  # --no-verify: the hooks in the copied .git belong to the host machine, and pre-commit runs later as a step.
  git -c user.name=ci-local -c user.email=ci-local@localhost commit -q --no-verify -m "ci_local: the working tree"
  echo "committed the working tree in the copy, so the decision sees it"
fi
chown -R runner:runner /work /cache
export PIP_CACHE_DIR=/cache/pip

job() {
RESULTS=""
FAILED=0
step() {
  # step NAME CONDITION -- COMMAND...  CONDITION is "true" or "false".
  local name="$1" cond="$2"; shift 2; [ "${1:-}" = "--" ] && shift
  if [ "$cond" != "true" ]; then
    printf "  \033[2m- %s (not reached by this change)\033[0m\n" "$name"
    RESULTS="${RESULTS}$(printf "%-52s %s" "$name" "skipped")\n"
    return 0
  fi
  printf "  \033[36m- %s\033[0m\n" "$name"
  local start; start=$(date +%s)
  if "$@"; then
    RESULTS="${RESULTS}$(printf "%-52s PASS %3ds" "$name" $(( $(date +%s) - start )))\n"
  else
    printf "  \033[31m  FAILED: %s\033[0m\n" "$name"
    RESULTS="${RESULTS}$(printf "%-52s FAIL %3ds" "$name" $(( $(date +%s) - start )))\n"
    FAILED=1
  fi
}

# The decision, exactly as the action runs it, against the pull request base.
DECIDE_SCRIPT="$(awk "/^      run: \|/{f=1;next} f&&/^        /{sub(/^        /,\"\");print;next} f{exit}" .github/actions/changed-paths/action.yml)"
decide() {
  local out; out="$(mktemp)"
  GITHUB_OUTPUT="$out" EVENT_NAME=pull_request PR_BASE_SHA="$BASE_SHA" PUSH_BEFORE_SHA="" \
    PATTERN="$1" REASON="$2" bash -c "$DECIDE_SCRIPT" | sed "s/^/    /" >&2
  sed -n "s/^run=//p" "$out"
}
pattern_of() {
  python - "$1" <<PY
import sys, yaml
steps = yaml.safe_load(open(".github/workflows/ci.yml"))["jobs"]["test"]["steps"]
print(next(s["with"]["pattern"] for s in steps if s.get("id") == sys.argv[1]))
PY
}

python -m pip --version
# The install is not a step: nothing below is meaningful without it.
python -m pip install --require-hashes -r requirements/dev.txt -q || { echo "installing requirements/dev.txt failed" >&2; exit 1; }
python -m pip install --no-deps -e . -q || { echo "installing the runtime failed" >&2; exit 1; }

echo "==> Decide whether this change reaches the runtime'"'"'s checks"
SCOPE="$(decide "$(pattern_of scope)" "running the runtime'"'"'s tests, type checks and audits")"
echo "==> Decide whether this change touches a document"
DOCS="$(decide "$(pattern_of docs)" "running the tests that read documents")"
if [ "$FORCE_ALL" = "1" ]; then SCOPE=true; DOCS=true; echo "--all: every step runs"; fi
# A decision that answered nothing would skip every step and read as green.
for answer in "$SCOPE" "$DOCS"; do
  case "$answer" in true|false) ;; *) echo "a decision produced no answer: scope=$SCOPE docs=$DOCS" >&2; exit 1 ;; esac
done
echo "scope=$SCOPE docs=$DOCS"
if [ "$DECIDE_ONLY" = "1" ]; then exit 0; fi
DOCS_ONLY=false
[ "$SCOPE" != "true" ] && [ "$DOCS" = "true" ] && DOCS_ONLY=true

echo "==> Test (Python $(python -c "import sys; print(\"%d.%d\" % sys.version_info[:2])"))"
step "Guard supply-chain invariants" "$SCOPE" -- bash -c "python scripts/check_workflows.py && bash scripts/check_rust_supply_chain.sh"
step "Test the vendored-vector provenance rule" "$SCOPE" -- bash scripts/test-refresh-evidence-vectors.sh
step "Check vendored evidence vectors against ori-specs" "$SCOPE" -- bash scripts/refresh-evidence-vectors.sh
step "Test the telemetry refusal fixture provenance rule" "$SCOPE" -- bash scripts/test-refresh-telemetry-refusal-fixture.sh
step "Audit a built wheelhouse for disclosure" "$SCOPE" -- bash -eo pipefail -c "
  export ORI_WHEELHOUSE_OUT=/tmp/wheelhouse ORI_WHEELHOUSE_TARGET=pi
  bash scripts/build-wheelhouse.sh
  term=\"\$(sed -n \"s/^ *term=\\\"\\([a-z]*\\)\\\"\$/\\1/p\" .github/workflows/ci.yml | head -1)\"
  [ -n \"\$term\" ] || { echo \"the synthetic disclosure term was not found in ci.yml\" >&2; exit 1; }
  ORI_DISCLOSURE_DENYLIST=\$term python -m pytest tests/evidence/test_disclosure.py -m disclosure_release -q
  probe=/tmp/wheelhouse-probe; rm -rf \$probe; cp -r \$ORI_WHEELHOUSE_OUT \$probe
  printf \"LEAKED = \\\"%s\\\"\\n\" \$term > /tmp/probe_leak.py
  (cd /tmp && zip -q \"\$(ls \$probe/*.whl | head -1)\" probe_leak.py)
  if ORI_WHEELHOUSE_OUT=\$probe ORI_DISCLOSURE_DENYLIST=\$term python -m pytest tests/evidence/test_disclosure.py -m disclosure_release -q >/dev/null 2>&1; then
    echo \"the audit accepted a wheelhouse carrying the probe term\" >&2; exit 1
  fi
  rm -rf \$probe /tmp/probe_leak.py"
step "Assemble a release bundle from that wheelhouse" "$SCOPE" -- bash -eo pipefail -c "
  export ORI_WHEELHOUSE_OUT=/tmp/wheelhouse
  target=\"\$(python -c \"import platform, sys; arch = {\\\"x86_64\\\": \\\"x86_64\\\", \\\"amd64\\\": \\\"x86_64\\\", \\\"aarch64\\\": \\\"aarch64\\\", \\\"arm64\\\": \\\"aarch64\\\"}[platform.machine()]; sys.stdout.write(f\\\"linux-{arch}-python{sys.version_info.major}.{sys.version_info.minor}\\\")\")\"
  tag=\"\$(python -c \"
import pathlib, re, sys
text = pathlib.Path(\\\"pyproject.toml\\\").read_text(encoding=\\\"utf-8\\\")
found = re.search(r\\\"^version = \\\\\\\"([^\\\\\\\"]+)\\\\\\\"\\\", text, re.M)
packaged = found.group(1)
parts = re.fullmatch(r\\\"(\\\\d+\\\\.\\\\d+\\\\.\\\\d+)(?:(a|b|rc)(\\\\d+))?\\\", packaged)
base, kind, number = parts.groups()
sys.stdout.write(\\\"v\\\" + (base if kind is None else f\\\"{base}-{kind}.{number}\\\"))
\")\"
  version=\"\$(python scripts/check_release_identity.py --tag \"\$tag\" | cut -d= -f2)\"
  python scripts/build_release_bundle.py --wheelhouse \$ORI_WHEELHOUSE_OUT --runtime-version \"\$version\" --target \"\$target\" --config-template ori.linux.yaml.example --service-template packaging/systemd/ori-runtime.service.in --output-dir /tmp/bundle
  ls -l /tmp/bundle"
step "Type check runtime contract boundaries" "$SCOPE" -- bash scripts/typecheck-boundaries.sh
step "Type check the whole package" "$SCOPE" -- python -m mypy ori/
step "Type check production code (pyright)" "$SCOPE" -- pyright ori/ scripts/
step "Type check the test tree (mypy)" "$SCOPE" -- python -m mypy tests/
step "Hold the pyright count against its baseline (ratchet)" "$SCOPE" -- python scripts/pyright_ratchet.py
step "Pre-commit (lint + format + hygiene)" true -- env SKIP=no-commit-to-branch pre-commit run --show-diff-on-failure --from-ref "$BASE_SHA" --to-ref HEAD
step "Guard Capability Matrix Updated" true -- env GUARD_CAP_MATRIX_BYPASS_TEXT="${PR_BODY:-}" bash scripts/guard-capability-matrix.sh "$BASE_SHA" HEAD
step "Guard Tier Escalation Invariants" "$SCOPE" -- pytest -q tests/test_action_dispatcher.py::TestCapabilityTierGuard tests/test_soundness_verification.py::test_tier_c_dispatch_upgrade tests/test_soundness_verification.py::test_dispatcher_never_downgrades_tier
step "Guard Skill Capability Invariants" "$SCOPE" -- pytest -q tests/test_skill_loader.py::TestValidation::test_missing_defaults_mapping_for_trigger_raises tests/test_skill_loader.py::TestValidation::test_extra_defaults_key_without_trigger_raises
step "Run tests with coverage" "$SCOPE" -- pytest tests/ -q --cov=ori --cov-report=term-missing --cov-report=xml -m "not hardware"
step "Run the tests that read documents" "$DOCS_ONLY" -- pytest -q -m "not hardware" tests/evidence/test_disclosure.py tests/evidence/test_harness.py tests/test_ci_scopes.py tests/test_linux_bootstrap.py tests/test_release_publication.py
step "Installer checks under private-group umask" "$SCOPE" -- bash -c "umask 0002 && pytest -q tests/test_linux_installer.py tests/test_installer_activation.py"
step "System-scope installer checks (root, real venv)" "$SCOPE" -- sudo -H env ORI_REQUIRE_ROOT_TESTS=1 "$(which python)" -m pytest tests/test_installer_system_scope.py -q
step "Audit pinned Python dependencies" "$SCOPE" -- bash -c "python -m pip_audit -r requirements/runtime.txt && python -m pip_audit -r requirements/dev.txt"
step "Generate runtime SBOM" "$SCOPE" -- python -m cyclonedx_py requirements requirements/runtime.txt --pyproject pyproject.toml --output-reproducible --of JSON -o sbom-runtime.json
step "Validate bundled skills load cleanly" "$SCOPE" -- python -c "
import pathlib, sys
from ori.skills.loader import SkillLoader
loader = SkillLoader(); failed = []
for skill_dir in sorted(pathlib.Path(\"skills\").iterdir()):
    if not skill_dir.is_dir(): continue
    try:
        skill = loader.load_one(skill_dir); print(f\"  ok {skill.name} v{skill.version} - {len(skill.triggers)} triggers\")
    except Exception as exc:
        print(f\"  FAILED {skill_dir.name}: {exc}\"); failed.append(skill_dir.name)
sys.exit(1 if failed else 0)"
step "Release wheel smoke test" "$SCOPE" -- bash scripts/smoke-release-wheel.sh

echo
echo "── steps ────────────────────────────────────────────────"
printf "%b" "$RESULTS"
exit $FAILED
}
# The job runs as the unprivileged user, with the functions above and the
# host values carried across.
exec sudo -u runner -H --preserve-env=BASE_SHA,FORCE_ALL,DECIDE_ONLY,PRE_COMMIT_HOME,PIP_CACHE_DIR \
  bash -c "cd /work && $(declare -f step decide pattern_of job); job"
'

docker run --rm --platform "$PLATFORM" \
  -v "${ROOT}:/src:ro" \
  -v "${CACHE_VOLUME}:/cache" \
  -e BASE_SHA="$BASE_SHA" -e FORCE_ALL="$FORCE_ALL" -e DECIDE_ONLY="$DECIDE_ONLY" \
  -e PRE_COMMIT_HOME=/cache/pre-commit \
  -w /work "$IMAGE" bash -c "$CONTAINER_SCRIPT"
STATUS=$?

echo
echo "════════════════════════════════════════════════════════"
if [ "$STATUS" -ne 0 ]; then
  echo "FAILED: a step failed (see the table above)"
  exit 1
fi
if [ "$DECIDE_ONLY" -eq 1 ]; then
  exit 0
fi
if [ ${#NOT_PROOF[@]} -gt 0 ]; then
  echo "every step passed, but this run is not full CI equivalence:"
  printf '  - %s\n' "${NOT_PROOF[@]}"
  exit 3
fi
echo "every step passed, CI-equivalent"
