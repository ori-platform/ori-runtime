#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Pre-publication system-scope evidence, on a real systemd host.
#
# The container harness marks installation and every downstream service claim
# BLOCKED, because a container has no systemd session bus. Those are exactly
# the claims release candidates have failed on hardware, so they are proven
# here instead: on the machine, as root, against an artifact built and
# development-signed from a named commit.
#
# Every claim is an assertion. A claim that cannot be proven fails the run; a
# claim the environment blocks is recorded as BLOCKED and changes the exit
# status, so partial coverage can never read as full coverage.
#
# Exit status:
#   0  every required claim proven
#   1  a required claim failed
#   3  claims remain BLOCKED by the environment (partial coverage)
#
# The full procedure — prerequisites, how to capture each phase's exit status,
# what to record, and how to reset the host — is in systemd-host-runbook.md
# beside this file. Reboot cannot be spanned by one process, so the run has
# phases:
#
#   sudo ./harness-systemd-host.sh install <bundle> <sig> <registry> <sha256> <version>
#   # reboot the host
#   sudo ./harness-systemd-host.sh persist <version>
#   sudo ./harness-systemd-host.sh rollback <bundle> <sig> <registry> <sha256> <version>
#   sudo ./harness-systemd-host.sh uninstall
#
# The artifact is verified before anything from it is extracted or executed.
# Installing first and letting the newly installed code check its own source
# would invert the trust boundary: this runs as root, so the digest and the
# signature are checked with tooling that predates the artifact — coreutils and
# openssl — against a registry and digest supplied by the caller.
#
# This proves nothing about KMS custody, the production trust root, GitHub
# publication, authenticated download, published asset completeness, or
# post-publication reverification. Those belong to the protected release
# workflow and are proven only by a real tag.
set -euo pipefail

HARNESS_REVISION="12"
PHASE="${1:?usage: harness-systemd-host.sh <install|persist|rollback|uninstall> ...}"
BLOCKED=0
UNIT="ori-runtime.service"
SYSTEM_ROOT="/opt/ori"

# Deterministic, so the resulting config and diagnosis can be asserted rather
# than merely produced.
EVIDENCE_DEVICE_ID="ori-rc-evidence"
EVIDENCE_NAME="Ori Release Candidate Evidence"
EVIDENCE_LOCATION="Pre-publication test host"
# Root-owned, and outside the install root so the installer's own uninstall
# cannot remove it mid-run. The harness clears it in its uninstall phase.
STATE_FILE="/var/lib/ori-evidence-state"

pass()    { printf '  %-56s PASS\n' "$1"; }
blocked() { printf '  %-56s BLOCKED (%s)\n' "$1" "$2"; BLOCKED=1; }
fail()    { printf '  %-56s FAIL: %s\n' "$1" "$2" >&2; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || fail "running as root" "re-run with sudo"
}

# systemd must be the init system, not merely installed: `systemctl` exists in
# images that cannot run a unit, and a BLOCKED run there would look like a pass
# to anyone reading only the exit status.
require_systemd() {
    [ -d /run/systemd/system ] \
        || fail "systemd is the init system" "/run/systemd/system is absent"
    command -v systemctl >/dev/null 2>&1 || fail "systemctl is available" "not on PATH"
}

# Root-owned and private. A predictable path under /tmp is writable by every
# account on the host, so a root process writing there can be aimed elsewhere
# through a symlink planted in advance.
make_workspace() {
    WORKSPACE="$(mktemp -d "$SYSTEM_ROOT-evidence-XXXXXX")"
    chmod 700 "$WORKSPACE"
}

record_host() {
    # shellcheck source=/dev/null
    local pretty; pretty="$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
    printf '=== HOST ===\n'
    printf '  harness revision  %s (phase %s)\n' "$HARNESS_REVISION" "$PHASE"
    printf '  distribution      %s\n' "$pretty"
    printf '  kernel            %s\n' "$(uname -sr)"
    printf '  architecture      %s\n' "$(uname -m)"
    printf '  systemd           %s\n' "$(systemctl --version | head -1)"
    printf '  python3           %s (%s)\n' \
        "$(python3 -V 2>&1 | cut -d' ' -f2)" "$(command -v python3)"
    printf '  base interpreter  %s\n' \
        "$(python3 -c 'import sys; print(sys._base_executable)')"
}

assert_exit() {
    local label="$1" expected="$2"; shift 2
    local output status
    set +e; output="$("$@" 2>&1)"; status=$?; set -e
    [ "$status" -eq "$expected" ] \
        || fail "$label" "expected exit $expected, got $status: $(head -1 <<<"$output")"
    LAST_OUTPUT="$output"
    pass "$label"
}

assert_contains() {
    case "$3" in
        *"$2"*) pass "$1" ;;
        *) fail "$1" "expected '$2' in: $(head -3 <<<"$3")" ;;
    esac
}

finish() {
    if [ "$BLOCKED" -eq 1 ]; then
        printf '\n  partial coverage: claims BLOCKED by this environment\n'
        exit 3
    fi
    printf '\n  every required claim proven for phase %s\n' "$PHASE"
}

# --- verification and binding live in Python ---------------------------------
#
# Five review rounds found the same defect in five shell variables: a value
# checked in one place and used in another. `scripts/evidence_host.py` makes
# each of them a function argument — the target parsed from the signed
# envelope, the interpreter selected and validated in one act, the digest and
# signature checked with tooling that predates the artifact, the install record
# written atomically and bound to its version. Shell keeps `sudo`, systemctl,
# and phase dispatch.
EVIDENCE_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)/scripts/evidence_host.py"
[ -f "$EVIDENCE_PY" ] || fail "the evidence module is present" "$EVIDENCE_PY"

evidence() {
    python3 "$EVIDENCE_PY" "$@"
}

verify_artifact() {
    local bundle="$1" signature="$2" registry="$3" expected_sha="$4" version="$5"
    local output
    if ! output="$(evidence verify --bundle "$bundle" --signature "$signature" \
            --registry "$registry" --sha256 "$expected_sha" --version "$version" \
            --workspace "$WORKSPACE/verify" 2>&1)"; then
        fail "the artifact verifies before extraction" "$output"
    fi
    pass "verified before extraction: $output"
}

select_tooling_interpreter() {
    local signature="$1" output
    if ! output="$(evidence select-python --signature "$signature" 2>&1)"; then
        fail "an interpreter matching the artifact's target" "$output"
    fi
    TOOLING_PYTHON="$output"
    pass "tooling interpreter $TOOLING_PYTHON matches the artifact target"
}

# The bundle's own hash-locked wheelhouse, in the order the bootstrap uses:
# pinned dependencies with hashes enforced, then the one runtime wheel.
install_release_tooling() {
    local extracted="$1" destination="$2"
    "${TOOLING_PYTHON:?select_tooling_interpreter must run first}" \
        -m venv "$destination" >/dev/null
    "$destination/bin/pip" install --quiet --no-index --require-hashes \
        --find-links "$extracted/wheelhouse" \
        -r "$extracted/wheelhouse/requirements.txt" >/dev/null
    local wheel
    wheel="$(find "$extracted/wheelhouse" -maxdepth 1 -name 'ori_runtime-*.whl' | head -1)"
    [ -n "$wheel" ] || fail "the wheelhouse holds a runtime wheel" "none found"
    "$destination/bin/pip" install --quiet --no-index --no-deps "$wheel" >/dev/null
}

# --- install ------------------------------------------------------------------

phase_install() {
    local bundle="${2:?bundle path required}"
    local signature="${3:?signature path required}"
    local registry="${4:?development key registry required}"
    local expected_sha="${5:?expected artifact sha256 required}"
    local version="${6:?release version required}"
    require_root; require_systemd; record_host; make_workspace
    trap 'rm -rf "$WORKSPACE"' EXIT

    echo "=== VERIFY (before extraction) ==="
    verify_artifact "$bundle" "$signature" "$registry" "$expected_sha" "$version"

    select_tooling_interpreter "$signature"

    echo "=== CLEAN STATE ==="
    [ ! -e "$SYSTEM_ROOT" ] \
        || fail "no prior system installation" "$SYSTEM_ROOT exists; uninstall first"
    if systemctl list-unit-files "$UNIT" 2>/dev/null | grep -q "$UNIT"; then
        fail "no prior unit" "$UNIT is already known to systemd"
    fi
    [ ! -e /usr/local/bin/ori ] \
        || fail "no prior launcher" "/usr/local/bin/ori exists; uninstall first"
    pass "no prior system installation"

    echo "=== INSTALL (system scope) ==="
    tar -C "$WORKSPACE" -xf "$bundle"
    local extracted
    extracted="$(find "$WORKSPACE" -maxdepth 1 -mindepth 1 -type d | head -1)"
    install_release_tooling "$extracted" "$WORKSPACE/venv"

    assert_exit "install completes" 0 \
        "$WORKSPACE/venv/bin/ori-install-linux" install \
            --scope system --unattended \
            --bundle "$bundle" --signature "$signature" \
            --expected-version "$version" \
            --device-id "$EVIDENCE_DEVICE_ID" \
            --name "$EVIDENCE_NAME" \
            --location "$EVIDENCE_LOCATION" \
            --json
    local report="$LAST_OUTPUT"
    assert_contains "install reports healthy" '"status": "healthy"' "$report"
    assert_contains "install reports system scope" '"scope": "system"' "$report"
    assert_contains "install reports the requested version" "\"version\": \"$version\"" "$report"
    assert_contains "install reports the evidence device" \
        "\"device_id\": \"$EVIDENCE_DEVICE_ID\"" "$report"

    echo "=== LAUNCHER ==="
    # A launcher conflict is deliberately non-fatal, so an installation can
    # report healthy having installed no `ori` command at all. Diagnosing
    # through the absolute venv path would never notice.
    assert_contains "launcher was installed" '"launcher_installed": true' "$report"
    local launcher="/usr/local/bin/ori"
    [ -x "$launcher" ] || fail "launcher is executable" "$launcher"
    assert_contains "install reports the expected launcher path" \
        "\"launcher_path\": \"$launcher\"" "$report"
    assert_exit "doctor runs through the launcher" 0 \
        "$launcher" doctor --scope system --json
    assert_contains "the launcher diagnosed this installation" \
        "\"device_id\": \"$EVIDENCE_DEVICE_ID\"" "$LAST_OUTPUT"

    echo "=== CONFIG ==="
    local config="$SYSTEM_ROOT/data/ori.yaml"
    [ -f "$config" ] || fail "config was written" "$config is absent"
    assert_contains "config carries the evidence device id" \
        "$EVIDENCE_DEVICE_ID" "$(cat "$config")"
    assert_contains "config carries the evidence location" \
        "$EVIDENCE_LOCATION" "$(cat "$config")"

    echo "=== SERVICE ==="
    assert_exit "unit is active" 0 systemctl is-active --quiet "$UNIT"
    assert_exit "unit is enabled for boot" 0 systemctl is-enabled --quiet "$UNIT"
    assert_contains "unit runs as ori-runtime" "User=ori-runtime" "$(systemctl cat "$UNIT")"

    echo "=== HEALTH SOCKET ==="
    local socket="$SYSTEM_ROOT/data/health.sock"
    [ -S "$socket" ] || fail "health socket exists" "not a socket: $socket"
    pass "health socket exists"

    echo "=== INSTALLED DOCTOR ==="
    assert_exit "installed doctor reports no blocking failure" 0 \
        "$SYSTEM_ROOT/current/venv/bin/ori" doctor --scope system --json
    local diagnosis="$LAST_OUTPUT"
    assert_contains "doctor diagnosed this installation" '"scope": "system"' "$diagnosis"
    assert_contains "doctor reports the requested version" \
        "\"version\": \"$version\"" "$diagnosis"
    assert_contains "doctor reports the evidence device" \
        "\"device_id\": \"$EVIDENCE_DEVICE_ID\"" "$diagnosis"

    # The defect that rolled back every rc.4 system install: an ordinary venv
    # interpreter refused because a symlink's mode reads as world-writable.
    case "$diagnosis" in
        *'"name": "permissions.code"'*'"status": "FAIL"'*)
            fail "code integrity passes on a real venv" "permissions.code reported FAIL" ;;
        *'"name": "permissions.code"'*) pass "code integrity passes on a real venv" ;;
        *) fail "code integrity was assessed" "permissions.code absent from the report" ;;
    esac

    # Last, and only now. Written earlier, a record of this boot would survive
    # any assertion above failing, and the persistence phase would later treat
    # a failed installation as its provenance.
    evidence record --path "$STATE_FILE" --version "$version" >/dev/null \
        || fail "the installation was recorded" "could not write $STATE_FILE"
    pass "install boot recorded, after every install assertion passed"
    finish
}

# --- persist (after a reboot) --------------------------------------------------

phase_persist() {
    local version="${2:?release version required}"
    require_root; require_systemd; record_host

    echo "=== REBOOT PERSISTENCE ==="
    local record
    if ! record="$(evidence require-reboot --path "$STATE_FILE" \
            --version "$version" 2>&1)"; then
        fail "the host rebooted since this release was installed" "$record"
    fi
    pass "the host rebooted since this release was installed ($record)"

    assert_exit "unit is active after reboot" 0 systemctl is-active --quiet "$UNIT"
    assert_exit "unit is still enabled" 0 systemctl is-enabled --quiet "$UNIT"
    assert_exit "doctor is healthy after reboot" 0 \
        "$SYSTEM_ROOT/current/venv/bin/ori" doctor --scope system --json
    assert_contains "doctor still reports the release under test" \
        "\"version\": \"$version\"" "$LAST_OUTPUT"
    finish
}

# --- rollback on a failure that reaches activation ----------------------------

phase_rollback() {
    local bundle="${2:-}" signature="${3:-}" registry="${4:-}"
    local expected_sha="${5:-}" version="${6:-}"
    require_root; require_systemd; record_host

    echo "=== ROLLBACK ==="
    local previous; previous="$(readlink -f "$SYSTEM_ROOT/current" 2>/dev/null || echo none)"
    [ "$previous" != "none" ] || fail "an installation to roll back from" "no active release"
    printf '  active release before  %s\n' "$previous"

    # Rollback needs a failure *after* activation. A tampered or mis-signed
    # artifact cannot produce one: verification refuses it before anything is
    # installed, and treating that refusal as rollback would prove nothing while
    # reporting PASS. This phase therefore needs an artifact that installs and
    # then fails its own post-install diagnosis.
    if [ -z "$bundle" ] || [ ! -f "$bundle" ] || [ -z "$version" ]; then
        blocked "rollback restores the previous release" \
                "no post-activation-failing artifact supplied"
        printf '  supply one as: rollback <bundle> <sig> <registry> <sha256> <version>\n'
        finish
        return
    fi

    make_workspace
    trap 'rm -rf "$WORKSPACE"' EXIT
    verify_artifact "$bundle" "$signature" "$registry" "$expected_sha" "$version"
    select_tooling_interpreter "$signature"
    tar -C "$WORKSPACE" -xf "$bundle"
    local extracted
    extracted="$(find "$WORKSPACE" -maxdepth 1 -mindepth 1 -type d | head -1)"
    install_release_tooling "$extracted" "$WORKSPACE/venv"

    set +e
    "$WORKSPACE/venv/bin/ori-install-linux" install \
        --scope system --unattended \
        --bundle "$bundle" --signature "$signature" \
        --expected-version "$version" \
        --device-id "$EVIDENCE_DEVICE_ID" --name "$EVIDENCE_NAME" \
        --location "$EVIDENCE_LOCATION" --json >"$WORKSPACE/rollback.json" 2>&1
    local status=$?
    set -e
    local output; output="$(cat "$WORKSPACE/rollback.json")"

    # The exact stable code, not "some nonzero exit": an argument error, a
    # signature rejection or a target mismatch all exit nonzero without ever
    # activating anything, and would otherwise be recorded as a rollback.
    assert_contains "the candidate failed after activation" \
        "post_install_health_failed" "$output"
    [ "$status" -ne 0 ] || fail "the failing artifact actually failed" "install reported success"

    local after; after="$(readlink -f "$SYSTEM_ROOT/current")"
    printf '  active release after   %s\n' "$after"
    [ "$after" = "$previous" ] \
        || fail "rollback restored the previous release" \
                "active moved from $previous to $after"
    pass "rollback restored the previous release"

    [ ! -e "$SYSTEM_ROOT/releases/$version" ] \
        || fail "the failed candidate was removed" \
                "$SYSTEM_ROOT/releases/$version remains"
    pass "the failed candidate was removed"

    assert_exit "service still active after rollback" 0 systemctl is-active --quiet "$UNIT"
    assert_exit "doctor still healthy after rollback" 0 \
        "$SYSTEM_ROOT/current/venv/bin/ori" doctor --scope system --json
    finish
}

# --- uninstall -----------------------------------------------------------------

phase_uninstall() {
    require_root; require_systemd; record_host
    echo "=== UNINSTALL ==="
    # The installer removes its own tree, including data, because the evidence
    # installation exists only for this run. Retention under the default flag is
    # the installer's behaviour and is covered by the unit suite; asserting it
    # here would mean deleting the retained data afterwards by hand.
    assert_exit "uninstall completes" 0 \
        "$SYSTEM_ROOT/current/venv/bin/ori-install-linux" \
            uninstall --scope system --remove-data
    if systemctl list-unit-files "$UNIT" 2>/dev/null | grep -q "$UNIT"; then
        fail "unit removed" "$UNIT is still known to systemd"
    fi
    pass "unit removed"

    # Every managed path, by name. `rmdir` below is the proof that nothing else
    # was left, but it cannot say which of these survived.
    local leftover
    for leftover in current releases data; do
        [ ! -e "$SYSTEM_ROOT/$leftover" ] \
            || fail "uninstall removed $leftover" "$SYSTEM_ROOT/$leftover remains"
    done
    pass "no release, data or active symlink remains"

    # Deliberate: files elsewhere may belong to it, and a freed uid can be
    # reused by a later account.
    if getent passwd ori-runtime >/dev/null; then
        pass "service account retained, as designed"
    else
        blocked "service account retained" "ori-runtime absent"
    fi

    rm -f "$STATE_FILE"
    pass "evidence state removed ($STATE_FILE)"

    # Non-recursive, and never forced. `rmdir` removes a directory only when it
    # is already empty, so it cannot delete anything the installer chose to
    # keep, cannot descend into a real deployment, and refuses outright on a
    # symlink. What is left behind is reported rather than destroyed — a
    # recursive removal here would be authorised by nothing stronger than this
    # harness having been pointed at the host.
    if rmdir "$SYSTEM_ROOT" 2>/dev/null; then
        pass "install root removed; a further run starts clean"
    else
        blocked "install root removed" \
                "$SYSTEM_ROOT is not empty: $(ls -A "$SYSTEM_ROOT" 2>/dev/null | tr '\n' ' ')"
    fi

    # The account is retained by design and does not block a further run:
    # installation reuses an existing usable account and creates one only when
    # it is absent.
    printf '\n  retained on this host: the ori-runtime service account\n'
    printf '  remove it deliberately if you want it gone: userdel ori-runtime\n'
    finish
}

case "$PHASE" in
    install)   phase_install "$@" ;;
    persist)   phase_persist "$@" ;;
    rollback)  phase_rollback "$@" ;;
    uninstall) phase_uninstall "$@" ;;
    *) fail "known phase" "unknown phase '$PHASE'" ;;
esac
