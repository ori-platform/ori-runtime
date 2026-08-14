#!/usr/bin/env bash
# trust-substituted pre-publication functional evidence harness.
#
# Every claim below is an assertion. A claim that cannot be proven fails the
# run; a claim blocked by the environment is recorded as BLOCKED and changes
# the exit status, so a partial run can never be mistaken for full coverage.
#
# Exit status:
#   0  every required claim proven
#   1  a required claim failed
#   3  claims remain BLOCKED by the environment (partial coverage)
#
# This substitutes the release trust anchor with an ephemeral development key
# and therefore proves nothing about KMS custody, GitHub delivery, redirect
# enforcement, published asset completeness, or publication reverification.
set -euo pipefail

HARNESS_REVISION="7"
TARGET="${1:?usage: harness-linux-functional.sh <target> <commit> <archive> <sha256> <distro>}"
EXPECTED_COMMIT="${2:?expected source commit required}"
ARCHIVE="${3:?source archive required (git archive --format=tar)}"
ARCHIVE_SHA256="${4:?expected archive sha256 required}"
EXPECTED_DISTRO="${5:?expected distro required, e.g. debian:12}"
VERSION="${ORI_EVIDENCE_VERSION:-2.3.1}"
WORK=/work
BLOCKED=0

cleanup() {
    rm -f /tmp/dev-key.pem /tmp/reg.json /tmp/fingerprint.pub
}
trap cleanup EXIT

pass()    { printf '  %-52s PASS\n' "$1"; }
blocked() { printf '  %-52s BLOCKED (%s)\n' "$1" "$2"; BLOCKED=1; }
fail()    { printf '  %-52s FAIL: %s\n' "$1" "$2" >&2; exit 1; }

# Run a command, capture output, and require an exact exit status.
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
    local label="$1" needle="$2" haystack="$3"
    case "$haystack" in
        *"$needle"*) pass "$label" ;;
        *) fail "$label" "expected '$needle' in: $(head -1 <<<"$haystack")" ;;
    esac
}

assert_file() {
    [ -f "$2" ] || fail "$1" "missing file: $2"
    pass "$1"
}

# --- provenance: externally supplied archive, verified by digest ----------
# No Git inside the container: a worktree pointer or a dirty tree would make
# the recorded commit ambiguous. The caller archives an exact commit and passes
# its digest; this only has to confirm it received those bytes.
#
# The commit and the digest are NOT intrinsically bound here — a caller could
# pass an archive of commit A while naming commit B. Binding them is the
# caller's job, which is why `run-evidence.sh` derives both from a single
# commit argument. A reviewer reproduces the digest with:
#
#     git archive --format=tar <commit> | sha256sum
#
# and compares it against the digest recorded in the evidence file.
echo "=== PROVENANCE ==="
[ -f "$ARCHIVE" ] || fail "source archive supplied" "missing: $ARCHIVE"
case "$EXPECTED_COMMIT" in
    [0-9a-f]|[0-9a-f][0-9a-f]*) : ;;
    *) fail "commit is well formed" "malformed: $EXPECTED_COMMIT" ;;
esac
[ "${#EXPECTED_COMMIT}" -eq 40 ] || fail "commit is a full sha1" "got ${#EXPECTED_COMMIT} chars"
case "$ARCHIVE_SHA256" in
    [0-9a-f]*) [ "${#ARCHIVE_SHA256}" -eq 64 ] \
        || fail "archive digest is a full sha256" "got ${#ARCHIVE_SHA256} chars" ;;
    *) fail "archive digest is well formed" "malformed" ;;
esac
actual_sha="$(sha256sum "$ARCHIVE" | cut -d' ' -f1)"
[ "$actual_sha" = "$ARCHIVE_SHA256" ] \
    || fail "source archive digest matches" "expected $ARCHIVE_SHA256, got $actual_sha"
pass "source archive digest $actual_sha"
pass "externally supplied commit $EXPECTED_COMMIT"

# The tuple is a claim about where this ran. Verify it, or the record could
# describe Pi evidence produced on x86_64.
tuple_arch="${TARGET#linux-}"; tuple_arch="${tuple_arch%%-python*}"
tuple_python="${TARGET##*-python}"
actual_arch="$(uname -m)"
[ "$actual_arch" = "$tuple_arch" ] \
    || fail "architecture matches the claimed tuple" \
            "tuple says $tuple_arch, uname -m says $actual_arch"
pass "architecture $actual_arch matches the tuple"

actual_python="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
[ "$actual_python" = "$tuple_python" ] \
    || fail "python matches the claimed tuple" \
            "tuple says $tuple_python, interpreter is $actual_python"
pass "python $(python3 -V 2>&1 | cut -d' ' -f2) matches the tuple"

# Read in a subshell: /etc/os-release defines VERSION, which would otherwise
# clobber this harness's VERSION and be built into the bundle as the runtime
# version. (It did exactly that on the first revision 5 run.)
# shellcheck source=/dev/null
actual_distro="$(. /etc/os-release && echo "${ID:-unknown}:${VERSION_ID:-unknown}")"
# shellcheck source=/dev/null
pretty_name="$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
[ "$actual_distro" = "$EXPECTED_DISTRO" ] \
    || fail "distribution matches the expected platform" \
            "expected $EXPECTED_DISTRO, found $actual_distro"
pass "distribution $actual_distro ($pretty_name)"

printf '  harness revision %s, target %s\n' "$HARNESS_REVISION" "$TARGET"

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq python3-pip python3-venv >/dev/null 2>&1
mkdir -p "$WORK" && tar -C "$WORK" -xf "$ARCHIVE"
cd "$WORK"
python3 -m pip install --quiet --break-system-packages cryptography pyyaml >/dev/null 2>&1

# --- substitute BOTH trust anchors, before building -----------------------
echo "=== TRUST ANCHOR SUBSTITUTION (before build) ==="
python3 - <<'PY'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, NoEncryption, PrivateFormat, PublicFormat,
)
import base64, hashlib, json, pathlib, re

key = Ed25519PrivateKey.generate()  # ephemeral; never a release key
pathlib.Path("/tmp/dev-key.pem").write_bytes(
    key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
public = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
b64 = base64.b64encode(public).decode()
digest = hashlib.sha256(public).hexdigest()
pathlib.Path("/tmp/fingerprint.pub").write_text(f"{b64}\n{digest}\n")

registry = pathlib.Path("/work/ori/installer/release-keys.json")
document = json.loads(registry.read_text())
for entry in document["keys"]:
    entry["public_key_b64"] = b64
registry.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")

bootstrap = pathlib.Path("/work/scripts/install-linux.sh")
text = bootstrap.read_text()
text, n1 = re.subn(r'PUBLIC_KEY_B64 = "[^"]+"', f'PUBLIC_KEY_B64 = "{b64}"', text, count=1)
text, n2 = re.subn(r'PUBLIC_KEY_SHA256 = "[^"]+"', f'PUBLIC_KEY_SHA256 = "{digest}"', text, count=1)
assert n1 == 1 and n2 == 1, "bootstrap anchor substitution did not apply"
bootstrap.write_text(text)
print(f"  ephemeral key sha256:{digest}")
PY
chmod 600 /tmp/dev-key.pem
python3 -m pip install --quiet --break-system-packages --no-deps -e . >/dev/null 2>&1

# --- determinism: build twice, compare bytes ------------------------------
echo "=== BUILD ==="
build_once() {
    ORI_WHEELHOUSE_OUT="$1/wh" ORI_WHEELHOUSE_TARGET=generic \
    ORI_RELEASE_BUNDLE_VERSION="$VERSION" ORI_RELEASE_BUNDLE_TARGET="$TARGET" \
    ORI_RELEASE_BUNDLE_OUT="$1/bundle" SOURCE_DATE_EPOCH=1700000000 \
        bash scripts/build-wheelhouse.sh >"$1/build.log" 2>&1 \
        || { tail -5 "$1/build.log" >&2; return 1; }
}
mkdir -p /tmp/b1 /tmp/b2
build_once /tmp/b1 || fail "first bundle build" "see build log"
pass "first bundle build"
build_once /tmp/b2 || fail "second bundle build" "see build log"
pass "second bundle build"

ARTIFACT="/tmp/b1/bundle/ori-runtime-$VERSION-$TARGET.tar.gz"
SECOND="/tmp/b2/bundle/ori-runtime-$VERSION-$TARGET.tar.gz"
h1="$(sha256sum "$ARTIFACT" | cut -d' ' -f1)"
h2="$(sha256sum "$SECOND" | cut -d' ' -f1)"
[ "$h1" = "$h2" ] || fail "build is deterministic" "sha256 differs: $h1 vs $h2"
pass "build is deterministic (two builds, identical sha256)"
printf '  artifact sha256 %s\n' "$h1"

# --- sign the final immutable artifact; never patch it afterwards ---------
python3 - <<'PY'
from ori.security.release_bundles import KEY_REGISTRY_SCHEMA, RELEASE_KEY_PURPOSE
import json, pathlib
b64 = pathlib.Path("/tmp/fingerprint.pub").read_text().splitlines()[0]
pathlib.Path("/tmp/reg.json").write_text(json.dumps({
    "schema": KEY_REGISTRY_SCHEMA,
    "keys": [{"key_id": "ori-runtime-release-2026-01", "public_key_b64": b64,
              "purpose": RELEASE_KEY_PURPOSE, "status": "active"}]}))
PY
python3 scripts/sign-release-bundle.py --artifact "$ARTIFACT" \
    --runtime-version "$VERSION" --target "$TARGET" \
    --key-id ori-runtime-release-2026-01 --key-registry /tmp/reg.json \
    --private-key-file /tmp/dev-key.pem --output "$ARTIFACT.signature.json" \
    >/dev/null 2>&1 || fail "sign final artifact" "signing failed"
assert_file "signature envelope produced" "$ARTIFACT.signature.json"

# The only post-signing substitution: the bootstrap's download(), because the
# real one hard-enforces the https://github.com origin. The artifact itself is
# never modified after signing.
cp scripts/install-linux.sh /tmp/boot.py
python3 - <<'PY'
import pathlib
p = pathlib.Path("/tmp/boot.py"); t = p.read_text()
start = t.index("def download("); end = t.index("\ndef ", start + 10)
stub = ('def download(url: str, destination: Path, limit: int) -> None:\n'
        '    import shutil as _sh\n'
        '    _sh.copyfile("/tmp/b1/bundle/" + url.rsplit("/", 1)[1], destination)\n')
p.write_text(t[:start] + stub + t[end:])
PY

# --- dispatch: exact exit status and stable code, unmodified bootstrap ----
echo "=== DISPATCH (unmodified bootstrap) ==="
cp scripts/install-linux.sh /tmp/orig.sh
cp scripts/install-linux.sh /tmp/renamed-installer.sh
chmod +x /tmp/orig.sh /tmp/renamed-installer.sh

DISPATCH_CODE="artifact_integrity_mismatch"
assert_exit "dispatch: original name exits 2" 2 /tmp/orig.sh --version "$VERSION"
assert_contains "dispatch: original name stable code" "$DISPATCH_CODE" "$LAST_OUTPUT"
assert_exit "dispatch: renamed copy exits 2" 2 /tmp/renamed-installer.sh --version "$VERSION"
assert_contains "dispatch: renamed copy stable code" "$DISPATCH_CODE" "$LAST_OUTPUT"
assert_exit "dispatch: absolute path exits 2" 2 bash /tmp/orig.sh --version "$VERSION"
assert_contains "dispatch: absolute path stable code" "$DISPATCH_CODE" "$LAST_OUTPUT"
assert_exit "dispatch: relative path exits 2" 2 \
    bash -c "cd /tmp && ./orig.sh --version $VERSION"
assert_contains "dispatch: relative path stable code" "$DISPATCH_CODE" "$LAST_OUTPUT"
assert_exit "dispatch: piped exits 2" 2 \
    bash -c "cat /tmp/orig.sh | bash -s -- --version $VERSION"
assert_contains "dispatch: piped stable code" "$DISPATCH_CODE" "$LAST_OUTPUT"
assert_exit "dispatch: piped without arguments exits 2" 2 \
    bash -c "cat /tmp/orig.sh | bash"
assert_contains "dispatch: piped without arguments shows usage" \
    "usage:" "$LAST_OUTPUT"

# --- tamper rejection: exact code, nonzero status -------------------------
echo "=== TAMPER REJECTION ==="
INSTALL_ARGS=(--scope user --unattended --device-id ev-01 --name Ev --location Lagos)
cp "$ARTIFACT" /tmp/pristine.tar.gz
cp "$ARTIFACT.signature.json" /tmp/pristine.sig

# (a) artifact bytes changed: the envelope still carries the original digest,
# so this is caught as an integrity mismatch before any signature check runs.
before_tamper="$(sha256sum "$ARTIFACT" | cut -d' ' -f1)"
printf '\x00' | dd of="$ARTIFACT" bs=1 seek=900 conv=notrunc status=none
after_tamper="$(sha256sum "$ARTIFACT" | cut -d' ' -f1)"
[ "$before_tamper" != "$after_tamper" ] \
    || fail "artifact was actually modified" "sha256 unchanged: $after_tamper"
pass "artifact was actually modified"
assert_exit "tampered artifact rejected (exit 2)" 2 \
    bash /tmp/boot.py --version "$VERSION" -- "${INSTALL_ARGS[@]}"
assert_contains "tampered artifact code" "artifact_integrity_mismatch" "$LAST_OUTPUT"
cp /tmp/pristine.tar.gz "$ARTIFACT"

# (b) malformed signature field: dropping the ed25519: prefix fails envelope
# validation, before the signature is ever evaluated.
python3 - "$ARTIFACT.signature.json" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d = json.loads(p.read_text())
d["signature"] = "A" * len(d["signature"])
p.write_text(json.dumps(d))
PY
assert_exit "malformed envelope rejected (exit 2)" 2 \
    bash /tmp/boot.py --version "$VERSION" -- "${INSTALL_ARGS[@]}"
assert_contains "malformed envelope code" "invalid_signature_envelope" "$LAST_OUTPUT"
cp /tmp/pristine.sig "$ARTIFACT.signature.json"

# (c) well-formed but incorrect signature: keep the prefix and valid base64 so
# the envelope parses, leaving only the cryptographic check to reject it.
python3 - "$ARTIFACT.signature.json" <<'PY'
import base64, json, pathlib, sys
p = pathlib.Path(sys.argv[1]); d = json.loads(p.read_text())
raw = bytearray(base64.b64decode(d["signature"].removeprefix("ed25519:")))
raw[0] ^= 0xFF  # still 64 valid bytes, no longer a valid signature
d["signature"] = "ed25519:" + base64.b64encode(bytes(raw)).decode()
p.write_text(json.dumps(d))
PY
assert_exit "incorrect signature rejected (exit 2)" 2 \
    bash /tmp/boot.py --version "$VERSION" -- "${INSTALL_ARGS[@]}"
assert_contains "incorrect signature code" "signature_verification_failed" "$LAST_OUTPUT"
cp /tmp/pristine.sig "$ARTIFACT.signature.json"

# --- install as an unprivileged operator ----------------------------------
echo "=== INSTALL (user scope, unprivileged) ==="
id -u oriop >/dev/null 2>&1 || useradd -m -u 1000 -s /bin/bash oriop
chmod -R a+rX /tmp/b1/bundle /tmp/boot.py
HOME_DIR=/home/oriop

set +e
su oriop -c "bash /tmp/boot.py --version $VERSION -- ${INSTALL_ARGS[*]}" \
    >/tmp/install.log 2>&1
install_status=$?
set -e

if [ "$install_status" -eq 0 ] && [ -d "$HOME_DIR/.local/ori/current" ]; then
    pass "install produced an active release"
    BIN="$HOME_DIR/.local/ori/current/venv/bin"

    for script in ori-runtime ori-install-linux ori-config-install \
                  ori-phone-doctor ori-firmware-provisioner \
                  ori-inverter-profile-doctor; do
        [ -f "$BIN/$script" ] || fail "console script $script present" "not installed"
        su oriop -c "$BIN/$script --help" >/dev/null 2>&1 \
            || fail "console script $script executes" "non-zero exit"
        pass "console script $script executes"
    done

    # Only meaningful because venv/bin demonstrably exists above.
    if grep -rl "ori-release-\|/staging/" "$BIN"/* >/dev/null 2>&1; then
        fail "no stale staging paths in venv/bin" "found staging references"
    fi
    pass "no stale staging paths in venv/bin"

    grep -q "VIRTUAL_ENV=" "$BIN/activate" || fail "activation script rebound" "no VIRTUAL_ENV"
    pass "activation script rebound"

    su oriop -c "bash /tmp/boot.py --version $VERSION -- ${INSTALL_ARGS[*]}" \
        >/tmp/reinstall.log 2>&1 || fail "same-version reinstall" "non-zero exit"
    pass "same-version reinstall"

    su oriop -c "$BIN/ori-install-linux uninstall --scope user --remove-data" \
        >/tmp/uninstall.log 2>&1 || fail "uninstall" "non-zero exit"
    [ -d "$HOME_DIR/.local/ori/current" ] && fail "uninstall removed the release" "still present"
    pass "uninstall removed the release"
else
    # Expected in a container: systemctl --user has no session bus. Everything
    # downstream is unproven, and must not be reported as absent or passing.
    detail="$(tail -1 /tmp/install.log)"
    if [ -d /run/systemd/system ]; then
        fail "install produced an active release" "$detail"
    fi
    blocked "install and all downstream service claims" "no systemd session bus"
    printf '      installer reported: %s\n' "$detail"
    for claim in "console script execution" "stale staging paths" \
                 "activation script rebinding" "same-version reinstall" \
                 "uninstall and launcher removal"; do
        blocked "$claim" "requires a surviving installed release"
    done
    # Rollback is provable here: the failed transaction must leave nothing active.
    [ -d "$HOME_DIR/.local/ori/current" ] \
        && fail "failed install rolls back cleanly" "an active release survived"
    pass "failed install rolls back cleanly (no active release)"
fi

echo "=== RESULT ==="
if [ "$BLOCKED" -eq 1 ]; then
    printf '  partial coverage: some claims BLOCKED by the environment\n'
    exit 3
fi
printf '  every required claim proven\n'
