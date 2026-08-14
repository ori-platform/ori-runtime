#!/usr/bin/env bash
# Host-side driver for the trust-substituted functional evidence harness.
#
# Takes ONE commit and derives everything else from it: the archive, its
# digest, and the values handed to the container. That binding is the point —
# the harness cannot tell whether a separately typed commit describes the
# archive it received, so nobody should be typing them separately.
#
# A reviewer reproduces the recorded digest with:
#     git archive --format=tar <commit> | sha256sum
#
# Usage: run-evidence.sh <commit> <target> <image> <distro>
# Exit:  0 all claims proven · 1 a claim failed · 3 partial (BLOCKED claims)
set -euo pipefail

COMMIT="${1:?usage: run-evidence.sh <commit> <target> <image> <distro>}"
TARGET="${2:?target tuple required, e.g. linux-aarch64-python3.11}"
IMAGE="${3:?container image required}"
DISTRO="${4:?expected distro required, e.g. debian:12}"

REPO_ROOT="$(git rev-parse --show-toplevel)"
HARNESS="$REPO_ROOT/docs/releases/evidence/harness-linux-functional.sh"
[ -f "$HARNESS" ] || { echo "harness not found: $HARNESS" >&2; exit 1; }

# Resolve to a full sha1 so the recorded commit is unambiguous.
FULL_COMMIT="$(git -C "$REPO_ROOT" rev-parse "$COMMIT^{commit}")"

# A directory, not `mktemp ... .tar`: appending a suffix to a mktemp result
# yields a different path, leaking the original file and losing the atomic
# creation that made mktemp worth using.
# Created under a path the container runtime can bind-mount. On macOS the
# system temp directory (/var/folders/...) is not shared with Docker Desktop,
# which silently yields an empty mount rather than an error.
WORKDIR="$(mktemp -d "${ORI_EVIDENCE_TMPDIR:-$HOME}/ori-evidence-XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT
ARCHIVE="$WORKDIR/source.tar"
git -C "$REPO_ROOT" archive --format=tar --output="$ARCHIVE" "$FULL_COMMIT"

DIGEST=""  # computed below, after digest_of is defined

# Hash the procedure itself. Evidence must describe the bytes that ran, so an
# edit after a run invalidates that run rather than silently inheriting it.
digest_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}
DIGEST="$(digest_of "$ARCHIVE")"
HARNESS_SHA256="$(digest_of "$HARNESS")"
DRIVER_SHA256="$(digest_of "${BASH_SOURCE[0]}")"

# A tag is mutable, and it can be repointed between inspection and execution.
# Resolve it once and run the immutable ID, so the recorded identity is the
# identity that ran.
IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE")"
IMAGE_DIGESTS="$(docker image inspect --format '{{join .RepoDigests ","}}' "$IMAGE")"

cat <<SUMMARY
=== EVIDENCE RUN ===
  commit          $FULL_COMMIT
  archive sha256  $DIGEST
  target          $TARGET
  image           $IMAGE
  image id        $IMAGE_ID
  image digests   ${IMAGE_DIGESTS:-<none: locally built, not pulled>}
  harness sha256  $HARNESS_SHA256
  driver sha256   $DRIVER_SHA256
  reproduce with  git archive --format=tar $FULL_COMMIT | sha256sum
SUMMARY

# Capture the harness status directly. A pipeline would report the status of
# whatever it was piped into, which is how an earlier run reported exit 0 for
# a harness that had exited 1.
set +e
docker run --rm \
    -v "$ARCHIVE":/src.tar:ro \
    -v "$REPO_ROOT/docs/releases/evidence":/evidence:ro \
    "$IMAGE_ID" \
    bash /evidence/harness-linux-functional.sh \
        "$TARGET" "$FULL_COMMIT" /src.tar "$DIGEST" "$DISTRO"
STATUS=$?
set -e

echo "=== HARNESS EXIT: $STATUS ==="
case "$STATUS" in
    0) echo "  every required claim proven" ;;
    3) echo "  partial coverage: claims BLOCKED by the environment" ;;
    *) echo "  a required claim failed" >&2 ;;
esac
exit "$STATUS"
