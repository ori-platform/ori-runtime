#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Build the Android-native Phone Starter runtime payload expected by APK
# provisioning. The resulting files are real ELF executables named
# libori_runtime_exec.so so Android extracts them into nativeLibraryDir where
# the APK can execute them without violating Android W^X rules.
#
# The name is a packaging requirement and not a description: nothing loads
# these as shared libraries, they are exec'd as processes. Android only
# populates nativeLibraryDir from APK entries matching lib/<abi>/*.so.
#
# Every check the consuming APK's release gate makes is made here too, so a
# payload that would be refused at packaging fails at the point it was built,
# where the toolchain that produced it is still at hand.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="${ROOT}/mobile/ori-runtime-mobile"
OUT="${ORI_ANDROID_RUNTIME_PAYLOAD_OUT:-${ROOT}/dist/android-runtime-payloads}"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/mobile/target}"

# Pinned rather than left to cargo-ndk's default, so an upgrade of the tool
# cannot move it silently. 21 is at or below every consuming APK's minSdk, so
# one binary serves all of them; a binary built for a lower API level runs on
# higher ones, not the reverse.
PLATFORM="${ORI_ANDROID_RUNTIME_PAYLOAD_PLATFORM:-21}"

# Debug symbols are a third of the artefact and nothing on the device reads
# them. Set to 0 to keep them when a crash needs symbolising.
STRIP="${ORI_ANDROID_RUNTIME_PAYLOAD_STRIP:-1}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required to build ori-runtime-mobile." >&2
  exit 1
fi

if ! cargo ndk --version >/dev/null 2>&1; then
  echo "ERROR: cargo-ndk is required. Install with: cargo install cargo-ndk" >&2
  exit 1
fi

# The NDK's strip. cargo-ndk finds its NDK through several variables and can
# build when none of them is set, so looking only at ANDROID_NDK_HOME would
# leave a build stripped or not depending on the caller's environment, with
# the artefact differing from what this script says it produces.
LLVM_STRIP=""
for ndk_root in \
  "${ANDROID_NDK_HOME:-}" \
  "${ANDROID_NDK_ROOT:-}" \
  "${NDK_HOME:-}" \
  "${ANDROID_HOME:-}"/ndk/* \
  "${ANDROID_SDK_ROOT:-}"/ndk/* \
  "${HOME}"/Library/Android/sdk/ndk/*; do
  [ -n "${ndk_root}" ] && [ -d "${ndk_root}" ] || continue
  for candidate in "${ndk_root}"/toolchains/llvm/prebuilt/*/bin/llvm-strip; do
    if [ -x "${candidate}" ]; then
      LLVM_STRIP="${candidate}"
      break 2
    fi
  done
done

# Refused rather than warned. The payload is correct unstripped, but silently
# producing one artefact when the run was asked for another is how a size and
# a digest stop meaning what a report says they mean.
if [ "${STRIP}" = "1" ] && [ -z "${LLVM_STRIP}" ]; then
  echo "ERROR: stripping was requested and no llvm-strip was found." >&2
  echo "  Set ANDROID_NDK_HOME, or pass ORI_ANDROID_RUNTIME_PAYLOAD_STRIP=0" >&2
  echo "  to keep symbols deliberately." >&2
  exit 1
fi

# Panic locations embed the absolute path of every source file they come from,
# and stripping keeps them, so a payload built under /home/runner differs from
# one built under /Users/someone by those bytes alone. Two prefixes leak:
#
#   * the Cargo registry, for every dependency, which is remapped to /cargo;
#   * the toolchain sysroot, for the standard library, but only when `rust-src`
#     is installed for the pinned toolchain. Without it rustc already renders
#     those paths as /rustc/<commit>/..., so the sysroot's copy of the sources
#     is remapped onto that same prefix rather than a prefix of our own. A
#     machine with `rust-src` then produces the bytes a machine without it
#     produces, instead of a digest that depends on which components happen to
#     be installed.
#
# The crate's own sources are passed to rustc relative to the crate, so they
# need no remap. Flags from the caller's environment would change the bytes
# without changing anything this script reports, so they are refused.
if [ -n "${RUSTFLAGS:-}" ] || [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
  echo "ERROR: RUSTFLAGS or CARGO_ENCODED_RUSTFLAGS is set; a payload's flags are this script's." >&2
  exit 1
fi
CARGO_HOME_DIR="$(cd "${CARGO_HOME:-${HOME}/.cargo}" && pwd -P)"
SYSROOT="$(cd "$(rustc --print sysroot)" && pwd -P)"
RUSTC_COMMIT="$(rustc -vV | awk '/^commit-hash: /{print $2}')"
if [ -z "${RUSTC_COMMIT}" ]; then
  echo "ERROR: rustc reports no commit hash, so the standard library cannot be remapped." >&2
  exit 1
fi
UNIT_SEPARATOR="$(printf '\037')"
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${CARGO_HOME_DIR}=/cargo${UNIT_SEPARATOR}--remap-path-prefix=${SYSROOT}/lib/rustlib/src/rust=/rustc/${RUSTC_COMMIT}${UNIT_SEPARATOR}--remap-path-prefix=${SYSROOT}=/rust"

mkdir -p "${OUT}"

build_one() {
  local abi="$1"
  local triple="$2"
  local elf_class="$3"
  local elf_machine="$4"
  echo "Building ori-runtime-mobile for ${abi} (${triple})"
  (
    cd "${CRATE_DIR}"
    CARGO_TARGET_DIR="${TARGET_DIR}" cargo ndk \
      -t "${abi}" \
      -P "${PLATFORM}" \
      build \
      --release \
      --locked
  )

  local source="${TARGET_DIR}/${triple}/release/ori-runtime-mobile"
  local dest_dir="${OUT}/${abi}"
  local dest="${dest_dir}/libori_runtime_exec.so"
  if [ ! -f "${source}" ]; then
    echo "ERROR: expected payload not found: ${source}" >&2
    exit 1
  fi
  mkdir -p "${dest_dir}"
  cp "${source}" "${dest}"
  chmod 0755 "${dest}"

  local symbols="unstripped"
  if [ "${STRIP}" = "1" ]; then
    "${LLVM_STRIP}" "${dest}"
    symbols="stripped"
  fi

  verify_payload "${dest}" "${elf_class}" "${elf_machine}"
  # The whole home directory, not just the two prefixes above: a leak from a
  # path this script did not anticipate is the same defect as a leak from one
  # it did, and a digest that embeds a home directory reproduces nowhere.
  if [ -n "${HOME:-}" ] && grep -q -F "${HOME}" "${dest}"; then
    echo "ERROR: payload still embeds a path under the build machine's home: ${dest}" >&2
    grep -o -F -m 3 "${HOME}[^\"]*" "${dest}" >&2 || true
    exit 1
  fi
  # Reported per artefact, so a digest is never read alongside a size the run
  # did not produce.
  echo "  ${abi}: ${symbols}"
  digest "${dest}"
}

# One unsigned byte from the ELF header at a given offset.
elf_byte() {
  od -An -tu1 -j "$2" -N1 "$1" | tr -d ' \n'
}

# Every one of these corresponds to a refusal in the consuming APK's release
# gate. A payload failing any of them would be refused at packaging.
verify_payload() {
  local path="$1" want_class="$2" want_machine="$3"
  local class data m_lo m_hi machine

  if [ "$(head -c 4 "${path}" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
    echo "ERROR: payload does not begin with ELF magic: ${path}" >&2
    exit 1
  fi

  # Decided from the ELF header, never from `file`'s prose. The prose nests:
  # an arm64 binary is described "ARM aarch64", so a substring test for the
  # 32-bit "ARM" accepts it and the wrong payload reaches the armeabi-v7a
  # slot, failing only once it is on a 32-bit handset.
  class="$(elf_byte "${path}" 4)"        # EI_CLASS: 1 = 32-bit, 2 = 64-bit
  data="$(elf_byte "${path}" 5)"         # EI_DATA: 1 = little-endian
  if [ "${data}" != "1" ]; then
    echo "ERROR: payload is not little-endian; every Android ABI here is: ${path}" >&2
    exit 1
  fi
  m_lo="$(elf_byte "${path}" 18)"
  m_hi="$(elf_byte "${path}" 19)"
  machine=$(( m_hi * 256 + m_lo ))       # e_machine

  if [ "${class}" != "${want_class}" ]; then
    echo "ERROR: payload is ELF class ${class}, expected ${want_class}: ${path}" >&2
    exit 1
  fi
  if [ "${machine}" != "${want_machine}" ]; then
    echo "ERROR: payload is e_machine ${machine}, expected ${want_machine}: ${path}" >&2
    exit 1
  fi

  # The placeholder the consuming repo ships to keep its own build green is a
  # shell script. Handing one over would pass an ELF check nowhere and this
  # everywhere.
  if grep -q "system/bin/sh" "${path}" 2>/dev/null; then
    echo "ERROR: payload contains a shell interpreter line: ${path}" >&2
    exit 1
  fi
  if grep -q "ORI_ANDROID_RUNTIME_PAYLOAD_SHIM" "${path}" 2>/dev/null; then
    echo "ERROR: payload carries the placeholder marker: ${path}" >&2
    exit 1
  fi
}

digest() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  else
    sha256sum "$1"
  fi
}

build_one "arm64-v8a" "aarch64-linux-android" 2 183
build_one "armeabi-v7a" "armv7-linux-androideabi" 1 40
build_one "x86_64" "x86_64-linux-android" 2 62

cat <<EOF

Android runtime payloads written to:
  ${OUT}

Use these paths for the Android release build:
  ORI_ANDROID_RUNTIME_PAYLOAD_ARM64_V8A=${OUT}/arm64-v8a/libori_runtime_exec.so
  ORI_ANDROID_RUNTIME_PAYLOAD_ARMEABI_V7A=${OUT}/armeabi-v7a/libori_runtime_exec.so
  ORI_ANDROID_RUNTIME_PAYLOAD_X86_64=${OUT}/x86_64/libori_runtime_exec.so
EOF
