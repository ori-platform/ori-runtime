#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Build the Android-native Phone Starter runtime payload expected by APK
# provisioning. The resulting files are real ELF executables named
# libori_runtime_exec.so so Android extracts them into nativeLibraryDir where
# the APK can execute them without violating Android W^X rules.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="${ROOT}/mobile/ori-runtime-mobile"
OUT="${ORI_ANDROID_RUNTIME_PAYLOAD_OUT:-${ROOT}/dist/android-runtime-payloads}"
TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/mobile/target}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required to build ori-runtime-mobile." >&2
  exit 1
fi

if ! cargo ndk --version >/dev/null 2>&1; then
  echo "ERROR: cargo-ndk is required. Install with: cargo install cargo-ndk" >&2
  exit 1
fi

mkdir -p "${OUT}"

build_one() {
  local abi="$1"
  local triple="$2"
  echo "Building ori-runtime-mobile for ${abi} (${triple})"
  (
    cd "${CRATE_DIR}"
    CARGO_TARGET_DIR="${TARGET_DIR}" cargo ndk \
      -t "${abi}" \
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
  if ! file "${dest}" | grep -q "ELF"; then
    echo "ERROR: payload is not an ELF executable: ${dest}" >&2
    exit 1
  fi
  shasum -a 256 "${dest}"
}

build_one "arm64-v8a" "aarch64-linux-android"
build_one "armeabi-v7a" "armv7-linux-androideabi"
build_one "x86_64" "x86_64-linux-android"

cat <<EOF

Android runtime payloads written to:
  ${OUT}

Use these paths for the Android release build:
  ORI_ANDROID_RUNTIME_PAYLOAD_ARM64_V8A=${OUT}/arm64-v8a/libori_runtime_exec.so
  ORI_ANDROID_RUNTIME_PAYLOAD_ARMEABI_V7A=${OUT}/armeabi-v7a/libori_runtime_exec.so
  ORI_ANDROID_RUNTIME_PAYLOAD_X86_64=${OUT}/x86_64/libori_runtime_exec.so
EOF
