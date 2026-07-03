#!/usr/bin/env bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0
#
# Guard Rust dependency posture for Android runtime payloads.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="${ROOT}/mobile/ori-runtime-mobile"
CARGO_TOML="${CRATE_DIR}/Cargo.toml"
CARGO_LOCK="${CRATE_DIR}/Cargo.lock"
BUILD_SCRIPT="${ROOT}/scripts/build-android-runtime-mobile.sh"

ERRORS=()

add_error() {
  ERRORS+=("$1")
}

require_file() {
  local path="$1"
  if [ ! -f "${path}" ]; then
    add_error "missing required file: ${path#${ROOT}/}"
  fi
}

check_manifest_dependencies() {
  local section=""
  local line_number=0
  while IFS= read -r line || [ -n "${line}" ]; do
    line_number=$((line_number + 1))
    local trimmed
    trimmed="$(printf '%s' "${line}" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')"

    if [[ "${trimmed}" =~ ^\[(.*)\]$ ]]; then
      section="${BASH_REMATCH[1]}"
      continue
    fi
    case "${section}" in
      dependencies|build-dependencies|dev-dependencies) ;;
      *) continue ;;
    esac
    if [ -z "${trimmed}" ] || [[ "${trimmed}" == \#* ]]; then
      continue
    fi
    if [[ ! "${trimmed}" =~ ^[A-Za-z0-9_.-]+[[:space:]]*= ]]; then
      add_error "Cargo.toml:${line_number}: malformed ${section} entry"
      continue
    fi

    local name spec
    name="${trimmed%%=*}"
    name="$(printf '%s' "${name}" | sed -E 's/[[:space:]]//g')"
    spec="${trimmed#*=}"
    spec="$(printf '%s' "${spec}" | sed -E 's/^[[:space:]]+//')"

    if [ "${spec}" = '"*"' ] || grep -Eq 'version[[:space:]]*=[[:space:]]*"\*"' <<<"${spec}"; then
      add_error "Cargo.toml:${line_number}: ${section}.${name} uses wildcard version"
    fi
    if grep -Eq '(^|[,{[:space:]])(git|path|branch|rev|tag)[[:space:]]*=' <<<"${spec}"; then
      add_error "Cargo.toml:${line_number}: ${section}.${name} uses a forbidden non-registry source"
    fi
    if [[ "${spec}" == \{* ]] && ! grep -Eq '(^|[,{[:space:]])version[[:space:]]*=' <<<"${spec}"; then
      add_error "Cargo.toml:${line_number}: ${section}.${name} table dependency must declare version"
    fi
  done < "${CARGO_TOML}"
}

check_lockfile() {
  if ! grep -q '^name = "ori-runtime-mobile"$' "${CARGO_LOCK}"; then
    add_error "Cargo.lock is missing ori-runtime-mobile root package"
  fi
  local tmp_errors
  tmp_errors="$(mktemp "${TMPDIR:-/tmp}/ori-rust-supply-chain.XXXXXX")"
  awk '
    function flush() {
      if (name != "" && name != "ori-runtime-mobile") {
        if (source ~ /^registry\+/ && checksum == "") {
          printf("Cargo.lock package %s is missing checksum\n", name)
        }
        if (source ~ /^git\+/) {
          printf("Cargo.lock package %s uses forbidden git source\n", name)
        }
      }
      name = ""; source = ""; checksum = ""
    }
    /^\[\[package\]\]/ { flush(); next }
    /^name = / {
      name = $0
      sub(/^name = "/, "", name)
      sub(/"$/, "", name)
      next
    }
    /^source = / {
      source = $0
      sub(/^source = "/, "", source)
      sub(/"$/, "", source)
      next
    }
    /^checksum = / {
      checksum = $0
      next
    }
    END { flush() }
  ' "${CARGO_LOCK}" > "${tmp_errors}"
  local error
  while IFS= read -r error || [ -n "${error}" ]; do
    [ -n "${error}" ] && add_error "${error}"
  done < "${tmp_errors}"
  rm -f "${tmp_errors}"
}

check_build_script() {
  if ! grep -q -- '--locked' "${BUILD_SCRIPT}"; then
    add_error "Android runtime payload build must use cargo --locked"
  fi
  if grep -Eiq '(curl|wget).*(\|[[:space:]]*(bash|sh|python[0-9]*)|&&[[:space:]]*(bash|sh|python[0-9]*))' "${BUILD_SCRIPT}"; then
    add_error "Android runtime payload build must not fetch and execute remote scripts"
  fi
}

require_file "${CARGO_TOML}"
require_file "${CARGO_LOCK}"
require_file "${BUILD_SCRIPT}"

if [ "${#ERRORS[@]}" -eq 0 ]; then
  check_manifest_dependencies
  check_lockfile
  check_build_script
fi

if [ "${#ERRORS[@]}" -ne 0 ]; then
  echo "Rust supply-chain guard failed:" >&2
  for error in "${ERRORS[@]}"; do
    echo "  - ${error}" >&2
  done
  exit 1
fi

echo "Rust supply-chain guard: OK"
