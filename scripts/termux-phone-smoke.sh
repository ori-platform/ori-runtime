#!/data/data/com.termux/files/usr/bin/bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

# Validate the Android/Termux Phone Starter path on a real phone.
#
# By default this script is non-destructive: it checks the Termux environment,
# current Ori install, config, phone doctor, and USB readiness. Pass
# --install-wheelhouse to validate the signed offline wheelhouse install path.
set -u

CONFIG_PATH="${ORI_CONFIG:-ori.yaml}"
WHEELHOUSE_DIR="${ORI_WHEELHOUSE_DIR:-${HOME}/ori-wheelhouse}"
PYTHON_BIN="${ORI_PYTHON:-python}"
INSTALL_WHEELHOUSE=false
NO_FAIL=false
RUNTIME_STARTUP_SECONDS=0

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

usage() {
  cat <<'EOF'
Usage:
  scripts/termux-phone-smoke.sh [options]

Options:
  --config PATH                 Path to ori.yaml. Defaults to ORI_CONFIG or ./ori.yaml.
  --wheelhouse DIR              Offline phone wheelhouse. Defaults to ORI_WHEELHOUSE_DIR or ~/ori-wheelhouse.
  --install-wheelhouse          Install dependencies and ori-runtime from the offline wheelhouse before checks.
  --runtime-startup-seconds N   Start ori-runtime and require it to stay alive for N seconds. Default: 0, disabled.
  --no-fail                     Always exit 0; useful when collecting diagnostics.
  -h, --help                    Show this help.

Examples:
  scripts/termux-phone-smoke.sh --config ori.yaml
  ORI_WHEELHOUSE_DIR=~/ori-wheelhouse scripts/termux-phone-smoke.sh --install-wheelhouse --config ori.yaml
  ORI_PYTHON=.venv/bin/python scripts/termux-phone-smoke.sh --config ori.yaml.phone.example --no-fail
  scripts/termux-phone-smoke.sh --config ori.yaml --runtime-startup-seconds 10
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --config)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --config requires a path" >&2
        exit 2
      fi
      CONFIG_PATH="$2"
      shift 2
      ;;
    --wheelhouse)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --wheelhouse requires a directory" >&2
        exit 2
      fi
      WHEELHOUSE_DIR="$2"
      shift 2
      ;;
    --install-wheelhouse)
      INSTALL_WHEELHOUSE=true
      shift
      ;;
    --runtime-startup-seconds)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --runtime-startup-seconds requires a number" >&2
        exit 2
      fi
      RUNTIME_STARTUP_SECONDS="$2"
      shift 2
      ;;
    --no-fail)
      NO_FAIL=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

record_pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS  $1"
}

record_warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "WARN  $1"
}

record_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "FAIL  $1"
}

have_command() {
  command -v "$1" >/dev/null 2>&1
}

run_step() {
  local label="$1"
  shift
  echo ""
  echo "==> ${label}"
  if "$@"; then
    record_pass "${label}"
    return 0
  fi
  record_fail "${label}"
  return 1
}

require_command() {
  local command_name="$1"
  local package_hint="${2:-}"
  if have_command "${command_name}"; then
    record_pass "command ${command_name} is available"
    return 0
  fi
  if [ -n "${package_hint}" ]; then
    record_fail "command ${command_name} is missing; ${package_hint}"
  else
    record_fail "command ${command_name} is missing"
  fi
  return 1
}

warn_command() {
  local command_name="$1"
  local package_hint="${2:-}"
  if have_command "${command_name}"; then
    record_pass "command ${command_name} is available"
    return 0
  fi
  if [ -n "${package_hint}" ]; then
    record_warn "command ${command_name} is missing; ${package_hint}"
  else
    record_warn "command ${command_name} is missing"
  fi
  return 0
}

check_termux_environment() {
  echo ""
  echo "==> Termux environment"
  if [ "${PREFIX:-}" = "/data/data/com.termux/files/usr" ] || echo "${HOME:-}" | grep -q "com.termux"; then
    record_pass "Termux app sandbox detected"
  else
    record_warn "Termux app sandbox not detected; run this script on the Android phone for final validation"
  fi

  require_command "${PYTHON_BIN}" "install Python with pkg install python, or set ORI_PYTHON"
  require_command pkg "run inside Termux; pkg is part of the Termux base environment"
  warn_command git "install git with pkg install git"
  warn_command sshd "install OpenSSH with pkg install openssh"
  warn_command termux-usb "install termux-api and the Termux:API app from the same source as Termux"
  warn_command termux-wake-lock "install termux-api and the Termux:API app from the same source as Termux"
}

check_config_file() {
  echo ""
  echo "==> Config file"
  if [ -f "${CONFIG_PATH}" ]; then
    record_pass "config exists: ${CONFIG_PATH}"
    return 0
  fi
  record_fail "config missing: ${CONFIG_PATH}"
  return 1
}

check_usb_snapshot() {
  echo ""
  echo "==> USB snapshot"
  local tty_devices
  tty_devices=$(ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null || true)
  if [ -n "${tty_devices}" ]; then
    echo "${tty_devices}"
    record_pass "direct USB serial path detected"
  elif have_command termux-usb; then
    local usb_devices
    usb_devices=$(termux-usb -l 2>/dev/null || true)
    if [ -n "${usb_devices}" ] && [ "${usb_devices}" != "[]" ]; then
      echo "${usb_devices}"
      record_warn "termux-usb sees USB device(s), but no direct serial tty is exposed"
    else
      record_warn "no USB meter detected by termux-usb yet"
    fi
  else
    record_warn "termux-usb unavailable; cannot inspect Android USB host state"
  fi
}

check_wheelhouse() {
  echo ""
  echo "==> Phone wheelhouse"
  if [ ! -d "${WHEELHOUSE_DIR}" ]; then
    if [ "${INSTALL_WHEELHOUSE}" = "true" ]; then
      record_fail "wheelhouse directory missing: ${WHEELHOUSE_DIR}"
      return 1
    fi
    record_warn "wheelhouse directory missing: ${WHEELHOUSE_DIR}; skipping install validation"
    return 0
  fi

  record_pass "wheelhouse directory exists: ${WHEELHOUSE_DIR}"

  if [ -f "${WHEELHOUSE_DIR}/requirements.txt" ]; then
    record_pass "wheelhouse install requirements.txt exists"
  else
    record_fail "wheelhouse requirements.txt missing"
    return 1
  fi

  if ls "${WHEELHOUSE_DIR}"/ori_runtime-*.whl >/dev/null 2>&1; then
    record_pass "ori-runtime wheel exists in wheelhouse"
  else
    record_fail "ori-runtime wheel missing from wheelhouse"
    return 1
  fi

  if [ -f "${WHEELHOUSE_DIR}/requirements-phone.txt" ]; then
    record_pass "phone source/build lockfile is present"
  else
    record_warn "requirements-phone.txt missing; install can proceed, but build provenance is incomplete"
  fi
}

install_from_wheelhouse() {
  if [ "${INSTALL_WHEELHOUSE}" != "true" ]; then
    return 0
  fi
  check_wheelhouse || return 1
  run_step "install phone wheelhouse dependencies" \
    "${PYTHON_BIN}" -m pip install --break-system-packages --no-index --find-links "${WHEELHOUSE_DIR}" --require-hashes -r "${WHEELHOUSE_DIR}/requirements.txt" || return 1
  run_step "install ori-runtime wheel" \
    "${PYTHON_BIN}" -m pip install --break-system-packages --no-index --find-links "${WHEELHOUSE_DIR}" --no-deps ori-runtime || return 1
}

check_python_imports() {
  run_step "import ori.runtime" "${PYTHON_BIN}" -c "import ori.runtime; print('ori.runtime import ok')"
  run_step "import ori.phone_doctor" "${PYTHON_BIN}" -c "import ori.phone_doctor; print('ori.phone_doctor import ok')"
}

run_doctor() {
  echo ""
  echo "==> ori-phone-doctor"
  "${PYTHON_BIN}" -m ori.phone_doctor --config "${CONFIG_PATH}"
  local status=$?
  if [ "${status}" -eq 0 ]; then
    record_pass "ori-phone-doctor passed"
    return 0
  fi
  record_fail "ori-phone-doctor reported blocking checks"
  return "${status}"
}

check_runtime_startup() {
  if [ "${RUNTIME_STARTUP_SECONDS}" = "0" ]; then
    record_warn "runtime startup smoke skipped; pass --runtime-startup-seconds N to enable"
    return 0
  fi

  case "${RUNTIME_STARTUP_SECONDS}" in
    ''|*[!0-9]*)
      record_fail "--runtime-startup-seconds must be a non-negative integer"
      return 1
      ;;
  esac

  echo ""
  echo "==> ori-runtime startup smoke (${RUNTIME_STARTUP_SECONDS}s)"
  "${PYTHON_BIN}" - "${CONFIG_PATH}" "${RUNTIME_STARTUP_SECONDS}" <<'PY'
import subprocess
import sys

config_path = sys.argv[1]
timeout_s = int(sys.argv[2])

command = [sys.executable, "-m", "ori.runtime", "--config", config_path, "--log-level", "INFO"]
try:
    result = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout_s,
    )
except FileNotFoundError:
    print("ori-runtime command is not available on PATH")
    raise SystemExit(1)
except subprocess.TimeoutExpired as exc:
    output = exc.stdout or ""
    if isinstance(output, bytes):
        output = output.decode(errors="replace")
    print(output[-4000:])
    print(f"ori-runtime stayed alive for {timeout_s}s")
    raise SystemExit(0)

print(result.stdout[-4000:])
print(f"ori-runtime exited early with code {result.returncode}")
raise SystemExit(1)
PY
  local status=$?
  if [ "${status}" -eq 0 ]; then
    record_pass "ori-runtime stayed alive for ${RUNTIME_STARTUP_SECONDS}s"
    return 0
  fi
  record_fail "ori-runtime exited before ${RUNTIME_STARTUP_SECONDS}s"
  return "${status}"
}

main() {
  echo "Ori Termux Phone Smoke"
  echo "Config: ${CONFIG_PATH}"
  echo "Wheelhouse: ${WHEELHOUSE_DIR}"
  echo "Python: ${PYTHON_BIN}"
  echo "Install wheelhouse: ${INSTALL_WHEELHOUSE}"
  echo "Runtime startup seconds: ${RUNTIME_STARTUP_SECONDS}"

  check_termux_environment
  check_config_file || true
  check_usb_snapshot
  if [ "${INSTALL_WHEELHOUSE}" = "true" ]; then
    install_from_wheelhouse || true
  else
    check_wheelhouse || true
  fi
  check_python_imports || true
  run_doctor || true
  check_runtime_startup || true

  echo ""
  echo "Summary: ${PASS_COUNT} pass, ${WARN_COUNT} warn, ${FAIL_COUNT} fail"
  if [ "${FAIL_COUNT}" -gt 0 ]; then
    echo "Result: FAIL"
    if [ "${NO_FAIL}" = "true" ]; then
      exit 0
    fi
    exit 1
  fi
  echo "Result: PASS"
}

main
