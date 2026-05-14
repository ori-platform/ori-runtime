#!/data/data/com.termux/files/usr/bin/bash
# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

# Ori Phone Gateway Setup Script (Termux)
set -euo pipefail

pkg update -y
pkg install -y python sqlite curl

WHEELHOUSE_DIR="${ORI_WHEELHOUSE_DIR:-${HOME}/ori-wheelhouse}"
if [ ! -d "${WHEELHOUSE_DIR}" ]; then
  echo "ERROR: Signed wheelhouse not found: ${WHEELHOUSE_DIR}" >&2
  echo "Production phone installs must use a signed Ori wheelhouse, not live PyPI resolution." >&2
  echo "Set ORI_WHEELHOUSE_DIR to a directory containing wheels and requirements.txt." >&2
  exit 1
fi

python -m pip --version
python -m pip install --break-system-packages --no-index --find-links "${WHEELHOUSE_DIR}" --require-hashes -r "${WHEELHOUSE_DIR}/requirements.txt"
python -m pip install --break-system-packages --no-index --find-links "${WHEELHOUSE_DIR}" --no-deps ori-runtime

MODEL_DIR="${HOME}/models"
MODEL_PATH="${MODEL_DIR}/qwen2.5-0.5b-instruct-q4_k_m.gguf"
MODEL_URL="https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf"

# SHA256 of the authoritative file in the HuggingFace Git LFS store.
# Obtained from the LFS pointer at:
#   https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/raw/main/qwen2.5-0.5b-instruct-q4_k_m.gguf
# oid sha256:74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db
# size 491400032
# Update this value whenever the model file is replaced in the HF repo.
MODEL_SHA256="74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
MODEL_SIZE_BYTES="491400032"

_verify_model() {
  local path="$1"
  echo "Verifying model integrity..."

  # Size check first (fast, catches partial downloads before hashing)
  local actual_size
  actual_size=$(stat -c%s "${path}" 2>/dev/null || stat -f%z "${path}" 2>/dev/null || echo "0")
  if [ "${actual_size}" != "${MODEL_SIZE_BYTES}" ]; then
    echo "ERROR: Model size mismatch (expected ${MODEL_SIZE_BYTES} bytes, got ${actual_size})." >&2
    return 1
  fi

  # SHA256 hash check
  local actual_sha256
  if command -v sha256sum >/dev/null 2>&1; then
    actual_sha256=$(sha256sum "${path}" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual_sha256=$(shasum -a 256 "${path}" | awk '{print $1}')
  else
    echo "WARNING: No sha256sum or shasum available — skipping hash check." >&2
    return 0
  fi

  if [ "${actual_sha256}" != "${MODEL_SHA256}" ]; then
    echo "ERROR: Model SHA256 mismatch." >&2
    echo "  Expected: ${MODEL_SHA256}" >&2
    echo "  Got:      ${actual_sha256}" >&2
    echo "The download may be corrupt or the file has been replaced upstream." >&2
    return 1
  fi

  echo "Model integrity verified (SHA256 OK, size OK)."
}

mkdir -p "${MODEL_DIR}"
if [ ! -f "${MODEL_PATH}" ]; then
  echo "Downloading Qwen 0.5B model (~491MB)..."
  curl -fL "${MODEL_URL}" -o "${MODEL_PATH}"
  if ! _verify_model "${MODEL_PATH}"; then
    rm -f "${MODEL_PATH}"
    echo "Removed corrupted download. Re-run this script to retry." >&2
    exit 1
  fi
else
  echo "Model already present at ${MODEL_PATH}; verifying integrity..."
  if ! _verify_model "${MODEL_PATH}"; then
    echo "Existing model failed integrity check. Remove ${MODEL_PATH} and re-run." >&2
    exit 1
  fi
fi

echo "Setup complete. Run: ori-runtime --config ori.yaml"
