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

mkdir -p "${MODEL_DIR}"
if [ ! -f "${MODEL_PATH}" ]; then
  echo "Downloading Qwen 0.5B model (500MB)..."
  curl -L "${MODEL_URL}" -o "${MODEL_PATH}"
else
  echo "Model already present at ${MODEL_PATH}; skipping download."
fi

echo "Setup complete. Run: ori-runtime --config ori.yaml"
