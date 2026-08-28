#!/usr/bin/env bash
# export_model.sh — pulls the real GGUF weight blob for a local Ollama model
# out of Ollama's internal blob store and drops it, plus a Modelfile that
# references it by relative path, into analysis_system/model/. This is what
# lets a fresh Rocky 8 machine rebuild the exact same model offline via
# `ollama create` instead of needing the original (unrecorded) base model
# tag or internet access.
#
# `ollama show <model> --modelfile` normally prints a Modelfile whose FROM
# line points at Ollama's own content-addressed blob path (e.g.
# ~/.ollama/models/blobs/sha256-...) — real on this machine, meaningless on
# any other. We copy that blob out under a stable name and rewrite FROM to
# point at it relatively, so the whole model/ directory is self-contained.
#
# Usage: scripts/export_model.sh [model-name]   (default: cybersecqwen)
set -euo pipefail

MODEL_NAME="${1:-cybersecqwen}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/analysis_system/model"
mkdir -p "$OUT_DIR"

if ! command -v ollama >/dev/null 2>&1; then
  echo "ollama not found on PATH — run this on the machine that already has $MODEL_NAME built." >&2
  exit 1
fi

MODELFILE_RAW="$(ollama show "$MODEL_NAME" --modelfile)"
BLOB_PATH="$(printf '%s\n' "$MODELFILE_RAW" | grep -m1 '^FROM ' | sed 's/^FROM //')"

if [ -z "$BLOB_PATH" ] || [ ! -f "$BLOB_PATH" ]; then
  echo "Could not locate a weight blob for $MODEL_NAME (looked for: $BLOB_PATH)." >&2
  exit 1
fi

echo "Copying weights: $BLOB_PATH -> $OUT_DIR/${MODEL_NAME}.gguf"
cp "$BLOB_PATH" "$OUT_DIR/${MODEL_NAME}.gguf"

{
  echo "FROM ./${MODEL_NAME}.gguf"
  printf '%s\n' "$MODELFILE_RAW" | grep -v '^FROM ' | grep -v '^#'
} > "$OUT_DIR/Modelfile"

echo "Wrote $OUT_DIR/Modelfile"
echo "Done — analysis_system/model/ is now self-contained for $MODEL_NAME."
