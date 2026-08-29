#!/usr/bin/env bash
# package_release.sh — builds distributable tarballs for both packages.
#
# The analysis_system tarball needs analysis_system/model/<model-name>.gguf
# to exist before packaging. Two ways to get there:
#   1. Manual: copy your own <model-name>.gguf into analysis_system/model/
#      yourself (alongside the already-committed Modelfile) before running
#      this script — it's used as-is, no Ollama needed on this machine.
#   2. Automatic: run this on a machine that already has the model built in
#      Ollama and don't place a .gguf yourself — this script calls
#      export_model.sh to pull the weights out of Ollama's own blob store.
#
# Usage: scripts/package_release.sh [model-name]   (default: cybersecqwen)
# Output: dist/analysis_system.tar.gz, dist/hierarchy_system.tar.gz
set -euo pipefail

MODEL_NAME="${1:-cybersecqwen}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
MODEL_DIR="$ROOT/analysis_system/model"
GGUF_PATH="$MODEL_DIR/${MODEL_NAME}.gguf"
mkdir -p "$DIST"

if [ -f "$GGUF_PATH" ]; then
  echo "== Using existing model weights at $GGUF_PATH =="
  if [ ! -f "$MODEL_DIR/Modelfile" ]; then
    echo "Found $GGUF_PATH but no $MODEL_DIR/Modelfile — write one manually" >&2
    echo "(FROM ./${MODEL_NAME}.gguf plus your PARAMETER/TEMPLATE lines), or" >&2
    echo "remove the .gguf and re-run this script to have export_model.sh" >&2
    echo "generate both from a locally-built Ollama model instead." >&2
    exit 1
  fi
else
  echo "== No existing weights at $GGUF_PATH — exporting from local Ollama ($MODEL_NAME) =="
  "$ROOT/scripts/export_model.sh" "$MODEL_NAME"
fi

echo "== Packaging analysis_system =="
tar -czf "$DIST/analysis_system.tar.gz" -C "$ROOT" \
  --exclude='analysis_system/hierarchies' \
  --exclude='analysis_system/corpus_db' \
  --exclude='analysis_system/__pycache__' \
  --exclude='analysis_system/lib/__pycache__' \
  --exclude='analysis_system/venv' \
  --exclude='analysis_system/.env' \
  analysis_system

echo "== Packaging hierarchy_system =="
tar -czf "$DIST/hierarchy_system.tar.gz" -C "$ROOT" \
  --exclude='hierarchy_system/__pycache__' \
  --exclude='hierarchy_system/venv' \
  --exclude='hierarchy_system/.env' \
  hierarchy_system

echo
echo "Done:"
echo "  $DIST/analysis_system.tar.gz"
echo "  $DIST/hierarchy_system.tar.gz"
echo
echo "Copy each tarball to its target Rocky 8 machine, extract, then run its"
echo "bundled install.sh as root (see each package's README section)."
