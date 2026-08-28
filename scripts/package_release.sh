#!/usr/bin/env bash
# package_release.sh — builds distributable tarballs for both packages.
# Run this on a machine that already has the real cybersecqwen model built
# in Ollama (it calls export_model.sh to pull the weights out first).
#
# Usage: scripts/package_release.sh [model-name]   (default: cybersecqwen)
# Output: dist/analysis_system.tar.gz, dist/hierarchy_system.tar.gz
set -euo pipefail

MODEL_NAME="${1:-cybersecqwen}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

echo "== Exporting Ollama model ($MODEL_NAME) =="
"$ROOT/scripts/export_model.sh" "$MODEL_NAME"

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
