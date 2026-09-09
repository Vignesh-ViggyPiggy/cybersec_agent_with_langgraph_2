#!/usr/bin/env bash
# start.sh — starts mcp_server.py, the only long-running process on this
# machine (fetch_directory_files/upload_file/get_attack_checklist over
# MCP, binding 0.0.0.0:8002). Runs it in the background and writes
# mcp_server.pid so stop.sh (or a plain `kill $(cat mcp_server.pid)`) can
# stop it later. Safe to re-run — a no-op if it's already running.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ -x venv/Scripts/python.exe ]; then PY="venv/Scripts/python.exe"; else PY="venv/bin/python"; fi
if [ ! -x "$PY" ]; then
  echo "No venv found at $HERE/venv — run ./install.sh first." >&2
  exit 1
fi

if [ -f mcp_server.pid ] && kill -0 "$(cat mcp_server.pid)" 2>/dev/null; then
  echo "mcp_server.py is already running (PID $(cat mcp_server.pid))."
  exit 0
fi

nohup "$PY" mcp_server.py > mcp_server.log 2>&1 &
echo $! > mcp_server.pid
sleep 1

if kill -0 "$(cat mcp_server.pid)" 2>/dev/null; then
  echo "mcp_server.py started (PID $(cat mcp_server.pid)), binding 0.0.0.0:8002."
  echo "Logs: $HERE/mcp_server.log — stop with ./stop.sh"
else
  echo "mcp_server.py failed to start — check mcp_server.log:" >&2
  tail -n 20 mcp_server.log >&2 || true
  rm -f mcp_server.pid
  exit 1
fi
