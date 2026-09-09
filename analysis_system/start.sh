#!/usr/bin/env bash
# start.sh — starts trigger_mcp_server.py, the only long-running process
# on this machine (accepts "analyze this hierarchy" requests over MCP,
# binding 0.0.0.0:8001; exposes analyze_hierarchy(hierarchy, vault_root)).
# Runs it in the background and writes trigger_mcp_server.pid so stop.sh
# (or a plain `kill $(cat trigger_mcp_server.pid)`) can stop it later.
# Safe to re-run — a no-op if it's already running.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ -x venv/Scripts/python.exe ]; then PY="venv/Scripts/python.exe"; else PY="venv/bin/python"; fi
if [ ! -x "$PY" ]; then
  echo "No venv found at $HERE/venv — run ./install.sh first." >&2
  exit 1
fi

if [ -f trigger_mcp_server.pid ] && kill -0 "$(cat trigger_mcp_server.pid)" 2>/dev/null; then
  echo "trigger_mcp_server.py is already running (PID $(cat trigger_mcp_server.pid))."
  exit 0
fi

nohup "$PY" trigger_mcp_server.py > trigger_mcp_server.log 2>&1 &
echo $! > trigger_mcp_server.pid
sleep 1

if kill -0 "$(cat trigger_mcp_server.pid)" 2>/dev/null; then
  echo "trigger_mcp_server.py started (PID $(cat trigger_mcp_server.pid)), binding 0.0.0.0:8001."
  echo "Logs: $HERE/trigger_mcp_server.log — stop with ./stop.sh"
else
  echo "trigger_mcp_server.py failed to start — check trigger_mcp_server.log:" >&2
  tail -n 20 trigger_mcp_server.log >&2 || true
  rm -f trigger_mcp_server.pid
  exit 1
fi
