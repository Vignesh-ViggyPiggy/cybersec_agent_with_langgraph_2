#!/usr/bin/env bash
# stop.sh — stops the trigger_mcp_server.py process started by start.sh.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if [ -f trigger_mcp_server.pid ] && kill -0 "$(cat trigger_mcp_server.pid)" 2>/dev/null; then
  kill "$(cat trigger_mcp_server.pid)"
  rm -f trigger_mcp_server.pid
  echo "trigger_mcp_server.py stopped."
else
  echo "trigger_mcp_server.py is not running."
  rm -f trigger_mcp_server.pid
fi
