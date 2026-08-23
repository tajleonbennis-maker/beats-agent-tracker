#!/bin/bash
# launchd 前台监督器：tracker.sh 会启动后台采集器，本进程保持存活以避免
# launchd 在启动命令退出后回收整个进程组。
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE="${1:-$ROOT}"
PIDFILE="$ROOT/events/.agent_stack.pids"
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

cleanup() {
  trap - TERM INT EXIT
  bash "$ROOT/tracker.sh" stop >/dev/null 2>&1 || true
}
trap cleanup TERM INT EXIT

bash "$ROOT/tracker.sh" start "$WORKSPACE"
while true; do
  collector="$(awk '$1=="collector"{print $2; exit}' "$PIDFILE" 2>/dev/null || true)"
  if [ -z "$collector" ] || ! kill -0 "$collector" 2>/dev/null; then
    echo "[supervisor] collector 已退出" >&2
    exit 1
  fi
  sleep 5
done
