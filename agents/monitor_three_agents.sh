#!/bin/bash
# 兼容文件名；实际同时追踪四个独立 Agent：VS Code/Codex、WorkBuddy、Trae、Kiro。
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WS="${1:?用法: bash agents/monitor_three_agents.sh /path/to/workspace [--mitm]}"
shift || true
MITM_ARG=()
[ "${1:-}" = "--mitm" ] && MITM_ARG=(--mitm)
PIDFILE="${ROOT}/events/.agent_stack.pids"
COLLECTOR="http://127.0.0.1:8787/ingest"

# 主栈：Collector、全局文件观察、HTTPS MITM、Codex session、Codex 进程树。
bash "${ROOT}/agents/monitor_agent.sh" vscode "$WS" --capture-reads "${MITM_ARG[@]}"

# WorkBuddy 第一方审计日志。
"${PYTHON:-python3}" "${ROOT}/agents/audit_tailer.py" --profile workbuddy \
  --collector "$COLLECTOR" >"${ROOT}/events/workbuddy_audit_tailer.log" 2>&1 &
echo "workbuddy_audit $!" >> "$PIDFILE"

# WorkBuddy 独立进程树。
bash "${ROOT}/kiro/watchdog.sh" "$WS" workbuddy_process_live \
  --agent-name WorkBuddy --collector "$COLLECTOR" --capture-reads \
  --seed-pattern "/Applications/WorkBuddy.app" \
  >"${ROOT}/events/workbuddy_observer.log" 2>&1 &
echo "workbuddy_watchdog $!" >> "$PIDFILE"

# Trae 独立进程树。
bash "${ROOT}/kiro/watchdog.sh" "$WS" trae_process_live \
  --agent-name Trae --collector "$COLLECTOR" --capture-reads --poll-proc 0.01 \
  --seed-pattern "/Applications/Trae.app,Trae.app/Contents,/Applications/TRAE SOLO CN.app,TRAE SOLO CN.app/Contents" \
  >"${ROOT}/events/trae_observer.log" 2>&1 &
echo "trae_watchdog $!" >> "$PIDFILE"

# Kiro 独立进程树。HTTPS 请求由同一 MITM 按域名写入 kiro_https。
bash "${ROOT}/kiro/watchdog.sh" "$WS" kiro_process_live \
  --agent-name Kiro --collector "$COLLECTOR" --capture-reads \
  --seed-pattern "/Applications/Kiro.app,Kiro.app/Contents" \
  >"${ROOT}/events/kiro_observer.log" 2>&1 &
echo "kiro_watchdog $!" >> "$PIDFILE"

echo "[all-agents] Codex / WorkBuddy / Trae / Kiro 已分别启动"
echo "[all-agents] Boss: http://127.0.0.1:8787/boss"
