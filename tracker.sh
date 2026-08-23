#!/bin/bash
# Agent Tracker 统一控制入口。管理 Boss、MITM 与全部 Agent 采集器。
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"
PIDFILE="${ROOT}/events/.agent_stack.pids"
WORKSPACE_FILE="${ROOT}/events/.tracker_workspace"
DEFAULT_WORKSPACE="${TRACKER_WORKSPACE:-$ROOT}"

usage() {
  echo "用法: bash tracker.sh {start|stop|restart|status|open} [workspace]"
}

is_up() {
  local pid="$1"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

status() {
  local failed=0
  echo "Agent Tracker 状态"
  if [ ! -f "$PIDFILE" ]; then
    echo "  采集栈: 未运行"
    return 1
  fi
  while read -r name pid; do
    [ -n "$pid" ] || continue
    if is_up "$pid"; then
      echo "  ✓ $name (pid $pid)"
    else
      echo "  ✗ $name (pid $pid)"
      failed=1
    fi
  done < "$PIDFILE"
  [ -f "$WORKSPACE_FILE" ] && echo "  workspace: $(<"$WORKSPACE_FILE")"
  echo "  Boss: http://127.0.0.1:8787/boss"
  return "$failed"
}

start() {
  local workspace="${1:-$DEFAULT_WORKSPACE}"
  if [ ! -d "$workspace" ]; then
    echo "workspace 不存在: $workspace" >&2
    exit 1
  fi

  # 旧 Kiro 单栈与统一栈不可并存；发现旧 PID 文件时自动迁移。
  if [ -f "${ROOT}/events/.kiro_stack.pids" ]; then
    echo "[tracker] 检测到旧 Kiro 单栈，正在切换到统一采集栈..."
    bash "${ROOT}/agents/monitor_agent.sh" --stop
  elif [ -f "$PIDFILE" ]; then
    local collector
    collector="$(awk '$1=="collector"{print $2; exit}' "$PIDFILE")"
    if is_up "$collector"; then
      echo "[tracker] 统一采集栈已在运行。"
      status || true
      return 0
    fi
    bash "${ROOT}/agents/monitor_agent.sh" --stop
  fi

  printf '%s\n' "$workspace" > "$WORKSPACE_FILE"
  bash "${ROOT}/agents/monitor_three_agents.sh" "$workspace" --mitm
  echo "[tracker] 四个 Agent 已纳入统一采集：Trae / WorkBuddy / VS Code Codex / Kiro"
  echo "[tracker] 未修改系统代理；Trae 专属代理: bash agents/trae_proxy.sh launch"
}

command="${1:-status}"
shift || true
case "$command" in
  start) start "${1:-}" ;;
  stop) bash "${ROOT}/agents/monitor_agent.sh" --stop ;;
  restart)
    workspace="${1:-}"
    if [ -z "$workspace" ] && [ -f "$WORKSPACE_FILE" ]; then workspace="$(<"$WORKSPACE_FILE")"; fi
    bash "${ROOT}/agents/monitor_agent.sh" --stop
    start "${workspace:-$DEFAULT_WORKSPACE}"
    ;;
  status) status ;;
  open) open "http://127.0.0.1:8787/boss" ;;
  *) usage; exit 2 ;;
esac
