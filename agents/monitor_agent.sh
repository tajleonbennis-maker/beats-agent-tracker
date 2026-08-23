#!/bin/bash
# monitor_agent.sh — 通用 Agent 监控栈启动器（从 monitor_kiro.sh 演化）
#
# 在你自己的终端里跑（不要在 Agent 沙箱里跑），因为需要：
#   - lsof 读取其他进程网络/文件描述符
#   - FSEvents 注册系统级文件监视
#
# 用法:
#   bash agents/monitor_agent.sh <profile> /path/to/workspace [--mitm] [--capture-reads]
#   bash agents/monitor_agent.sh workbuddy ~/code/myproject --capture-reads
#   bash agents/monitor_agent.sh kiro ~/code/myproject --mitm --capture-reads
#   bash agents/monitor_agent.sh --stop
#
# profile = agents/profiles/<name>.sh，定义：
#   AGENT_NAME      面板显示名
#   SEED_PATTERN    种子进程 argv 前缀（逗号分隔多个）
#   EXTRA_FS_PATHS  额外文件监视目录
#   AUDIT_PROFILE   一等公民日志 profile（空 = 该 Agent 无第一方日志）
#   SESSION_PROFILE 本地会话日志适配器（codex 或空）
# 停止： bash agents/monitor_agent.sh --stop
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-/Users/jatsmith/.workbuddy/binaries/python/versions/3.13.12/bin/python3}"
PIDFILE="${ROOT}/events/.agent_stack.pids"
COLLECTOR_URL="http://127.0.0.1:8787/ingest"

mkdir -p "${ROOT}/events"

cleanup_and_exit() {
  echo "[stack] 启动失败，清理中..."
  [ -f "$PIDFILE" ] && bash "$0" --stop >/dev/null 2>&1 || true
  exit 1
}
trap cleanup_and_exit ERR

# ---------------- stop mode
if [ "${1:-}" = "--stop" ]; then
  for f in "$PIDFILE" "${ROOT}/events/.kiro_stack.pids"; do
    [ -f "$f" ] || continue
    while read -r name pid; do
      [ -z "$pid" ] && continue
      if kill -0 "$pid" 2>/dev/null; then
        echo "[stack] 停止 $name (pid $pid)"
        kill -TERM "$pid" 2>/dev/null || true
        sleep 0.5
        kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
      fi
    done < "$f"
    rm -f "$f"
  done
  # 兜底：杀所有相关子进程。
  # 注意：模式必须锚定到实际启动命令（脚本路径+首参数），否则会误杀任何
  # 命令行里恰好提到这些文件名的进程（如 grep/编辑器/AI 会话的 shell）。
  pkill -f "collector\.py --port" 2>/dev/null || true
  pkill -f "fs_watcher\.py --" 2>/dev/null || true
  pkill -f "kiro/observer\.py --agent-name" 2>/dev/null || true
  pkill -f "kiro/watchdog\.sh .*--agent-name" 2>/dev/null || true
  pkill -f "audit_tailer\.py --profile" 2>/dev/null || true
  pkill -f "codex_session_tailer\.py --collector" 2>/dev/null || true
  pkill -f "mitmdump .*mitm_addon" 2>/dev/null || true
  pkill -f "mitmdump --mode" 2>/dev/null || true
  echo "[stack] 已停止"
  exit 0
fi

PROFILE="${1:?用法: bash agents/monitor_agent.sh <profile> /path/to/workspace [--mitm] [--capture-reads]}"
WS="${2:?用法: bash agents/monitor_agent.sh <profile> /path/to/workspace [--mitm] [--capture-reads]}"
shift 2 || true

PROFILE_FILE="${ROOT}/agents/profiles/${PROFILE}.sh"
[ -f "$PROFILE_FILE" ] || { echo "未知 profile: $PROFILE（找不到 $PROFILE_FILE）"; exit 1; }
# shellcheck disable=SC1090
source "$PROFILE_FILE"
AGENT_NAME="${AGENT_NAME:-$PROFILE}"
SEED_PATTERN="${SEED_PATTERN:-}"
AUDIT_PROFILE="${AUDIT_PROFILE:-}"
SESSION_PROFILE="${SESSION_PROFILE:-}"

ENABLE_MITM=0
CAPTURE_READS_ARG=""
TRACE_ID="${TRACE_ID:-${PROFILE}_live}"
while [ $# -gt 0 ]; do
  case "$1" in
    --mitm) ENABLE_MITM=1 ;;
    --capture-reads) CAPTURE_READS_ARG="--capture-reads" ;;
    --trace-id) TRACE_ID="$2"; shift ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
  shift
done

# 避免重复启动
if [ -f "$PIDFILE" ]; then
  old=$(awk '/collector/{print $2}' "$PIDFILE" | head -1)
  if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then
    echo "[stack] 采集栈已在运行 (collector pid $old)，面板: http://127.0.0.1:8787"
    exit 0
  fi
  rm -f "$PIDFILE"
fi

export COLLECTOR_URL TRACE_ID AGENT_NAME

# ---------------- 1. collector
COLLECTOR_LOG="${ROOT}/events/collector.log"
"$PY" "${ROOT}/dashboard/collector.py" --port 8787 >"$COLLECTOR_LOG" 2>&1 &
COLLECTOR_PID=$!
echo "collector $COLLECTOR_PID" >> "$PIDFILE"
sleep 1
if ! kill -0 $COLLECTOR_PID 2>/dev/null; then
  echo "[stack] collector 启动失败，日志:"; tail -20 "$COLLECTOR_LOG"; cleanup_and_exit
fi

# ---------------- 2. FSEvents 文件监视（workspace + profile 目录 + 敏感目录）
FS_LOG="${ROOT}/events/fs_watcher.log"
FS_PATHS=("$WS")
for _d in "${EXTRA_FS_PATHS[@]}"; do
  [ -d "$_d" ] && FS_PATHS+=("$_d")
done
for _d in "$HOME/Documents" "$HOME/Desktop" "$HOME/Downloads" \
          "$HOME/.ssh" "$HOME/.aws" "$HOME/.gnupg" "$HOME/.config"; do
  [ -d "$_d" ] && FS_PATHS+=("$_d")
done
TRACE_ID=filesystem_live AGENT_NAME=System "$PY" "${ROOT}/dashboard/fs_watcher.py" \
  "${FS_PATHS[@]}" >"$FS_LOG" 2>&1 &
FS_PID=$!
echo "fs_watcher $FS_PID" >> "$PIDFILE"

# ---------------- 3. MITM 代理（可选，需先装 CA）
if [ "$ENABLE_MITM" = "1" ]; then
  if ! command -v mitmproxy >/dev/null 2>&1; then
    echo "[stack] 未找到 mitmproxy，跳过 MITM。安装: brew install mitmproxy"
    ENABLE_MITM=0
  else
    MITM_LOG="${ROOT}/events/mitmproxy.log"
    MITM_UPSTREAM="${MITM_UPSTREAM:-http://127.0.0.1:1087}"
    UPSTREAM_PORT="${MITM_UPSTREAM##*:}"
    if lsof -nP -iTCP:"$UPSTREAM_PORT" -sTCP:LISTEN >/dev/null 2>&1; then
      MODE="upstream:${MITM_UPSTREAM}@8080"
      echo "[stack] 检测到上游代理在端口 $UPSTREAM_PORT，mitmproxy 走 upstream 模式"
    else
      MODE="regular@8080"
      echo "[stack] 未检测到上游代理($UPSTREAM_PORT)，mitmproxy 走直连模式"
    fi
    mitmdump --mode "$MODE" --scripts "${ROOT}/dashboard/mitm_addon.py" \
      --set termlog_verbosity=warn >"$MITM_LOG" 2>&1 &
    MITM_PID=$!
    echo "mitmdump $MITM_PID" >> "$PIDFILE"
    echo "[stack] MITM 代理已启动: http://127.0.0.1:8080（切系统代理: bash kiro/proxy_setup.sh on）"
  fi
fi

# ---------------- 4. 一等公民审计日志 tailer（profile 提供时）
AUDIT_PID=""
if [ -n "$AUDIT_PROFILE" ]; then
  AUDIT_LOG="${ROOT}/events/audit_tailer.log"
  BACKFILL="${AUDIT_BACKFILL_HOURS:-0}"
  "$PY" "${ROOT}/agents/audit_tailer.py" --profile "$AUDIT_PROFILE" \
    --collector "$COLLECTOR_URL" --backfill-hours "$BACKFILL" >"$AUDIT_LOG" 2>&1 &
  AUDIT_PID=$!
  echo "audit_tailer $AUDIT_PID" >> "$PIDFILE"
fi

# ---------------- 4b. 本地会话日志（Codex VS Code 等）
SESSION_PID=""
if [ "$SESSION_PROFILE" = "codex" ]; then
  SESSION_LOG="${ROOT}/events/codex_session_tailer.log"
  "$PY" "${ROOT}/agents/codex_session_tailer.py" --collector "$COLLECTOR_URL" \
    --backfill-latest >"$SESSION_LOG" 2>&1 &
  SESSION_PID=$!
  echo "session_tailer $SESSION_PID" >> "$PIDFILE"
fi

# ---------------- 5. 被动 observer（带 watchdog）
OBSERVER_LOG="${ROOT}/events/observer.log"
OBSERVER_ARGS=(--agent-name "$AGENT_NAME" --collector "$COLLECTOR_URL")
[ -n "$CAPTURE_READS_ARG" ] && OBSERVER_ARGS+=(--capture-reads)
[ -n "$SEED_PATTERN" ] && OBSERVER_ARGS+=(--seed-pattern "$SEED_PATTERN")

bash "${ROOT}/kiro/watchdog.sh" "$WS" "$TRACE_ID" \
  "${OBSERVER_ARGS[@]}" \
  >"$OBSERVER_LOG" 2>&1 &
WATCHDOG_PID=$!
echo "watchdog $WATCHDOG_PID" >> "$PIDFILE"

# ---------------- 6. 打开面板
sleep 2
command -v open >/dev/null 2>&1 && open "http://127.0.0.1:8787" || true

echo "=============================================="
echo " Agent 执行监视器 — 采集栈已启动 (profile: $PROFILE)"
echo " 面板      : http://127.0.0.1:8787"
echo " workspace : $WS"
echo " trace_id  : $TRACE_ID"
[ -n "$SEED_PATTERN" ] && echo " 种子进程  : $SEED_PATTERN"
[ -n "$AUDIT_PID" ] && echo " audit日志 : 已接入 ($AUDIT_PROFILE, pid $AUDIT_PID)"
[ -n "$SESSION_PID" ] && echo " 会话日志  : 已接入 ($SESSION_PROFILE, pid $SESSION_PID)"
[ "$ENABLE_MITM" = "1" ] && echo " MITM      : 127.0.0.1:8080（已启用）"
echo " 停止      : bash agents/monitor_agent.sh --stop"
echo "=============================================="
