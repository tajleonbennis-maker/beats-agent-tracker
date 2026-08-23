#!/bin/bash
# watchdog.sh — 观察器守护进程（产品化长期运行）
#
# 职责：
#   1. 启动 kiro/observer.py 并在异常退出后 1 秒内自动拉起
#   2. 配合 observer 的 --resume：同一会话（trace_id）断链续写，哈希链无缝
#   3. 优雅停止：observer 退出码 42（STOP 哨兵 / SIGTERM）→ watchdog 也退出
#
# 用法：
#   bash kiro/watchdog.sh <workspace> [trace_id] [-- extra observer args ...]
#   停止：touch events/STOP          （观察器收尾出报告，watchdog 退出）
#         kill -TERM <watchdog_pid>  （透传给观察器，同样优雅收尾）
#
# 环境变量：
#   PYTHON   指定 python3 路径（默认 /usr/bin/env python3）
# 兼容 macOS 自带 bash 3.2：不用 set -u 空数组展开
set -o pipefail

WS="${1:?用法: watchdog.sh <workspace> [trace_id] [-- extra observer args]}"
TRACE_ID="${2:-}"
shift; shift || true
# 如果用户用了 -- 分隔符，去掉它
[ "${1:-}" = "--" ] && shift
EXTRA_ARGS=("$@")
PYTHON_BIN="${PYTHON:-$(command -v python3 || echo python3)}"

DIR="$(cd "$(dirname "$0")/.." && pwd)"
EVENTS_DIR="$DIR/events"
STOP_FILE="$EVENTS_DIR/STOP"
SESSION_FILE="$EVENTS_DIR/.current_session"
mkdir -p "$EVENTS_DIR"

OBSERVER_PID=""

cleanup() {
  # 透传 SIGTERM 给观察器（触发其优雅收尾，退出码 42）
  if [ -n "$OBSERVER_PID" ] && kill -0 "$OBSERVER_PID" 2>/dev/null; then
    kill -TERM "$OBSERVER_PID" 2>/dev/null
    wait "$OBSERVER_PID" 2>/dev/null
  fi
  rm -f "$SESSION_FILE"
  echo "[watchdog] 已退出"
  exit 0
}
trap cleanup TERM INT

# 清掉可能残留的 STOP 哨兵（上次停止请求），避免新会话秒退
rm -f "$STOP_FILE"

restarts=0
while true; do
  # 若给了 trace_id 就续写；否则首轮记录新会话 id 供人查询
  if [ -n "$TRACE_ID" ]; then
    "$PYTHON_BIN" "$DIR/kiro/observer.py" --workspace "$WS" --resume "$TRACE_ID" "${EXTRA_ARGS[@]}" &
  else
    "$PYTHON_BIN" "$DIR/kiro/observer.py" --workspace "$WS" "${EXTRA_ARGS[@]}" &
  fi
  OBSERVER_PID=$!
  if [ -z "$TRACE_ID" ]; then
    # 首轮启动后，从观察器日志捕获新 trace_id（kiro_ 开头文件最新一个）
    sleep 2
    NEWEST=$(ls -t "$EVENTS_DIR"/kiro_*.ndjson 2>/dev/null | head -1)
    [ -n "$NEWEST" ] && TRACE_ID=$(basename "$NEWEST" .ndjson)
    echo "$TRACE_ID" > "$SESSION_FILE"
  fi
  wait "$OBSERVER_PID"
  code=$?
  OBSERVER_PID=""

  if [ "$code" -eq 42 ]; then
    echo "[watchdog] 观察器优雅停止（exit 42），守护结束"
    break
  fi
  restarts=$((restarts + 1))
  echo "[watchdog] ⚠️ 观察器异常退出（exit $code），1 秒后第 $restarts 次拉起 → 续写会话 $TRACE_ID"
  sleep 1
done

rm -f "$SESSION_FILE"
