#!/bin/bash
# server_tunnel.sh — 建立 SSH 反向隧道，把服务器事件回传到本机 collector
#
# 链路：
#   服务器 102.134.48.49 的 agent.py --report-url http://127.0.0.1:<REMOTE_PORT>/ingest
#       ↓ SSH 反向隧道 -R
#   本机 collector (127.0.0.1:<LOCAL_PORT>) → 实时面板
#
# 用法:
#   bash kiro/server_tunnel.sh [本地端口] [服务器端口]
#   默认: 本地 8787 ← 服务器 18787
# 密码: 用环境变量 SSHPASS_PW 覆盖（默认读记忆里的服务器密码）
# 停止: Ctrl+C 或 pkill -f server_tunnel.sh
set -e

LOCAL_PORT="${1:-8787}"
REMOTE_PORT="${2:-18787}"
SERVER="${TUNNEL_SERVER:-root@102.134.48.49}"
SSHPASS_PW="${SSHPASS_PW:-r140Bpxm2cPCFt30}"

if ! command -v sshpass >/dev/null 2>&1; then
  echo "[tunnel] 需要 sshpass（brew install hudochenkov/sshpass/sshpass）"
  exit 1
fi

echo "[tunnel] 反向隧道: 服务器 127.0.0.1:${REMOTE_PORT} → 本机 127.0.0.1:${LOCAL_PORT}"
echo "[tunnel] 服务器 agent.py 上报到 http://127.0.0.1:${REMOTE_PORT}/ingest"
echo "[tunnel] 停止: pkill -f server_tunnel.sh"

while true; do
  echo "[tunnel] $(date +%H:%M:%S) 建立隧道..."
  sshpass -p "$SSHPASS_PW" ssh -N -T \
    -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
    -o ExitOnForwardFailure=yes \
    -o StrictHostKeyChecking=accept-new \
    -R "127.0.0.1:${REMOTE_PORT}:127.0.0.1:${LOCAL_PORT}" \
    "$SERVER"
  echo "[tunnel] $(date +%H:%M:%S) 隧道断开，3 秒后重连..."
  sleep 3
done
