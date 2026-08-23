#!/bin/bash
# 仅让 Trae 使用本项目的 MITM，不修改 macOS 系统代理。
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROXY_URL="${TRAE_PROXY_URL:-http://127.0.0.1:8080}"
if [ -n "${TRAE_APP_NAME:-}" ]; then
  APP_NAME="$TRAE_APP_NAME"
elif [ -d "/Applications/Trae.app" ]; then
  APP_NAME="Trae"
elif [ -d "/Applications/TRAE SOLO CN.app" ]; then
  APP_NAME="TRAE SOLO CN"
else
  echo "未找到 Trae 应用（检查了 Trae.app 和 TRAE SOLO CN.app）" >&2
  exit 1
fi

is_listening() {
  lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
}

case "${1:-status}" in
  status)
    is_listening 8787 && echo "✓ collector 127.0.0.1:8787" || echo "✗ collector 127.0.0.1:8787"
    is_listening 8080 && echo "✓ mitmproxy 127.0.0.1:8080" || echo "✗ mitmproxy 127.0.0.1:8080"
    is_listening 1087 && echo "✓ upstream 127.0.0.1:1087" || echo "! upstream 127.0.0.1:1087（MITM 将直连）"
    ;;
  start)
    workspace="${2:-$ROOT}"
    if ! is_listening 8787 || ! is_listening 8080; then
      bash "$ROOT/tracker.sh" start "$workspace"
    fi
    if pgrep -f '/Applications/(Trae|TRAE SOLO CN).app/Contents' >/dev/null 2>&1; then
      echo "Trae 正在运行，Chromium 不会给现有进程补加代理参数。"
      echo "请保存工作并完全退出 Trae，然后执行：bash agents/trae_proxy.sh launch"
      exit 2
    fi
    open -a "$APP_NAME" --args --proxy-server="$PROXY_URL"
    echo "Trae 已使用专属代理启动：$PROXY_URL（系统代理未修改）"
    ;;
  launch)
    if ! is_listening 8787 || ! is_listening 8080; then
      echo "采集服务未运行；请先执行：bash agents/trae_proxy.sh start [workspace]" >&2
      exit 1
    fi
    if pgrep -f '/Applications/(Trae|TRAE SOLO CN).app/Contents' >/dev/null 2>&1; then
      echo "Trae 仍在运行，请完全退出后重试。" >&2
      exit 2
    fi
    open -a "$APP_NAME" --args --proxy-server="$PROXY_URL"
    echo "Trae 已使用专属代理启动：$PROXY_URL（系统代理未修改）"
    ;;
  *)
    echo "用法: bash agents/trae_proxy.sh {status|start|launch} [workspace]" >&2
    exit 2
    ;;
esac
