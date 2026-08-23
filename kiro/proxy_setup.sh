#!/bin/bash
# 设置/清除 macOS 系统代理，让 Kiro 走本地 mitmproxy（127.0.0.1:8080）
#
# 用法：
#   bash kiro/proxy_setup.sh on     # 开启代理
#   bash kiro/proxy_setup.sh off    # 关闭代理
#   bash kiro/proxy_setup.sh status # 查看当前代理
set -e

MODE="${1:-status}"
PORT=8080
HOST=127.0.0.1

# 获取当前活跃的网络接口（Wi-Fi 或 Ethernet）
IFACE=$(networksetup -listallnetworkservices | grep -E "Wi-Fi|Ethernet|USB|Thunderbolt" | head -1 | sed 's/^\*//')
if [ -z "$IFACE" ]; then
  echo "[proxy] 找不到网络接口"
  exit 1
fi

case "$MODE" in
  on)
    echo "[proxy] 在接口 '$IFACE' 上设置 HTTP/HTTPS 代理为 $HOST:$PORT"
    networksetup -setwebproxy "$IFACE" "$HOST" "$PORT"
    networksetup -setsecurewebproxy "$IFACE" "$HOST" "$PORT"
    echo "[proxy] ✅ 已开启。Kiro 等应用的新连接将经过 mitmproxy。"
    echo "[proxy] 注意：bash kiro/monitor_kiro.sh ... --mitm 会自动启动 mitmproxy。"
    ;;
  off)
    echo "[proxy] 关闭接口 '$IFACE' 的 HTTP/HTTPS 代理"
    networksetup -setwebproxystate "$IFACE" off
    networksetup -setsecurewebproxystate "$IFACE" off
    echo "[proxy] ✅ 已关闭"
    ;;
  status)
    echo "[proxy] 接口: $IFACE"
    networksetup -getwebproxy "$IFACE"
    networksetup -getsecurewebproxy "$IFACE"
    ;;
  *)
    echo "用法: $0 on|off|status"
    exit 1
    ;;
esac
