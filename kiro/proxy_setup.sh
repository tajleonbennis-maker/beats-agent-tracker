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

# 获取所有启用的物理网络服务。不能取列表第一项：它可能不是默认路由所在接口。
SERVICES=()
while IFS= read -r service; do
  case "$service" in
    ""|"An asterisk"*) continue ;;
    \**) continue ;;
    *VPN*|*L2TP*) continue ;;
  esac
  SERVICES+=("$service")
done < <(networksetup -listallnetworkservices)
if [ ${#SERVICES[@]} -eq 0 ]; then
  echo "[proxy] 找不到已启用的网络服务"
  exit 1
fi

case "$MODE" in
  on)
    for service in "${SERVICES[@]}"; do
      echo "[proxy] 在 '$service' 上设置 HTTP/HTTPS 代理为 $HOST:$PORT"
      networksetup -setwebproxy "$service" "$HOST" "$PORT"
      networksetup -setsecurewebproxy "$service" "$HOST" "$PORT"
    done
    echo "[proxy] ✅ 已开启。Kiro 等应用的新连接将经过 mitmproxy。"
    echo "[proxy] 注意：bash kiro/monitor_kiro.sh ... --mitm 会自动启动 mitmproxy。"
    ;;
  off)
    for service in "${SERVICES[@]}"; do
      echo "[proxy] 关闭 '$service' 的 HTTP/HTTPS 代理"
      networksetup -setwebproxystate "$service" off
      networksetup -setsecurewebproxystate "$service" off
    done
    echo "[proxy] ✅ 已关闭"
    ;;
  status)
    for service in "${SERVICES[@]}"; do
      echo "[proxy] 网络服务: $service"
      networksetup -getwebproxy "$service"
      networksetup -getsecurewebproxy "$service"
    done
    ;;
  *)
    echo "用法: $0 on|off|status"
    exit 1
    ;;
esac
