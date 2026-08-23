#!/bin/bash
# install.sh — 把服务器端采集器部署到目标服务器（在被监视的 Mac 上运行）
#
# 用法：
#   bash server/install.sh <user@host> [ssh端口]
#   bash server/install.sh root@102.134.48.49
#
# 做的事：
#   1. scp server/agent.py → 服务器 /opt/agent-monitor/agent.py
#   2. 写 systemd 单元 agent-monitor.service（root、开机自启、崩溃自动拉起）
#   3. systemctl enable --now
#
# 服务器要求：Linux + python3 + systemd（Ubuntu/Debian/CentOS 均可）
# 停止（在服务器上）：systemctl stop agent-monitor
# 卸载：systemctl disable --now agent-monitor && rm -rf /opt/agent-monitor
set -euo pipefail

TARGET="${1:?用法: bash server/install.sh <user@host> [port]}"
PORT="${2:-22}"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
REMOTE_DIR="/opt/agent-monitor"

echo "==> 上传采集器到 $TARGET:$REMOTE_DIR"
ssh -p "$PORT" "$TARGET" "mkdir -p $REMOTE_DIR /var/lib/agent-monitor/events"
scp -P "$PORT" "$DIR/server/agent.py" "$TARGET:$REMOTE_DIR/agent.py"

echo "==> 写入 systemd 单元（root 常驻 + 崩溃自动拉起）"
ssh -p "$PORT" "$TARGET" "cat > /etc/systemd/system/agent-monitor.service <<'UNIT'
[Unit]
Description=Agent-Monitor server-side collector
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $REMOTE_DIR/agent.py --watch /opt,/srv,/root,/var/www,/home --poll-proc 0.25 --poll-net 0.5 --poll-file 5
Restart=always
RestartSec=2
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now agent-monitor.service
systemctl status agent-monitor.service --no-pager | head -8"

echo ""
echo "部署完成。服务器上的事件流："
echo "  /var/lib/agent-monitor/events/srv_*.ndjson"
echo "  实时日志：journalctl -u agent-monitor -f"
echo "  停止：systemctl stop agent-monitor"
