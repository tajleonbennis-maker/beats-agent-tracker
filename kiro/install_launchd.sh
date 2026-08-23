#!/bin/bash
# install_launchd.sh — 产品化部署：把观察器注册为 macOS LaunchAgent
#
# launchd 的 KeepAlive 是系统级守护：观察器被杀（哪怕 SIGKILL 整个进程组）
# launchd 也会立即重新拉起 watchdog → observer --resume，会话无缝续写。
#
# 用法：
#   bash kiro/install_launchd.sh <workspace>          # 安装并启动
#   bash kiro/install_launchd.sh --uninstall         # 停止并卸载
#
# 日志：~/Library/Logs/agent-monitor/observer.log（launchd StandardOutPath）
set -u

LABEL="com.agentmonitor.observer"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOGDIR="$HOME/Library/Logs/agent-monitor"
PYTHON_BIN="${PYTHON:-$(command -v python3 || echo python3)}"

uninstall() {
  launchctl unload "$PLIST" 2>/dev/null && echo "已卸载 $LABEL"
  rm -f "$PLIST"
  exit 0
}

[ "${1:-}" = "--uninstall" ] && uninstall

WS="${1:?用法: install_launchd.sh <workspace> | --uninstall}"
WS="$(cd "$WS" && pwd)"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$LOGDIR" "$HOME/Library/LaunchAgents"

cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>$DIR/kiro/watchdog.sh</string>
        <string>$WS</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHON</key>
        <string>$PYTHON_BIN</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>2</integer>
    <key>StandardOutPath</key>
    <string>$LOGDIR/observer.log</string>
    <key>StandardErrorPath</key>
    <string>$LOGDIR/observer.err</string>
</dict>
</plist>
EOF

launchctl unload "$PLIST" 2>/dev/null
launchctl load "$PLIST"
echo "已安装并启动 $LABEL"
echo "  监视工作区: $WS"
echo "  日志:        $LOGDIR/observer.log"
echo "  停止:        touch $DIR/events/STOP   （优雅出报告）"
echo "  卸载:        bash kiro/install_launchd.sh --uninstall"
