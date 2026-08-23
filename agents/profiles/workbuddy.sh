#!/bin/bash
# agent profile: WorkBuddy 独立桌面 Agent（不包含 VS Code/Codex）
AGENT_NAME="WorkBuddy"
SEED_PATTERN="/Applications/WorkBuddy.app"

# 文件监视目标：workspace 之外的数据/配置目录（launcher 会自动附加敏感目录）
EXTRA_FS_PATHS=(
  "$HOME/.workbuddy"
  "$HOME/Library/Application Support/CodeBuddyExtension"
  "$HOME/Library/Application Support/WorkBuddy"
)

# 一等公民日志源（agents/audit_tailer.py 消费）
AUDIT_PROFILE="workbuddy"
SESSION_PROFILE=""
