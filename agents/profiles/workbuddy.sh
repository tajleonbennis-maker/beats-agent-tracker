#!/bin/bash
# agent profile: WorkBuddy（VS Code / 桌面端通用）
# 种子进程：CodeBuddy IDE / VS Code 系应用均可列出，逗号分隔多个前缀
AGENT_NAME="WorkBuddy"
SEED_PATTERN="/Applications/CodeBuddy.app,/Applications/Code AI.app"

# 文件监视目标：workspace 之外的数据/配置目录（launcher 会自动附加敏感目录）
EXTRA_FS_PATHS=(
  "$HOME/.workbuddy"
  "$HOME/Library/Application Support/CodeBuddyExtension"
  "$HOME/Library/Application Support/WorkBuddy"
)

# 一等公民日志源（agents/audit_tailer.py 消费）
AUDIT_PROFILE="workbuddy"
