#!/bin/bash
# agent profile: Kiro（AWS CodeWhisperer 套壳 IDE）
AGENT_NAME="Kiro"
SEED_PATTERN="/Applications/Kiro.app"

EXTRA_FS_PATHS=(
  "$HOME/Library/Application Support/Kiro/User"
)

# Kiro 无第一方审计日志，全靠被动观测 + MITM
AUDIT_PROFILE=""
