#!/bin/bash
# Trae IDE / Trae Agent 独立 profile。
AGENT_NAME="Trae"
SEED_PATTERN="/Applications/Trae.app,Trae.app/Contents"
EXTRA_FS_PATHS=(
  "$HOME/Library/Application Support/Trae"
  "$HOME/.trae"
)
AUDIT_PROFILE=""
SESSION_PROFILE=""
