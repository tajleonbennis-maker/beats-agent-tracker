#!/bin/bash
# 兼容名称：vscode profile 专指 VS Code 中的 Codex Agent。
AGENT_NAME="Codex"
TRACE_ID="vscode_codex_process_live"
SEED_PATTERN=".vscode/extensions/openai.chatgpt,.vscode-insiders/extensions/openai.chatgpt"

EXTRA_FS_PATHS=(
  "$HOME/.vscode/extensions"
  "$HOME/.vscode-insiders/extensions"
  "$HOME/.codex"
  "$HOME/Library/Application Support/Code/User"
  "$HOME/.workbuddy"
  "$HOME/Library/Application Support/WorkBuddy"
  "$HOME/.trae"
  "$HOME/Library/Application Support/Trae"
)

AUDIT_PROFILE=""
SESSION_PROFILE="codex"
