#!/bin/bash
# VS Code 内的 OpenAI Codex 扩展；不包含其他 VS Code 插件。
AGENT_NAME="Codex"
TRACE_ID="vscode_codex_process_live"
SEED_PATTERN=".vscode/extensions/openai.chatgpt,.vscode-insiders/extensions/openai.chatgpt"
EXTRA_FS_PATHS=(
  "$HOME/.codex"
  "$HOME/.vscode/extensions"
  "$HOME/Library/Application Support/Code/User"
)
AUDIT_PROFILE=""
SESSION_PROFILE="codex"
