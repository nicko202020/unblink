#!/usr/bin/env bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/tmux.lib.sh"

SESSION_NAME="unb-prod"
PROJECT_DIR="$(tmux_get_project_dir)"
ENV_FILE="$PROJECT_DIR/.env"

BACKEND_CMD="go run ./cmd/server"

if ! tmux has-session -t "=$SESSION_NAME" 2>/dev/null; then
  echo "Creating tmux session '$SESSION_NAME'"

  tmux_session_init "$SESSION_NAME"
  tmux_configure_session "$SESSION_NAME"

  tmux_create_window "$SESSION_NAME" "backend" "$PROJECT_DIR" "$BACKEND_CMD" "$ENV_FILE"

  tmux_session_attach "$SESSION_NAME" "backend"
else
  echo "Attaching to existing session '$SESSION_NAME'"
  tmux attach-session -t "$SESSION_NAME"
fi
