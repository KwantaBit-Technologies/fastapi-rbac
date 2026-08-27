#!/usr/bin/env bash
# PreToolUse hook (Edit|Write): deny edits to .env / secret files.
# Reads the hook payload JSON on stdin; prints a deny decision only for secret files.
# Silence = allow.

payload=$(cat)

# Extract tool_input.file_path without jq (not available on this machine).
p=$(printf '%s' "$payload" |
  sed -nE 's/.*"file_path"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')

[ -n "$p" ] || exit 0

# Normalize separators: backslashes -> slashes, collapse repeats.
# Handles both "C:\path" and JSON-doubled "C:\\path".
p=${p//\\//}
p=$(printf '%s' "$p" | tr -s '/')
base=${p##*/}

case "$base" in
  .env | .env.* | *.env)
    printf '%s' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Editing .env / secret files is blocked by project policy (.claude/hooks/block-secrets.sh). This repo injects SECRET_KEY, DATABASE_URL and JWT config via the environment; edit them outside the agent."}}'
    ;;
esac

exit 0
