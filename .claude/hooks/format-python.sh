#!/usr/bin/env bash
# PostToolUse hook (Edit|Write): auto-format edited Python files.
# Runs ruff --fix, black, isort against the single edited file.
#
# Deliberately calls the venv binaries DIRECTLY rather than `uv run`:
# `uv run` attempts a network sync on every invocation, which hangs for
# minutes on a restricted network and would stall every edit. If the dev
# env isn't installed yet, this no-ops silently. Install it with `make dev`.
#
# Line length / target versions come from pyproject.toml.

payload=$(cat)

p=$(printf '%s' "$payload" |
  sed -nE 's/.*"file_path"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p')

[ -n "$p" ] || exit 0

# Normalize separators: backslashes -> slashes, collapse repeats.
p=${p//\\//}
p=$(printf '%s' "$p" | tr -s '/')

# Python files only.
case "$p" in
  *.py) ;;
  *) exit 0 ;;
esac

[ -f "$p" ] || exit 0

# Locate the project venv (Scripts on Windows, bin on POSIX).
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bin=""
for d in "$root/.venv/Scripts" "$root/.venv/bin"; do
  [ -d "$d" ] && bin="$d" && break
done

# Dev env not installed -> no-op rather than hang or error.
[ -n "$bin" ] || exit 0

run() { # run <tool> <args...> ; skip if the tool isn't installed
  local exe="$bin/$1"
  [ -x "$exe" ] || [ -x "$exe.exe" ] || return 0
  shift
  "$exe" "$@" >/dev/null 2>&1 || true
}

run ruff check --fix "$p"
run black -q "$p"
run isort "$p"

exit 0
