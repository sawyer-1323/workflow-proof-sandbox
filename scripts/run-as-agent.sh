#!/usr/bin/env bash
# Runs a command as the unprivileged agent user with a reset environment.
# The agent never receives the model key: ANTHROPIC_API_KEY is always the fixed
# placeholder, and ANTHROPIC_BASE_URL points at the local model proxy.
# Usage: run-as-agent.sh [--quiet <name>] [--stdin <file>] <workdir> <command> [args...]
#   --quiet <name>: the command's stdout and stderr go to /home/agent/out/<name>.out
#     and .err, and no agent-uid process keeps the job-log pipe. Use it for every
#     command that runs after, or as, untrusted agent code.
# The agent holds NO credential canary: the model-key detection is done by a
# root step on the dump this collection produces. The four GITHUB_* output-file
# paths are passed through so the collector can TEST whether the agent can read
# them; they name files, not secrets.
# Env: AGENT_PATH (optional; default: the root-owned /etc/proof-agent-path
#   written by install-tools.sh); AGENT_MODEL, MP_MAX_TOKENS, DUMP_DIR (for the
#   collector); GITHUB_OUTPUT, GITHUB_ENV, GITHUB_STATE, GITHUB_STEP_SUMMARY.
set -euo pipefail

quiet=""; stdin_file=/dev/null
while [ "$#" -gt 0 ]; do
  case "$1" in
    --quiet) [[ "$2" =~ ^[a-z0-9-]+$ ]] || { echo "bad --quiet name"; exit 2; }; quiet="/home/agent/out/$2"; shift 2 ;;
    --stdin) stdin_file="$2"; shift 2 ;;
    *) break ;;
  esac
done
workdir="$1"; shift
if [ -z "${AGENT_PATH:-}" ]; then
  [ -f /etc/proof-agent-path ] && [ "$(stat -c %u /etc/proof-agent-path)" = 0 ] \
    || { echo "agent PATH file missing or not root-owned"; exit 2; }
  AGENT_PATH="$(cat /etc/proof-agent-path)"
fi
[[ "$AGENT_PATH" =~ ^[A-Za-z0-9/._:-]+$ ]] || { echo "bad agent PATH"; exit 2; }
export AGENT_PATH

export ANTHROPIC_BASE_URL="http://127.0.0.1:${MODEL_PROXY_PORT:-8787}"
export ANTHROPIC_API_KEY="proof-placeholder-not-a-key"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
export DISABLE_AUTOUPDATER=1
export CLAUDE_CODE_MAX_OUTPUT_TOKENS="${MP_MAX_TOKENS:-8192}"
export ANTHROPIC_SMALL_FAST_MODEL="${AGENT_MODEL:-}"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export AGENT_WORKDIR="$workdir" AGENT_QUIET="$quiet" AGENT_STDIN="$stdin_file"

keep="ANTHROPIC_BASE_URL,ANTHROPIC_API_KEY,CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC,DISABLE_AUTOUPDATER"
keep="$keep,CLAUDE_CODE_MAX_OUTPUT_TOKENS,ANTHROPIC_SMALL_FAST_MODEL,AGENT_MODEL,MP_MAX_TOKENS"
keep="$keep,DOTNET_CLI_TELEMETRY_OPTOUT,DOTNET_NOLOGO,DOTNET_SKIP_FIRST_TIME_EXPERIENCE"
keep="$keep,AGENT_PATH,AGENT_WORKDIR,AGENT_QUIET,AGENT_STDIN,MODEL_PROXY_PORT,PROOF_STAGE"
keep="$keep,DUMP_DIR,GITHUB_OUTPUT,GITHUB_ENV,GITHUB_STATE,GITHUB_STEP_SUMMARY"

exec sudo -u agent -H --preserve-env="$keep" -- /bin/bash -c '
  export PATH="$AGENT_PATH"
  cd "$AGENT_WORKDIR"
  if [ -n "$AGENT_QUIET" ]; then
    exec "$@" <"$AGENT_STDIN" >"$AGENT_QUIET.out" 2>"$AGENT_QUIET.err"
  fi
  exec "$@" <"$AGENT_STDIN"' agent-run "$@"
