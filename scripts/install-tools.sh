#!/usr/bin/env bash
# Installs the agent's tools as the runner user, BEFORE the sandbox exists, into
# root-owned paths the agent can execute but not modify.
#   - Claude Code CLI, pinned version, with its registry integrity checked;
#   - PostgreSQL 17 with pgTAP and pg_prove (T4), plus a role for the agent;
#   - a root-owned copy of the .NET SDK if it was installed under the runner's home.
# Usage: install-tools.sh [--no-postgres]   (writes the agent PATH to the root-owned
#   file /etc/proof-agent-path, read by run-as-agent.sh; no GITHUB_ENV write)
set -euo pipefail

CLAUDE_CODE_VERSION="2.1.309" # published 2026-10-22; at least 14 days old on 2026-11-06
CC_INTEGRITY="sha512-+lBYZRuXOJpiKJcRv/CK7gF+5UFNWyJE7hSxkgGUKDZOWgANl9MAabfTkrJk183Tp3B0Nv4xF/DU1t0BaKXOPw=="
CC_LINUX_X64_INTEGRITY="sha512-36D6kMC0fWdWLwBA8XYaJTSTXEWvw0Kc3WQYqterieKDtplIfUsE5jurZAYilhzOeF+uNL9SNn4DkwhQmUrRMg=="

# Claude Code.
sudo install -d -m 0755 /opt/claude-code
sudo env "PATH=$PATH" npm install --prefix /opt/claude-code --no-fund --no-audit \
  "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" >/dev/null
lock=/opt/claude-code/package-lock.json
got_main="$(jq -r '.packages["node_modules/@anthropic-ai/claude-code"].integrity' "$lock")"
got_x64="$(jq -r '.packages["node_modules/@anthropic-ai/claude-code-linux-x64"].integrity' "$lock")"
[ "$got_main" = "$CC_INTEGRITY" ] || { echo "::error::claude-code integrity mismatch"; exit 1; }
[ "$got_x64" = "$CC_LINUX_X64_INTEGRITY" ] || { echo "::error::claude-code-linux-x64 integrity mismatch"; exit 1; }
sudo chmod -R a+rX,go-w /opt/claude-code
echo "Claude Code ${CLAUDE_CODE_VERSION}: integrity verified" >&2

# .NET: make sure the SDK is outside the runner's home, which the agent cannot read.
dotnet_dir=""
if [ -n "${DOTNET_ROOT:-}" ] && [ -d "$DOTNET_ROOT" ]; then
  case "$DOTNET_ROOT" in
    "$HOME"/*) sudo cp -a "$DOTNET_ROOT" /opt/dotnet; sudo chmod -R a+rX,go-w /opt/dotnet; dotnet_dir=/opt/dotnet ;;
    *) dotnet_dir="$DOTNET_ROOT" ;;
  esac
fi

# PostgreSQL 17 with pgTAP.
if [ "${1:-}" != "--no-postgres" ]; then
  if [ ! -x /usr/lib/postgresql/17/bin/postgres ]; then
    sudo install -d /usr/share/postgresql-common/pgdg
    sudo curl -fsSL -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
      https://www.postgresql.org/media/keys/ACCC4CF8.asc
    codename="$(. /etc/os-release && echo "$VERSION_CODENAME")"
    echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt ${codename}-pgdg main" \
      | sudo tee /etc/apt/sources.list.d/pgdg.list >/dev/null
    sudo apt-get update -q >/dev/null
    sudo apt-get install -y -q postgresql-17 postgresql-17-pgtap libtap-parser-sourcehandler-pgtap-perl >/dev/null
  fi
  sudo pg_ctlcluster 17 main start 2>/dev/null || true
  sudo -u postgres psql -q -c "DO \$\$BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'agent') THEN CREATE ROLE agent LOGIN; END IF; END\$\$;"
  sudo -u postgres createdb -O agent toolchain_check 2>/dev/null || true
  sudo -u postgres psql -q -d toolchain_check -c "CREATE EXTENSION IF NOT EXISTS pgtap;"
fi

node_dir="$(dirname "$(command -v node)")"
case "$node_dir" in "$HOME"/*) echo "::error::node is under the runner's home"; exit 1 ;; esac
echo "/opt/claude-code/node_modules/.bin:${node_dir}${dotnet_dir:+:$dotnet_dir}:/usr/lib/postgresql/17/bin:/usr/local/bin:/usr/bin:/bin" \
  | sudo tee /etc/proof-agent-path >/dev/null
sudo chown root:root /etc/proof-agent-path
sudo chmod 0644 /etc/proof-agent-path
echo "AGENT_PATH: $(cat /etc/proof-agent-path)"
