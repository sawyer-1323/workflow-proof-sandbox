#!/usr/bin/env bash
# Credential audit (T1, P1, P5, W9, W11, W14).
# Usage: credential-audit.sh <profile>   profile: ci | agent | publish
#   ci, agent: any token-shaped value or key material is a finding.
#   publish:   key material on disk or in env is a finding; the minted token is expected.
# Reports NAMES, PATHS and COUNTS only. It never prints a value.
# Exit 1 if a forbidden credential is found for the profile.
set -uo pipefail

profile="${1:-ci}"
case "$profile" in ci|agent) strict=1 ;; *) strict=0 ;; esac
forbidden=0
pem_head='-----BEGIN'
pem_tail='PRIVATE KEY-----'
pem_regex="${pem_head}[A-Z ]*${pem_tail}"
token_regex='(ghs|ghp|gho|ghu|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-ant-[A-Za-z0-9_-]{10,}'

flag() { echo "FOUND  $1"; forbidden=1; }
info() { echo "INFO   $1"; }
ok()   { echo "NONE   $1"; }

echo "== credential audit, profile=$profile, runner=${RUNNER_NAME:-unknown}"

# 1. Environment variables: names that suggest credentials, and values shaped like keys.
names="$(env | cut -d= -f1 | grep -Ei 'token|secret|key|pass|cred|private|auth' | sort || true)"
if [ -n "$names" ]; then info "credential-like variable names: $(echo "$names" | tr '\n' ' ')"; else ok "credential-like variable names"; fi
while IFS= read -r name; do
  value="${!name-}"
  if printf '%s' "$value" | grep -Eq -- "$pem_regex"; then flag "private key material in env var $name"; fi
  if printf '%s' "$value" | grep -Eq -- "$token_regex"; then
    if [ "$strict" -eq 1 ]; then flag "token-shaped value in env var $name"; else info "token-shaped value in env var $name"; fi
  fi
done < <(env | cut -d= -f1)

# 2. Private key material on disk (paths only).
for dir in "$HOME" "${RUNNER_TEMP:-/nonexistent}" "${GITHUB_WORKSPACE:-/nonexistent}" /tmp; do
  [ -d "$dir" ] || continue
  hits="$(grep -rIlE --exclude-dir=node_modules --exclude-dir=.git -- "$pem_regex" "$dir" 2>/dev/null | head -20 || true)"
  if [ -n "$hits" ]; then flag "private key material under $dir: $(echo "$hits" | tr '\n' ' ')"; else ok "private key material under $dir"; fi
done

# 3. Token-shaped strings on disk (paths only).
for dir in "$HOME" "${RUNNER_TEMP:-/nonexistent}" "${GITHUB_WORKSPACE:-/nonexistent}" /tmp; do
  [ -d "$dir" ] || continue
  hits="$(grep -rIlE --exclude-dir=node_modules -- "$token_regex" "$dir" 2>/dev/null | head -20 || true)"
  if [ -n "$hits" ]; then
    if [ "$strict" -eq 1 ]; then flag "token-shaped strings under $dir: $(echo "$hits" | tr '\n' ' ')"; else info "token-shaped strings under $dir: $(echo "$hits" | tr '\n' ' ')"; fi
  else ok "token-shaped strings under $dir"; fi
done

# 4. GitHub CLI and Git credential routes.
if command -v gh >/dev/null 2>&1; then
  if GH_TOKEN= GITHUB_TOKEN= gh auth status >/dev/null 2>&1; then flag "gh has a stored login"; else ok "gh stored login"; fi
fi
[ -f "$HOME/.config/gh/hosts.yml" ] && flag "gh hosts file $HOME/.config/gh/hosts.yml" || ok "gh hosts file"
[ -f "$HOME/.git-credentials" ] && flag "plaintext git credentials file" || ok "plaintext git credentials file"
for scope in --system --global; do
  keys="$(git config "$scope" --name-only --get-regexp '^(credential\.|http\..*extraheader|url\..*insteadof)' 2>/dev/null | tr '\n' ' ' || true)"
  [ -n "$keys" ] && info "git $scope credential-related keys: $keys" || ok "git $scope credential-related keys"
done
if [ -n "${GITHUB_WORKSPACE:-}" ] && [ -d "$GITHUB_WORKSPACE/.git" ]; then
  keys="$(git -C "$GITHUB_WORKSPACE" config --local --name-only --get-regexp '^(credential\.|http\..*extraheader|include\.path|url\..*insteadof)' 2>/dev/null | tr '\n' ' ' || true)"
  [ -n "$keys" ] && flag "workspace git config holds credential-related keys: $keys" || ok "workspace git credential keys"
fi

# 5. SSH keys and agents.
if [ -d "$HOME/.ssh" ]; then info "~/.ssh entries: $(ls -1 "$HOME/.ssh" | tr '\n' ' ')"; else ok "~/.ssh directory"; fi
if ssh-add -l >/dev/null 2>&1; then flag "an ssh agent holds identities"; else ok "ssh agent identities"; fi

# 6. Other developer-tool and cloud credentials.
for f in "$HOME/.docker/config.json" "$HOME/.npmrc" "$HOME/.netrc" "$HOME/.aws/credentials" "$HOME/.azure" "$HOME/.config/gcloud"; do
  [ -e "$f" ] && info "present: $f" || ok "$f"
done

# 7. Process arguments (count only).
count="$(ps -eo args= 2>/dev/null | grep -Ec -- "$token_regex|$pem_head" || true)"
[ "${count:-0}" -gt 0 ] && info "processes whose arguments match credential patterns: $count" || ok "credential patterns in process arguments"

# 8. State left by an earlier job (W14): the canary written by a previous run.
[ -e "$HOME/.proof-canary" ] && flag "canary from an earlier job found in HOME" || ok "earlier-job canary in HOME"
[ -e /tmp/.proof-canary ] && flag "canary from an earlier job found in /tmp" || ok "earlier-job canary in /tmp"
date -u +%FT%TZ > "$HOME/.proof-canary" 2>/dev/null || true
date -u +%FT%TZ > /tmp/.proof-canary 2>/dev/null || true

echo "== result: $([ "$forbidden" -eq 0 ] && echo PASS || echo FAIL)"
exit "$forbidden"
