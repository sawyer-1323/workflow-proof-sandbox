#!/usr/bin/env bash
# Credential audit (T1, P1, P5, W9, W11, W14).
# Usage: credential-audit.sh <profile>   profile: ci | agent | publish | selftest
#   ci, agent: any token-shaped value or key material is a finding.
#   publish:   key material on disk or in env is a finding; the minted token is expected.
#   selftest:  strict, for test/credential-audit.test.js only. It scans only the
#              directories the test names (AUDIT_SCAN_DIRS, AUDIT_TMP_DIRS) and skips the
#              machine checks (sections 4 to 8). No other profile reads an AUDIT_* variable.
# Reports NAMES, PATHS and COUNTS only. It never prints a value.
# Exit 1 if a forbidden credential is found for the profile; 2 on a usage error.
#
# Pinned fixtures (credential-audit.allow). The repository holds a few synthetic files
# that contain credential-shaped text on purpose. A hit is exempt only if ALL of these hold:
#   - the file sits at exactly the reviewed path, relative to the repository root;
#   - its git blob hash equals the pinned one (an edited file is scanned like any other);
#   - it was found while scanning a non-temporary directory. Hits under /tmp or
#     RUNNER_TEMP (or a selftest AUDIT_TMP_DIRS entry) are never exempt.
# A relocated or copied fixture, a file the allowlist doesn't name, and every hit in a
# temporary directory are findings. Exemptions are listed by path, never silently.
set -uo pipefail

profile="${1:-ci}"
case "$profile" in
  ci|agent|selftest) strict=1 ;;
  publish) strict=0 ;;
  *) echo "usage: $0 ci|agent|publish|selftest" >&2; exit 2 ;;
esac
forbidden=0
pem_head='-----BEGIN'
pem_tail='PRIVATE KEY-----'
pem_regex="${pem_head}[A-Z ]*${pem_tail}"
token_regex='(ghs|ghp|gho|ghu|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-ant-[A-Za-z0-9_-]{10,}'

flag() { echo "FOUND  $1"; forbidden=1; }
info() { echo "INFO   $1"; }
ok()   { echo "NONE   $1"; }

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
strip() { local d="$1"; while [ "${#d}" -gt 1 ] && [ "${d%/}" != "$d" ]; do d="${d%/}"; done; printf '%s' "$d"; }

# The repository root that pinned paths are relative to, and the directories to scan.
case "$profile" in
  ci|publish)
    repo_root="$(strip "${GITHUB_WORKSPACE:-}")"
    allow_file="$here/credential-audit.allow"
    scan_dirs=("$HOME" "${GITHUB_WORKSPACE:-/nonexistent}")
    tmp_dirs=("${RUNNER_TEMP:-/nonexistent}" /tmp) ;;
  agent)
    # The staged copy this script runs from (stage-for-agent.sh puts the repository at
    # the agent's work directory; the script is <root>/scripts/probes/credential-audit.sh).
    repo_root="$(cd "$here/../.." && pwd)"
    allow_file="$here/credential-audit.allow"
    scan_dirs=("$HOME" "${GITHUB_WORKSPACE:-/nonexistent}")
    tmp_dirs=("${RUNNER_TEMP:-/nonexistent}" /tmp) ;;
  selftest)
    repo_root="$(strip "${AUDIT_REPO_ROOT:?selftest needs AUDIT_REPO_ROOT}")"
    allow_file="${AUDIT_ALLOW_FILE:?selftest needs AUDIT_ALLOW_FILE}"
    IFS=: read -r -a scan_dirs <<<"${AUDIT_SCAN_DIRS:-}"
    IFS=: read -r -a tmp_dirs <<<"${AUDIT_TMP_DIRS:-}" ;;
esac

echo "== credential audit, profile=$profile, runner=${RUNNER_NAME:-unknown}"

# The git blob hash of a file's exact bytes (no git needed, no line-ending filters).
blob_of() { local n; n="$(wc -c <"$1" | tr -d ' ')"; { printf 'blob %s\0' "$n"; cat "$1"; } | sha1sum | cut -c1-40; }
# Exit 0 only if $1 is at a pinned path under the repository root with the pinned blob.
pinned() {
  local f="$1" rel want
  [ -n "$repo_root" ] && [ -f "$allow_file" ] && [ -f "$f" ] && [ ! -L "$f" ] || return 1
  case "$f" in "$repo_root"/*) rel="${f#"$repo_root"/}" ;; *) return 1 ;; esac
  want="$(awk -v p="$rel" '$0 !~ /^#/ && NF == 2 && $2 == p { print $1; n++ } END { if (n != 1) exit 1 }' "$allow_file")" || return 1
  [ "$(blob_of "$f")" = "$want" ]
}
# scan <label> <regex> <dir> <temporary 0|1> <strict-for-this-check 0|1> [grep options]
scan() {
  local label="$1" re="$2" dir="$3" is_tmp="$4" is_strict="$5"; shift 5
  local f hits=() exempt=()
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ "$is_tmp" -eq 0 ] && pinned "$f"; then exempt+=("${f#"$repo_root"/}"); else hits+=("$f"); fi
  done < <(grep -rIlE "$@" -- "$re" "$dir" 2>/dev/null || true)
  [ "${#exempt[@]}" -gt 0 ] && info "pinned fixtures exempt under $dir (path and blob match): ${exempt[*]}"
  if [ "${#hits[@]}" -gt 0 ]; then
    local shown="${hits[*]:0:20}"; [ "${#hits[@]}" -gt 20 ] && shown="$shown (+$(( ${#hits[@]} - 20 )) more)"
    if [ "$is_strict" -eq 1 ]; then flag "$label under $dir: $shown"; else info "$label under $dir: $shown"; fi
  else ok "$label under $dir"; fi
}

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

# 2 and 3. Private key material and token-shaped strings on disk (paths only).
for d in "${scan_dirs[@]}"; do d="$(strip "$d")"; [ -d "$d" ] || continue
  scan "private key material" "$pem_regex" "$d" 0 1 --exclude-dir=node_modules --exclude-dir=.git
  scan "token-shaped strings" "$token_regex" "$d" 0 "$strict" --exclude-dir=node_modules
done
for d in "${tmp_dirs[@]}"; do d="$(strip "$d")"; [ -d "$d" ] || continue
  scan "private key material" "$pem_regex" "$d" 1 1 --exclude-dir=node_modules --exclude-dir=.git
  scan "token-shaped strings" "$token_regex" "$d" 1 "$strict" --exclude-dir=node_modules
done

if [ "$profile" != selftest ]; then
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
fi

echo "== result: $([ "$forbidden" -eq 0 ] && echo PASS || echo FAIL)"
exit "$forbidden"
