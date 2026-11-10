#!/usr/bin/env bash
# Pin-age check, run by the approver before recording an authorization, and
# again on the run date. Read-only: GitHub API GET calls through `gh api` and one
# GET to the npm registry. Fails unless every pin is at least MIN_DAYS old on
# RUN_DATE and every action tag still resolves to the pinned commit.
# Checks: every `uses: owner/repo[/path]@<sha> # <tag>` in .github/workflows,
# the Claude Code npm version in scripts/install-tools.sh, and the actionlint and
# zizmor versions in .github/workflows/ci.yml.
# Usage: RUN_DATE=YYYY-MM-DD MIN_DAYS=14 bash scripts/check-pin-age.sh   (from the repo root)
# Needs: gh (authenticated; read-only use), curl, node, GNU date.
set -uo pipefail

run_date="${RUN_DATE:-$(date -u +%F)}"
min_days="${MIN_DAYS:-14}"
run_epoch="$(date -u -d "$run_date" +%s)"
fail=0
printf '%-48s %-10s %-12s %5s  %s\n' "PIN" "VERSION" "PUBLISHED" "DAYS" "RESULT"

report() { # name version published-iso extra-fail(0/1)
  local name="$1" ver="$2" pub="$3" extra="$4" days res
  if [ -z "$pub" ] || [ "$pub" = "null" ]; then
    printf '%-48s %-10s %-12s %5s  %s\n' "$name" "$ver" "?" "?" "FAIL (no publish date)"; fail=1; return
  fi
  days=$(( (run_epoch - $(date -u -d "$pub" +%s)) / 86400 ))
  res="OK"
  [ "$days" -ge "$min_days" ] || { res="FAIL (younger than $min_days days)"; fail=1; }
  [ "$extra" -eq 0 ] || { res="FAIL (tag does not resolve to the pinned SHA)"; fail=1; }
  printf '%-48s %-10s %-12s %5s  %s\n' "$name" "$ver" "${pub%%T*}" "$days" "$res"
}

# Actions.
while read -r _ ref _ tag; do
  action="${ref%@*}"; sha="${ref#*@}"
  repo="$(echo "$action" | cut -d/ -f1-2)"
  obj="$(gh api "repos/$repo/git/ref/tags/$tag" --jq '.object.type + " " + .object.sha' 2>/dev/null)"
  type="${obj%% *}"; osha="${obj#* }"
  [ "$type" = "tag" ] && osha="$(gh api "repos/$repo/git/tags/$osha" --jq '.object.sha' 2>/dev/null)"
  mismatch=0; [ "$osha" = "$sha" ] || mismatch=1
  pub="$(gh api "repos/$repo/releases/tags/$tag" --jq '.published_at' 2>/dev/null)"
  report "$action" "$tag" "$pub" "$mismatch"
done < <(grep -hoE 'uses: [A-Za-z0-9._/-]+@[0-9a-f]{40} # v[0-9][0-9.]*' .github/workflows/*.yml | sort -u)

# npm: Claude Code CLI.
cc="$(grep -oE 'CLAUDE_CODE_VERSION="[0-9.]+"' scripts/install-tools.sh | cut -d'"' -f2)"
pub="$(curl -fsSL https://registry.npmjs.org/@anthropic-ai/claude-code | node -e \
  'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const t=JSON.parse(s).time||{};process.stdout.write(t[process.argv[1]]||"")})' "$cc")"
report "npm @anthropic-ai/claude-code" "$cc" "$pub" 0

# Binaries used by ci.yml.
al="$(grep -oE 'ACTIONLINT_VERSION: "[0-9.]+"' .github/workflows/ci.yml | cut -d'"' -f2)"
report "rhysd/actionlint (binary)" "v$al" "$(gh api "repos/rhysd/actionlint/releases/tags/v$al" --jq .published_at 2>/dev/null)" 0
zz="$(grep -oE 'ZIZMOR_VERSION: "[0-9.]+"' .github/workflows/ci.yml | cut -d'"' -f2)"
report "zizmorcore/zizmor (binary)" "v$zz" "$(gh api "repos/zizmorcore/zizmor/releases/tags/v$zz" --jq .published_at 2>/dev/null)" 0

echo "run date $run_date, minimum $min_days days"
exit "$fail"
