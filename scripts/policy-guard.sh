#!/usr/bin/env bash
# Protected-path guard (round 6, C-B6 merge block). Runs from the BASE checkout
# only, in review.yml (pull_request_target). Reads the pull request head as
# data: it never executes or sources PR files.
#
# It answers one question: does the pull request change any protected policy
# path? Workflows, scripts, agent instruction files, tool settings. Golden
# baselines are golden-guard's (T6).
#
# Exit 0: no protected path changed.
# Exit 3: a protected path changed. The workflow then passes the check only if
#         every commit in the pull request is a verified commit by the approver
#         (see review.yml). Cursor's commits, and any unsigned or other-author
#         commit, therefore keep the check failing, and the ruleset blocks the
#         merge.
# Exit 2: usage or internal error (fails the check).
# Usage: policy-guard.sh <base-dir> <pr-head-dir>
set -euo pipefail

base="${1:?base dir}"
pr="${2:?pr dir}"
[ -d "$base" ] && [ -d "$pr" ] || { echo "::error::policy-guard: missing checkout"; exit 2; }

# Directories and files under policy control (relative to the repository root).
protected=(
  .github .cursor .claude .husky scripts toolchain docs/guides
  AGENTS.md CLAUDE.md CLAUDE.local.md .mcp.json .claude.json .gitattributes .gitmodules
  .ripgreprc package.json package-lock.json
)

changed=0
for p in "${protected[@]}"; do
  b="$base/$p"; h="$pr/$p"
  if [ ! -e "$b" ] && [ ! -L "$b" ] && [ ! -e "$h" ] && [ ! -L "$h" ]; then continue; fi
  if [ -e "$b" ] || [ -L "$b" ]; then :; else echo "changed: $p (added)"; changed=1; continue; fi
  if [ -e "$h" ] || [ -L "$h" ]; then :; else echo "changed: $p (removed)"; changed=1; continue; fi
  # --no-dereference compares symlinks as links, never following them.
  if ! diff -rq --no-dereference "$b" "$h" >/dev/null 2>&1; then
    echo "changed: $p"
    changed=1
  fi
done

if [ "$changed" -eq 0 ]; then
  echo "policy-guard: no protected path changed"
  exit 0
fi
echo "policy-guard: protected paths changed; only verified commits by the approver may change them"
exit 3
