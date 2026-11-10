#!/usr/bin/env bash
# S5, publish side. Runs in a PUBLISH job (trusted code only). Validates every
# stub case as data, with the forbidden-value list, and compares the outcome
# with s5-cases.expected. Prints case names and VALID or REJECT only, never
# content. The forbidden-value file is deleted at the end.
# Usage: check-s5-cases.sh <cases-dir> <pr-number> <head-sha> <base-sha>
# Env:   S5_CANARY (non-secret test value)
set -uo pipefail

cases="$1"; pr="$2"; head="$3"; base="$4"
here="$(cd "$(dirname "$0")" && pwd)"
validator="$here/../validate-artifact.js"
forbid="$(mktemp)"
printf '%s\n%s\n' "${S5_CANARY:?S5_CANARY required}" "proof-placeholder-not-a-key" > "$forbid"
fail=0
while read -r name kind want; do
  [[ "$name" =~ ^[a-z0-9-]+$ ]] || { echo "FAIL  bad case name"; fail=1; continue; }
  dir="$cases/$name"
  [ -d "$dir" ] && [ ! -L "$dir" ] || { echo "FAIL  $name: missing"; fail=1; continue; }
  if [ "$kind" = review ]; then
    out="$(node "$validator" review "$dir" --pr "$pr" --head "$head" --forbid-file "$forbid")"
  else
    out="$(node "$validator" patch "$dir" --task 1 --base "$base" --branch agent/s5 --expected-head new --forbid-file "$forbid")"
  fi
  got="${out%% *}"
  if [ "$got" = "$want" ]; then echo "PASS  $name: $got"; else echo "FAIL  $name: expected $want, got $got"; fail=1; fi
done < "$here/s5-cases.expected"
rm -f "$forbid"
echo "== S5 validator result: $([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
