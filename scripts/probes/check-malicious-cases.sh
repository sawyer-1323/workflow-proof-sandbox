#!/usr/bin/env bash
# S4 (d), publish side. Runs in a PUBLISH job (trusted code only). Validates
# every downloaded case as data and compares the outcome with the expected list.
# Never executes, sources or interpolates case content. Finally checks that no
# payload marker was created.
# Usage: check-malicious-cases.sh <cases-dir> <pr-number> <head-sha> <base-sha>
set -uo pipefail

cases="$1"; pr="$2"; head="$3"; base="$4"
here="$(cd "$(dirname "$0")" && pwd)"
validator="$here/../validate-artifact.js"
fail=0

while read -r name kind want; do
  [[ "$name" =~ ^[a-z0-9-]+$ ]] || { echo "FAIL  bad case name in expected list"; fail=1; continue; }
  dir="$cases/$name"
  if [ ! -d "$dir" ] || [ -L "$dir" ]; then echo "FAIL  $name: case missing"; fail=1; continue; fi
  if [ "$kind" = review ]; then
    out="$(node "$validator" review "$dir" --pr "$pr" --head "$head" 2>&1)"
  else
    out="$(node "$validator" patch "$dir" --task 1 --base "$base" --branch agent/s4d --expected-head new 2>&1)"
  fi
  got="$(printf '%s' "$out" | head -n1 | cut -d' ' -f1)"
  if [ "$got" = "$want" ]; then echo "PASS  $name: $got"; else echo "FAIL  $name: expected $want, got $got"; fail=1; fi
done < "$here/malicious-cases.expected"

extra="$(comm -13 <(cut -d' ' -f1 "$here/malicious-cases.expected" | sort) <(ls -1 "$cases" | sort))"
[ -z "$extra" ] || { echo "NOTE  unexpected case directories ignored: $(echo "$extra" | tr '\n' ' ')"; }

if ls /tmp/proof-pwned-* >/dev/null 2>&1; then echo "FAIL  a payload marker exists in /tmp"; fail=1; else echo "PASS  no payload marker created"; fi
echo "== result: $([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
