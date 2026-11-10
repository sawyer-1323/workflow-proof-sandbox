#!/usr/bin/env bash
# Golden-test protection (T6). Runs from the BASE checkout only, in review.yml.
# Usage: golden-guard.sh <base-dir> <pr-head-dir>
# Reads the pull request head as data: it never executes or sources PR files.
# Fails if the pull request changes a protected baseline or its recorded hash.
set -euo pipefail

base="$1"
pr="$2"
list="test/golden/PROTECTED.sha256"
status=0

# 1. The base must be self-consistent; otherwise the guard itself is broken.
(cd "$base" && sha256sum --strict --quiet -c "$list") || {
  echo "::error::base baseline does not match its own recorded hashes"
  exit 2
}

# 2. The recorded hash file must be byte-identical to the base.
if ! cmp -s "$base/$list" "$pr/$list"; then
  echo "::error file=$list::recorded hash file changed or missing in the pull request"
  status=1
fi

# 3. Every protected file must be a regular file (not a symlink) with the base hash.
while read -r expected_hash rel; do
  rel="${rel#\*}"
  target="$pr/$rel"
  if [ -L "$target" ] || [ ! -f "$target" ]; then
    echo "::error file=$rel::protected file is missing or not a regular file"
    status=1
    continue
  fi
  actual_hash="$(sha256sum "$target" | cut -d' ' -f1)"
  if [ "$actual_hash" != "$expected_hash" ]; then
    echo "::error file=$rel::protected file changed (golden file, expected value or specification)"
    status=1
  fi
done < "$base/$list"

if [ "$status" -eq 0 ]; then
  echo "golden-guard: protected baselines unchanged"
else
  echo "golden-guard: an update needs the owner's approval of the new content and hash"
fi
exit "$status"
