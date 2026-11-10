#!/usr/bin/env bash
# Collects the agent's output as untrusted data, as the runner user (with sudo).
#   1. kills every agent process and checks none is left (no race on the files);
#   2. copies only regular files (never symlinks, devices or sockets), each at
#      most 1 MiB and at most 500 files, preserving relative paths whose names
#      match a strict pattern;
#   3. the copies are owned by the runner user and are never executed.
# Usage: collect-agent-output.sh <agent-out-dir> <dst-dir>
set -euo pipefail

src="$1"; dst="$2"
sudo pkill -KILL -u agent 2>/dev/null || true
sleep 1
if pgrep -u agent >/dev/null; then echo "::error::agent processes still running"; exit 1; fi

mkdir -p "$dst"
count=0
while IFS= read -r -d '' f; do
  rel="${f#"$src"/}"
  [[ "$rel" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+){0,3}$ ]] || { echo "skipped unexpected name"; continue; }
  size="$(sudo stat -c %s "$f")"
  [ "$size" -le 1048576 ] || { echo "skipped oversize file $rel"; continue; }
  count=$((count + 1))
  [ "$count" -le 500 ] || { echo "::error::too many files"; exit 1; }
  mkdir -p "$dst/$(dirname "$rel")"
  sudo cat -- "$f" > "$dst/$rel"
done < <(sudo find "$src" -mindepth 1 -type f -print0)
echo "collected $count file(s) into $dst"
