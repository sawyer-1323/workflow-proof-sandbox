#!/usr/bin/env bash
# Copies a directory into the agent's area, as the runner user (with sudo).
# Usage: stage-for-agent.sh <src> <dst> <agent|readonly> [--neutralize-symlinks]
#   agent:    the agent user owns the copy and may change it (implementation work).
#   readonly: root owns the copy; the agent may only read it (review inputs).
#   --neutralize-symlinks: replace each symlink with a text file naming its
#     target, so no read can follow it (pull request heads).
set -euo pipefail

src="$1"; dst="$2"; mode="$3"; neutralize="${4:-}"
sudo rm -rf "$dst"
sudo cp -a "$src/." "$dst/" 2>/dev/null || { sudo mkdir -p "$dst"; sudo cp -a "$src/." "$dst/"; }
if [ "$neutralize" = "--neutralize-symlinks" ]; then
  sudo find "$dst" -type l -print0 | while IFS= read -r -d '' link; do
    target="$(sudo readlink "$link")"
    sudo rm -f "$link"
    printf 'symlink -> %s\n' "$target" | sudo tee "${link}.symlink-as-data" >/dev/null
  done
fi
case "$mode" in
  agent)    sudo chown -R agent:agent "$dst"; sudo chmod -R u+rwX,go-rwx "$dst" ;;
  readonly) sudo chown -R root:root "$dst"; sudo chmod -R a+rX,go-w,u-w "$dst" ;;
  *) echo "unknown mode $mode"; exit 2 ;;
esac
echo "staged $src -> $dst ($mode)"
