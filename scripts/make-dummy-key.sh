#!/usr/bin/env bash
# Creates a fresh synthetic model-key canary for this run, as the runner user,
# in a step that runs no agent code. It has the shape of a real key and can
# never be valid: `sk-ant-api03-` + `PROOFDUMMY` + random base64url characters
# + `AA`, DUMMY_KEY_LENGTH characters in total (default 108 [U]: the length of
# current Anthropic API keys as commonly observed; the approver confirms it
# against the proof key's length, computed locally without displaying the key).
# The value is written only to a root-only file and masked in the job log; the
# script prints its length, never the value.
# Usage: make-dummy-key.sh        Output: /var/lib/proofdummy/dummy (root, 0600)
set -euo pipefail

len="${DUMMY_KEY_LENGTH:-108}"
[[ "$len" =~ ^[0-9]+$ ]] && [ "$len" -ge 40 ] && [ "$len" -le 200 ] || { echo "::error::bad length"; exit 2; }
dummy="$(node -e '
  const n = Number(process.argv[1]);
  const prefix = "sk-ant-api03-PROOFDUMMY";
  const body = require("node:crypto").randomBytes(n).toString("base64url").slice(0, n - prefix.length - 2);
  process.stdout.write(prefix + body + "AA");
' "$len")"
[ "${#dummy}" -eq "$len" ] || { echo "::error::dummy length mismatch"; exit 1; }
echo "::add-mask::$dummy"
sudo install -d -o root -g root -m 0700 /var/lib/proofdummy
printf '%s' "$dummy" | sudo tee /var/lib/proofdummy/dummy >/dev/null
sudo chmod 0600 /var/lib/proofdummy/dummy
unset dummy
echo "synthetic key canary created: length $len, root-only file"
