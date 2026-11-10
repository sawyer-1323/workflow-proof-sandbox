#!/usr/bin/env bash
# Starts the model proxy as uid `modelproxy`, as the runner user, BEFORE any
# agent process runs. This is the only step that receives the model key
# (env MP_UPSTREAM_KEY). The key goes to the proxy through the environment
# (sudo --preserve-env), never through a command line (readable by every user)
# and never through a file.
# The key is either MP_UPSTREAM_KEY (the real proof key, for the M2 to M7
# request-path run) or, for the M1/S4b isolation run, the synthetic dummy in the
# root-only file /var/lib/proofdummy/dummy (set MP_USE_DUMMY=1). The dummy takes
# the real key's exact path, so the isolation test exercises the real path with
# nothing at stake.
# Env (required): one of MP_UPSTREAM_KEY (with PROOF_STAGE=live) or MP_USE_DUMMY=1
#   (always offline); MP_MODELS,
#   MP_MAX_TOKENS, MP_MAX_REQUESTS, MP_SPEND_CAP_USD, MP_INPUT_USD_PER_MTOK,
#   MP_OUTPUT_USD_PER_MTOK
# Env (optional): MODEL_PROXY_PORT (default 8787)
set -euo pipefail

# Stage gate (second layer; the workflow step conditions are the first).
#  - the dummy key always runs OFFLINE: no request leaves the runner;
#  - the real key is accepted only when PROOF_STAGE=live is passed to this step.
if [ "${MP_USE_DUMMY:-0}" = "1" ]; then
  [ -z "${MP_UPSTREAM_KEY:-}" ] || { echo "::error::dummy mode with a real key present"; exit 1; }
  MP_UPSTREAM_KEY="$(sudo cat /var/lib/proofdummy/dummy)"
  export MP_UPSTREAM_KEY
  echo "::add-mask::$MP_UPSTREAM_KEY"
  export MP_OFFLINE=1
else
  [ "${PROOF_STAGE:-}" = "live" ] || { echo "::error::a real model key needs PROOF_STAGE=live"; exit 1; }
  export MP_OFFLINE=0
fi
: "${MP_UPSTREAM_KEY:?model key missing}"
export MP_PORT="${MODEL_PROXY_PORT:-8787}"
export MP_PLACEHOLDER="proof-placeholder-not-a-key"
export MP_LOG=/var/lib/modelproxy/metadata.log
MP_UPSTREAM_IPS="$(paste -sd, /opt/modelproxy/anthropic-ips)"
export MP_UPSTREAM_IPS
node_bin="$(command -v node)"
case "$node_bin" in "$HOME"/*) echo "::error::node is under the runner's home"; exit 1 ;; esac

# Root-only canary for the root-side scan step (scan-dump.js):
#  - the synthetic dummy (MP_USE_DUMMY=1, the M1 isolation run) is written in
#    plaintext, so all three detection checks run;
#  - the real proof key is NEVER written to disk. Only "sha256:<hex>" of it is
#    written, so the scan runs the hash check alone.
sudo install -d -o root -g root -m 0700 /var/lib/proofdummy
if [ "${MP_USE_DUMMY:-0}" = "1" ]; then
  printf '%s' "$MP_UPSTREAM_KEY" | sudo tee /var/lib/proofdummy/canary >/dev/null
else
  printf 'sha256:%s' "$(printf '%s' "$MP_UPSTREAM_KEY" | sha256sum | cut -c1-64)" | sudo tee /var/lib/proofdummy/canary >/dev/null
fi
sudo chmod 0600 /var/lib/proofdummy/canary

keep="MP_UPSTREAM_KEY,MP_PORT,MP_PLACEHOLDER,MP_MODELS,MP_MAX_TOKENS,MP_MAX_REQUESTS"
keep="$keep,MP_SPEND_CAP_USD,MP_INPUT_USD_PER_MTOK,MP_OUTPUT_USD_PER_MTOK,MP_UPSTREAM_IPS,MP_LOG"
keep="$keep,MP_MAX_INPUT_TOKENS,MP_CACHE_WRITE_MULT,MP_OFFLINE"
sudo -u modelproxy --preserve-env="$keep" -- /bin/sh -c \
  'cd /var/lib/modelproxy && exec "$0" /opt/modelproxy/model-proxy.js </dev/null >/dev/null 2>&1' \
  "$node_bin" &
unset MP_UPSTREAM_KEY

for _ in $(seq 1 40); do
  (exec 3<>"/dev/tcp/127.0.0.1/$MP_PORT") 2>/dev/null && break
  sleep 0.25
done
pid="$(pgrep -u modelproxy -f /opt/modelproxy/model-proxy.js | head -n1 || true)"
[ -n "$pid" ] || { echo "::error::model proxy did not start"; exit 1; }
echo "model proxy: pid $pid, uid modelproxy, 127.0.0.1:$MP_PORT"
