#!/usr/bin/env bash
# Model proxy probe (M2 to M7). Runs AS THE AGENT USER, in probe.yml mode
# probe-requests, where the proxy runs with probe caps (MP_MAX_REQUESTS=3,
# MP_SPEND_CAP_USD small).
# PROOF_STAGE=live: at most three tiny real requests (max_tokens 1) reach the model API.
# PROOF_STAGE=dummy: the proxy is OFFLINE. Every local refusal (M2 to M5 a, b; M7) is
#   checked as in live; rows that would reach the upstream expect 503 instead.
# Env: AGENT_MODEL (an allowlisted model), MP_MAX_TOKENS (the cap), PROOF_STAGE.
set -uo pipefail

base="http://127.0.0.1:${MODEL_PROXY_PORT:-8787}"
ph="proof-placeholder-not-a-key"
model="${AGENT_MODEL:?AGENT_MODEL required}"
cap="${MP_MAX_TOKENS:?MP_MAX_TOKENS required}"
fail=0
case "${PROOF_STAGE:-}" in live) up=200; capped=429 ;; dummy) up=503; capped=503 ;; *) echo "PROOF_STAGE must be dummy or live"; exit 2 ;; esac
row() { if [ "$2" = "$3" ]; then echo "$1 PASS $4 (http $3)"; else echo "$1 FAIL $4 (expected $2, got $3)"; fail=1; fi; }
req() { # method path body [extra curl args...]
  local m="$1" p="$2" b="$3"; shift 3
  curl -sS -o /dev/null -m 60 -w '%{http_code}' -X "$m" -H 'content-type: application/json' \
    -H 'anthropic-version: 2023-06-01' "$@" "$base$p" ${b:+-d "$b"} 2>/dev/null; true
}
msg() { printf '{"model":"%s","max_tokens":%s,"messages":[{"role":"user","content":"Reply with OK."}]}' "$1" "$2"; }

# M2 paths and methods outside the allowlist.
row M2 405 "$(req GET /v1/models '' -H "x-api-key: $ph")" "GET /v1/models"
row M2 403 "$(req POST /v1/complete "$(msg "$model" 1)" -H "x-api-key: $ph")" "POST /v1/complete"
row M2 403 "$(req POST /v1/messages/batches "$(msg "$model" 1)" -H "x-api-key: $ph")" "POST /v1/messages/batches"
row M2 403 "$(req POST '/v1/messages?stream=true' "$(msg "$model" 1)" -H "x-api-key: $ph")" "unexpected query string"
row M2 403 "$(req POST /v1/files '{}' -H "x-api-key: $ph")" "POST /v1/files"

# M3 model not allowlisted.
row M3 403 "$(req POST /v1/messages "$(msg not-an-allowlisted-model 1)" -H "x-api-key: $ph")" "model not allowlisted"

# M4 max_tokens above the cap, or missing.
row M4 403 "$(req POST /v1/messages "$(msg "$model" $((cap + 1)))" -H "x-api-key: $ph")" "max_tokens = cap + 1"
row M4 403 "$(req POST /v1/messages "{\"model\":\"$model\",\"messages\":[]}" -H "x-api-key: $ph")" "max_tokens missing"

# M5 client-supplied credentials.
fake="sk-ant""-api03-notreal-notreal-notreal-notreal" # split so this file never matches a key scan
row M5 403 "$(req POST /v1/messages "$(msg "$model" 1)" -H "x-api-key: $fake")" "client x-api-key other than the placeholder"
row M5 403 "$(req POST /v1/messages "$(msg "$model" 1)" -H 'authorization: Bearer notreal')" "client Authorization header"
row M5 "$up" "$(req POST /v1/messages "$(msg "$model" 1)" -H "x-api-key: $ph")" "placeholder replaced by the injected key (1 real request)"

# M6 caps: spend estimate first (refused before any upstream call), then request count.
row M6 "$capped" "$(req POST /v1/messages "$(msg "$model" "$cap")" -H "x-api-key: $ph")" "spend estimate cap (max_tokens at cap)"
row M6 "$up" "$(req POST /v1/messages "$(msg "$model" 1)" -H "x-api-key: $ph")" "request 2 of 3"
row M6 "$up" "$(req POST /v1/messages "$(msg "$model" 1)" -H "x-api-key: $ph")" "request 3 of 3"
row M6 "$capped" "$(req POST /v1/messages "$(msg "$model" 1)" -H "x-api-key: $ph")" "request 4: count cap"

# M7 the agent cannot kill, replace, read or impersonate the proxy.
pid="$(pgrep -u modelproxy -f /opt/modelproxy/model-proxy.js | head -n1)"
kill -TERM "$pid" 2>/dev/null; r=$?; row M7 1 "$([ $r -eq 0 ] && echo 0 || echo 1)" "kill -TERM the proxy (1 = refused)"
pkill -KILL -u modelproxy 2>/dev/null; sleep 1
pgrep -u modelproxy -f /opt/modelproxy/model-proxy.js >/dev/null; r=$?; row M7 0 "$r" "proxy still running after pkill -u modelproxy (0 = running)"
( : > /opt/modelproxy/model-proxy.js ) 2>/dev/null; r=$?; row M7 1 "$([ $r -eq 0 ] && echo 0 || echo 1)" "overwrite the proxy script (1 = refused)"
cat "/proc/$pid/environ" >/dev/null 2>&1; r=$?; row M7 1 "$([ $r -eq 0 ] && echo 0 || echo 1)" "read the proxy's environ (1 = refused)"
head -c 1 "/proc/$pid/mem" >/dev/null 2>&1; r=$?; row M7 1 "$([ $r -eq 0 ] && echo 0 || echo 1)" "read the proxy's memory (1 = refused)"
cat /var/lib/modelproxy/metadata.log >/dev/null 2>&1; r=$?; row M7 1 "$([ $r -eq 0 ] && echo 0 || echo 1)" "read the proxy's log (1 = refused)"
row M7 405 "$(req GET / '')" "proxy still answering"

echo "== model proxy result: $([ "$fail" -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"
