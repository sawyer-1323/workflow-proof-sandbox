#!/usr/bin/env bash
# Token probe (T2, P4, D1 to D11) with the review App installation token (round 6, Path A;
# phase R: read-only).
# Usage: token-probe.sh <pr-number>
# Env:   GH_TOKEN          implementation installation token (never printed)
#        GITHUB_REPOSITORY owner/name of this repository
#        INSTALLATION_ID   from the token-minting step
#        PROBE_OTHER_REPO  owner/name of a second synthetic PRIVATE repository that the
#                          App is NOT installed on (a public one would answer reads)
# Every prohibited action must be denied. Responses are recorded as
# "<id> <label> <http-code> <message>" with no credential in them.
#        PROBE_PHASE       R (default: read-only token) or W (write token)
# Runs only in a PUBLISH job (trusted code, no agent code). In phase R every
# write is denied by the token's permissions; in phase W the same rows test the
# rulesets. WARNING (phase W): D1 and D8 attempt real writes to main. Run only
# after the rulesets are configured, and stop at any UNEXPECTED line.
set -uo pipefail

api="${GITHUB_API_URL:-https://api.github.com}"
repo="$GITHUB_REPOSITORY"
phase="${PROBE_PHASE:-R}"
pr="${1:?pull request number required}"
out="${RUNNER_TEMP:-/tmp}/token-probe.tsv"
: > "$out"
unexpected=0
auth_header="$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w0)"
echo "::add-mask::$auth_header"

record() { # id label code message verdict
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" | tee -a "$out"
  [ "$5" = "UNEXPECTED" ] && unexpected=1
  return 0
}

# call <id> <label> <method> <path> [json] ; 2xx is UNEXPECTED unless <id> ends in "+"
call() {
  local id="$1" label="$2" method="$3" path="$4" data="${5:-}" body code msg verdict
  body="$(mktemp)"
  if [ -n "$data" ]; then
    code="$(curl -sS -o "$body" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' "$api$path" -d "$data")"
  else
    code="$(curl -sS -o "$body" -w '%{http_code}' -X "$method" \
      -H "Authorization: Bearer $GH_TOKEN" -H 'Accept: application/vnd.github+json' \
      -H 'X-GitHub-Api-Version: 2022-11-28' "$api$path")"
  fi
  msg="$(jq -r '(.message // "") + ((.errors // []) | map(" " + (.message // tostring)) | join(""))' "$body" 2>/dev/null | tr '\t\n' '  ' | head -c 240)"
  case "$id" in
    *+) [[ "$code" =~ ^2 ]] && verdict="EXPECTED-ALLOWED" || verdict="UNEXPECTED" ;;
    *)  [[ "$code" =~ ^2 ]] && verdict="UNEXPECTED" || verdict="DENIED" ;;
  esac
  record "${id%+}" "$label" "$code" "$msg" "$verdict"
  rm -f "$body"
}

# gitpush <id> <label> <refspec...> ; success is UNEXPECTED unless <id> ends in "+"
gitpush() {
  local id="$1" label="$2"; shift 2
  local log rc verdict
  log="$(mktemp)"
  git -c core.hooksPath=/dev/null -c "http.https://github.com/.extraheader=AUTHORIZATION: basic $auth_header" \
    push "https://github.com/${PUSH_REPO:-$repo}.git" "$@" >"$log" 2>&1
  rc=$?
  case "$id" in
    *+) [ "$rc" -eq 0 ] && verdict="EXPECTED-ALLOWED" || verdict="UNEXPECTED" ;;
    *)  [ "$rc" -eq 0 ] && verdict="UNEXPECTED" || verdict="DENIED" ;;
  esac
  record "${id%+}" "$label" "git-exit-$rc" "$(grep -E 'remote:|error:|rejected' "$log" | tr '\t\n' '  ' | head -c 240)" "$verdict"
  rm -f "$log"
}

git config user.name "token-probe"
git config user.email "token-probe@users.noreply.github.com"
git fetch -q origin main
main_sha="$(git rev-parse origin/main)"
pr_json="$(curl -sS -H "Authorization: Bearer $GH_TOKEN" "$api/repos/$repo/pulls/$pr")"
pr_head="$(jq -r '.head.sha' <<<"$pr_json")"
pr_node="$(jq -r '.node_id' <<<"$pr_json")"
run="${GITHUB_RUN_ID:-local}"

# --- T2 positive (phase W only): the implementation identity CAN push an agent
# branch and open a PR. In phase R the token is read-only, so this is skipped.
git switch -q --detach "$main_sha"
git commit -q --allow-empty -m "token probe $run"
if [ "$phase" = "W" ]; then
  gitpush "T2+" "push agent branch" "HEAD:refs/heads/agent/probe-t2-$run"
  call "T2+" "open draft pull request" POST "/repos/$repo/pulls" \
    "{\"title\":\"token probe T2 $run\",\"head\":\"agent/probe-t2-$run\",\"base\":\"main\",\"draft\":true,\"body\":\"Synthetic probe.\"}"
else
  record "T2" "push branch and open PR" "skipped" "phase R: read-only token" "SKIPPED"
fi

# --- D1: push to main.
gitpush "D1" "push to main" "HEAD:refs/heads/main"

# --- D2: merge a pull request through the API.
call "D2" "merge pull request" PUT "/repos/$repo/pulls/$pr/merge" '{"merge_method":"squash"}'

# --- D3: enable auto-merge (GraphQL returns 200 with errors, so inspect errors).
body="$(curl -sS -X POST -H "Authorization: Bearer $GH_TOKEN" "$api/graphql" \
  -d "{\"query\":\"mutation{enablePullRequestAutoMerge(input:{pullRequestId:\\\"$pr_node\\\",mergeMethod:SQUASH}){clientMutationId}}\"}")"
if jq -e '.errors | length > 0' >/dev/null 2>&1 <<<"$body"; then
  record "D3" "enable auto-merge" "graphql" "$(jq -r '[.errors[].message] | join("; ")' <<<"$body" | head -c 240)" "DENIED"
else
  record "D3" "enable auto-merge" "graphql" "no error returned" "UNEXPECTED"
fi

# --- D4: push a workflow file (no Workflows permission).
git switch -q --detach "$main_sha"
mkdir -p .github/workflows
printf 'name: probe\non: workflow_dispatch\npermissions: {}\njobs:\n  probe:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: echo probe\n' > .github/workflows/probe-d4.yml
git add .github/workflows/probe-d4.yml
git commit -q -m "token probe D4 $run"
gitpush "D4" "push workflow file" "HEAD:refs/heads/agent/probe-d4-$run"
git switch -q --detach "$main_sha"

# --- D5: dispatch a workflow (no Actions permission).
call "D5" "dispatch ci.yml" POST "/repos/$repo/actions/workflows/ci.yml/dispatches" '{"ref":"main"}'

# --- D6: rulesets, environments, secrets, variables, deploy keys, webhooks, installation.
call "D6" "create ruleset" POST "/repos/$repo/rulesets" '{"name":"probe","target":"branch","enforcement":"disabled","rules":[]}'
call "D6" "create environment" PUT "/repos/$repo/environments/probe-env" '{}'
call "D6" "read secrets public key" GET "/repos/$repo/actions/secrets/public-key"
call "D6" "create repository secret" PUT "/repos/$repo/actions/secrets/PROBE_SECRET" '{"encrypted_value":"AAAA","key_id":"0"}'
call "D6" "create environment secret" PUT "/repos/$repo/environments/probe/secrets/PROBE_SECRET" '{"encrypted_value":"AAAA","key_id":"0"}'
call "D6" "create variable" POST "/repos/$repo/actions/variables" '{"name":"PROBE_VAR","value":"x"}'
call "D6" "create deploy key" POST "/repos/$repo/keys" '{"title":"probe","key":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG9wcm9iZXByb2JlcHJvYmVwcm9iZXByb2JlcHJvYmVw","read_only":true}'
call "D6" "create webhook" POST "/repos/$repo/hooks" '{"config":{"url":"https://example.invalid/hook","content_type":"json"},"events":["push"],"active":false}'
repo_id="$(curl -sS -H "Authorization: Bearer $GH_TOKEN" "$api/repos/$repo" | jq -r '.id')"
call "D6" "add repository to installation" PUT "/user/installations/${INSTALLATION_ID:-0}/repositories/$repo_id"
call "T2" "change repository settings" PATCH "/repos/$repo" '{"allow_auto_merge":true}'
call "INFO+" "list installation repositories (scope evidence)" GET "/installation/repositories"

# --- D7: create a v* tag (tag ruleset), by git, by API, and through a release.
gitpush "D7" "push tag v0.0.0-probe-git" "$main_sha:refs/tags/v0.0.0-probe-git-$run"
call "D7" "create tag ref by API" POST "/repos/$repo/git/refs" "{\"ref\":\"refs/tags/v0.0.0-probe-api-$run\",\"sha\":\"$main_sha\"}"
call "D7" "create release with new tag" POST "/repos/$repo/releases" "{\"tag_name\":\"v0.0.0-probe-rel-$run\",\"target_commitish\":\"main\",\"draft\":false}"

# --- D8: force-push or delete main.
parent="$(git rev-parse "$main_sha^" 2>/dev/null || true)"
if [ -n "$parent" ]; then gitpush "D8" "force-push main to its parent" "+$parent:refs/heads/main"; else record "D8" "force-push main" "skipped" "main has one commit; add a second commit first" "UNEXPECTED"; fi
gitpush "D8" "delete main by git" ":refs/heads/main"
call "D8" "force-update main by API" PATCH "/repos/$repo/git/refs/heads/main" "{\"sha\":\"${parent:-$main_sha}\",\"force\":true}"
call "D8" "delete main by API" DELETE "/repos/$repo/git/refs/heads/main"

# --- D9: an App approval counts toward nothing. Record the state before and after.
before="$(curl -sS -H "Authorization: Bearer $GH_TOKEN" "$api/repos/$repo/pulls/$pr" | jq -r '.mergeable_state')"
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Authorization: Bearer $GH_TOKEN" \
  "$api/repos/$repo/pulls/$pr/reviews" -d '{"event":"APPROVE","body":"token probe D9"}')"
sleep 5
after="$(curl -sS -H "Authorization: Bearer $GH_TOKEN" "$api/repos/$repo/pulls/$pr" | jq -r '.mergeable_state')"
record "D9" "App approval (inspect: must not change mergeability)" "$code" "mergeable_state before=$before after=$after" "INSPECT"

# --- D10: post a check run or commit status under a required check's name.
call "D10" "check run named golden-guard" POST "/repos/$repo/check-runs" \
  "{\"name\":\"golden-guard\",\"head_sha\":\"$pr_head\",\"status\":\"completed\",\"conclusion\":\"success\"}"
call "D10" "commit status named golden-guard" POST "/repos/$repo/statuses/$pr_head" '{"state":"success","context":"golden-guard"}'

# --- D11: reach another repository.
if [ -n "${PROBE_OTHER_REPO:-}" ]; then
  call "D11" "read other repository" GET "/repos/$PROBE_OTHER_REPO/contents/"
  call "D11" "write issue in other repository" POST "/repos/$PROBE_OTHER_REPO/issues" '{"title":"token probe D11"}'
  PUSH_REPO="$PROBE_OTHER_REPO" gitpush "D11" "push to other repository" "HEAD:refs/heads/probe-d11-$run"
else
  record "D11" "reach another repository" "skipped" "PROBE_OTHER_REPO not set" "UNEXPECTED"
fi

echo "== results in $out"
echo "== result: $([ "$unexpected" -eq 0 ] && echo 'PASS (check INSPECT rows by hand)' || echo FAIL)"
exit "$unexpected"
