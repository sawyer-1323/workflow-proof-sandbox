#!/usr/bin/env node
'use strict';

// Persistent cross-run spend budget (round 6). Runs in base-branch workflow
// code, in an AGENT job, BEFORE the model proxy starts and before any agent
// code exists. It replaces the per-workflow run_number window, which restarts
// when a workflow file is renamed or added.
//
// The counter is the number of GitHub deployment records of this job's agent
// environment created inside the authorized window. GitHub creates a deployment
// when a job that names an environment starts [U: confirmed per attempt by the
// dummy stage, test B5]. The count therefore does not depend on the workflow
// file, its name, its edits, or run numbers.
//
// Refuses (exit 1) unless ALL of these hold:
//   1. inputs are well formed;
//   2. now is inside [WINDOW_START, WINDOW_END];
//   3. GITHUB_RUN_ATTEMPT <= MAX_ATTEMPTS;
//   4. this run's own deployment is found among the newest deployments of the
//      environment (proves the count includes this job; otherwise the
//      assumption above is false and the step fails closed);
//   5. the number of deployments of the environment created at or after
//      WINDOW_START, counting EVERY creator, ref and status, is <= RUN_MAX.
// Nothing is filtered out of the count, so no filter can be gamed: extra
// deployments (for example a pull request job refused by the environment's
// branch policy) only use up budget, which fails safe. The breakdown is
// printed so the approver sees any deployment not made by a main-branch run.
//
// Residual (documented in ROUND-6.md): deployments can be DELETED by a token
// with deployments write once they are inactive. No proof workflow requests
// that permission; a pull request workflow could. The per-run proxy cap and
// the workspace hard limit still bound spend.
//
// Env: GITHUB_API_URL, GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT
//      (runner); GH_TOKEN (the job's GITHUB_TOKEN, deployments: read);
//      BUDGET_ENVIRONMENT (literal in the workflow, the job's environment);
//      WINDOW_START, WINDOW_END (UTC, YYYY-MM-DDTHH:MM:SSZ), RUN_MAX,
//      MAX_ATTEMPTS (environment variables set at authorization).
// Prints counts, deployment IDs and fixed reasons only; never the token.

const SELF_SEARCH = 10;   // newest deployments searched for this run's own record
const MAX_PAGES = 10;     // 1000 deployments; more inside one window fails closed

const fail = (msg) => { console.log(`::error::run budget: ${msg}; the model proxy will not start`); process.exit(1); };
const env = (n) => { const v = process.env[n]; if (v === undefined || v === '') fail(`${n} is not set`); return v; };

async function main() {
  const api = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
  const repo = env('GITHUB_REPOSITORY');
  const runId = env('GITHUB_RUN_ID');
  const attempt = env('GITHUB_RUN_ATTEMPT');
  const token = env('GH_TOKEN');
  const environment = env('BUDGET_ENVIRONMENT');
  const startText = env('WINDOW_START');
  const endText = env('WINDOW_END');
  const max = env('RUN_MAX');
  const maxAttempts = env('MAX_ATTEMPTS');

  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) fail('bad repository');
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(environment)) fail('bad environment name');
  for (const [n, v] of [['GITHUB_RUN_ID', runId], ['GITHUB_RUN_ATTEMPT', attempt], ['RUN_MAX', max], ['MAX_ATTEMPTS', maxAttempts]]) {
    if (!/^[0-9]{1,15}$/.test(v)) fail(`${n} must be an integer`);
  }
  const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
  if (!ISO.test(startText) || !ISO.test(endText)) fail('WINDOW_START and WINDOW_END must be YYYY-MM-DDTHH:MM:SSZ');
  const start = Date.parse(startText);
  const end = Date.parse(endText);
  const now = Date.now();
  if (!(start < end)) fail('window start is not before its end');
  if (now < start || now > end) fail(`now is outside the authorized window ${startText}..${endText}`);
  if (Number(attempt) > Number(maxAttempts)) fail(`run_attempt ${attempt} exceeds MAX_ATTEMPTS ${maxAttempts}`);

  const get = async (path) => {
    const r = await fetch(`${api}${path}`, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' },
    });
    if (r.status !== 200) fail(`GitHub API ${path.split('?')[0].replace(/\/\d+(?=\/|$)/g, '/<id>')} returned ${r.status}`);
    const body = await r.json();
    if (!Array.isArray(body)) fail('GitHub API returned a non-list');
    return body;
  };

  // Deployments come newest first. Read until one is older than the window.
  const inWindow = [];
  const newest = [];
  let done = false;
  for (let page = 1; page <= MAX_PAGES && !done; page++) {
    const list = await get(`/repos/${repo}/deployments?environment=${encodeURIComponent(environment)}&per_page=100&page=${page}`);
    for (const d of list) {
      const created = Date.parse(d && d.created_at);
      if (!Number.isFinite(created) || !Number.isInteger(d.id)) fail('malformed deployment record');
      if (newest.length < SELF_SEARCH) newest.push(d);
      if (created < start) { done = true; break; }
      inWindow.push(d);
    }
    if (list.length < 100) done = true;
    if (!done && page === MAX_PAGES) fail('more deployments than the reader allows; fail closed');
  }

  // This run's own deployment: a status whose URL names this run.
  const marker = `/actions/runs/${runId}/`;
  let self = null;
  for (const d of newest) {
    const statuses = await get(`/repos/${repo}/deployments/${d.id}/statuses?per_page=100`);
    if (statuses.some((s) => [s && s.target_url, s && s.log_url].some((u) => typeof u === 'string' && u.includes(marker)))) { self = d; break; }
  }
  if (!self) fail(`this run's own deployment was not found in the newest ${SELF_SEARCH} of ${environment}`);
  if (!inWindow.some((d) => d.id === self.id)) fail('own deployment is outside the window');

  const isMainActions = (d) => d.creator && d.creator.login === 'github-actions[bot]' && ['main', 'refs/heads/main'].includes(d.ref);
  const mainRuns = inWindow.filter(isMainActions).length;
  const other = inWindow.length - mainRuns;
  console.log(`run budget: environment ${environment}, window ${startText}..${endText}`);
  console.log(`  deployments counted: ${inWindow.length} (main-branch Actions runs ${mainRuns}, other ${other}); limit ${max}`);
  console.log(`  own deployment: ${self.id}; attempt ${attempt} of at most ${maxAttempts}`);
  console.log(`  counted IDs: ${inWindow.map((d) => d.id).join(',')}`);
  if (other > 0) console.log(`::warning::run budget: ${other} deployment(s) in ${environment} not created by a main-branch Actions run; the approver reviews them`);
  if (inWindow.length > Number(max)) fail(`${inWindow.length} deployments in the window exceed RUN_MAX ${max}`);
  console.log('run budget OK');
}

main().catch(() => fail('unexpected error'));
