#!/usr/bin/env node
'use strict';

// D-1 run audit (round 7). Read-only. Run by the approver after every proof
// session and every Cursor session (and, in bootstrap, on a schedule). It keeps
// a LOCAL state file on the approver's machine, so a record deleted on GitHub
// is still known to have existed: GitHub logs, runs and deployments can all be
// deleted by a token with Actions or Deployments write, but this file cannot.
//
// Findings (one line each; exit 1 if any):
//   DELETED-DEPLOYMENT env=<e> id=<id> run=<run> created=<t>
//       seen by an earlier audit, absent now: deleted.
//   MISSING-DEPLOYMENT workflow=<path> run=<id> job=<name> env=<e>
//       an agent job of a main-branch run started, and no deployment of its
//       environment names that run: deleted before any audit saw it, or
//       never created (an environment opt-out such as `deployment: false`).
//   FOREIGN-DEPLOYMENT env=<e> id=<id> ref=<ref> creator=<login>
//       a deployment not made by a main-branch Actions run.
//   DELETED-RUN workflow=<path> run=<id> number=<n>
//       seen by an earlier audit, absent now.
//   RUN-GAP workflow=<path> number=<n>
//       a run_number missing between two runs of the same workflow in the
//       window (run numbers never repeat, so a gap is a deleted run).
//   UNEXPECTED-WORKFLOW run=<id> path=<path> event=<e> branch=<b>
//       a run on a non-main branch from a workflow file that is not on main,
//       or whose file at the run's head differs from main's current file.
//       Runs on main and pull_request_target runs use main's file by
//       definition and are not compared.
//   NON-APPROVER-TRIGGER run=<id> path=<path> event=<e> attempt=<a> by=<login>
//       a workflow_dispatch, or a re-run (attempt > 1), not started by the
//       approver.
// Prints IDs, paths, refs and logins only.
//
// Usage: GH_TOKEN="$(gh auth token)" node scripts/audit/run-audit.js \
//          --repo owner/name --since YYYY-MM-DDTHH:MM:SSZ --approver <login> \
//          --state <local file, outside any repository>

const fs = require('node:fs');
const { get, list, runIdOf, totalCount } = require('./gh.js');
// Known limits (ROUND-7 D-1 review):
//   - a deletion made before the FIRST audit is visible only as MISSING-DEPLOYMENT
//     or RUN-GAP, so run the first audit before the first proof run;
//   - deleting the newest run (with its deployment) shows as RUN-GAP only once a
//     later run of that workflow exists;
//   - UNEXPECTED-WORKFLOW compares with main's CURRENT file, so a branch cut
//     before a main workflow change is reported (a false positive, fail-safe);
//   - deployments are assumed to be created by `github-actions[bot]` [U until
//     DS-5]; if not, every one is reported FOREIGN (noisy, fail-safe).

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : d; };
const repo = arg('repo');
const since = arg('since');
const approver = arg('approver');
const stateFile = arg('state');
// Agent jobs and the environment each one names (this repository's layout).
const AGENT_JOBS = { '.github/workflows/review.yml': { 'review-agent': 'review-agent' }, '.github/workflows/probe.yml': { 'probe-agent': 'probe-agent' } };
const ENVS = ['review-agent', 'probe-agent', 'review', 'probe'];

async function main() {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '') || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(since || '')
    || !/^[A-Za-z0-9-]{1,39}$/.test(approver || '') || !stateFile) {
    console.error('usage: --repo owner/name --since YYYY-MM-DDTHH:MM:SSZ --approver login --state file'); process.exit(2);
  }
  const t0 = Date.parse(since);
  let state = { deployments: {}, runs: {} };
  if (fs.existsSync(stateFile)) state = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
  const findings = [];
  const f = (s) => findings.push(s);

  // main's workflow files and their blob SHAs.
  const mainFiles = new Map(((await get(`/repos/${repo}/contents/.github/workflows?ref=main`)) || [])
    .map((x) => [`.github/workflows/${x.name}`, x.sha]));

  // Runs in the window. The filtered listing stops at 1,000 results, so a
  // larger window fails closed instead of auditing a partial set.
  const runsPath = `/repos/${repo}/actions/runs?created=${encodeURIComponent('>=' + since)}`;
  const total = await totalCount(runsPath);
  if (total > 1000) throw new Error(`${total} runs in the window exceed the 1,000 the API returns; use a later --since`);
  const runs = await list(runsPath, 'workflow_runs');
  if (runs.length !== total) throw new Error(`listed ${runs.length} of ${total} runs; rerun the audit`);
  const runIds = new Set(runs.map((r) => r.id));
  const byWorkflow = new Map();
  for (const r of runs) {
    if (!byWorkflow.has(r.path)) byWorkflow.set(r.path, []);
    byWorkflow.get(r.path).push(r.run_number);
    const by = (r.triggering_actor && r.triggering_actor.login) || '?';
    if ((r.event === 'workflow_dispatch' || r.run_attempt > 1) && by !== approver) {
      f(`NON-APPROVER-TRIGGER run=${r.id} path=${r.path} event=${r.event} attempt=${r.run_attempt} by=${by}`);
    }
    // Runs on main, and pull_request_target runs, use main's file by definition.
    if (r.event !== 'pull_request_target' && r.head_branch !== 'main') {
      const mainSha = mainFiles.get(r.path);
      let differs = !mainSha;
      if (mainSha) {
        const atHead = await get(`/repos/${repo}/contents/${r.path}?ref=${r.head_sha}`);
        differs = !atHead || atHead.sha !== mainSha;
      }
      if (differs) f(`UNEXPECTED-WORKFLOW run=${r.id} path=${r.path} event=${r.event} branch=${r.head_branch}`);
    }
  }
  for (const [path, nums] of byWorkflow) {
    const s = [...new Set(nums)].sort((a, b) => a - b);
    for (let n = s[0] + 1; n < s[s.length - 1]; n++) if (!s.includes(n)) f(`RUN-GAP workflow=${path} number=${n}`);
  }
  for (const [id, r] of Object.entries(state.runs)) {
    if (Date.parse(r.created) >= t0 && !runIds.has(Number(id))) f(`DELETED-RUN workflow=${r.path} run=${id} number=${r.number}`);
  }

  // Deployments in the window.
  const deps = [];
  for (const e of ENVS) {
    const all = (await list(`/repos/${repo}/deployments?environment=${encodeURIComponent(e)}`)).filter((d) => Date.parse(d.created_at) >= t0);
    for (const d of all) {
      const st = await list(`/repos/${repo}/deployments/${d.id}/statuses`);
      const run = st.map((s) => runIdOf(s.log_url) || runIdOf(s.target_url)).find(Boolean) || null;
      deps.push({ id: d.id, env: e, ref: d.ref, creator: d.creator && d.creator.login, created: d.created_at, run });
      const mainActions = d.creator && d.creator.login === 'github-actions[bot]' && ['main', 'refs/heads/main'].includes(d.ref);
      if (!mainActions) f(`FOREIGN-DEPLOYMENT env=${e} id=${d.id} ref=${d.ref} creator=${(d.creator && d.creator.login) || '?'}`);
    }
  }
  const depIds = new Set(deps.map((d) => String(d.id)));
  for (const [id, d] of Object.entries(state.deployments)) {
    if (Date.parse(d.created) >= t0 && !depIds.has(id)) f(`DELETED-DEPLOYMENT env=${d.env} id=${id} run=${d.run || '?'} created=${d.created}`);
  }

  // Every started agent job of a main-branch run must have its deployment.
  for (const r of runs) {
    const jobsFor = AGENT_JOBS[r.path];
    const mainBranchRun = r.head_branch === 'main' || r.event === 'pull_request_target';
    if (!jobsFor || !mainBranchRun) continue;
    const jobs = await list(`/repos/${repo}/actions/runs/${r.id}/jobs?filter=all`, 'jobs');
    for (const j of jobs) {
      const env = jobsFor[j.name];
      if (!env || !j.started_at || j.conclusion === 'skipped' || !(j.steps || []).length) continue;
      if (!deps.some((d) => d.env === env && d.run === r.id) && !Object.values(state.deployments).some((d) => d.env === env && d.run === r.id)) {
        f(`MISSING-DEPLOYMENT workflow=${r.path} run=${r.id} job=${j.name} env=${env}`);
      }
    }
  }

  // Update the local state (union: nothing seen is ever forgotten).
  for (const r of runs) state.runs[r.id] = { path: r.path, number: r.run_number, created: r.created_at };
  for (const d of deps) state.deployments[d.id] = { env: d.env, run: d.run, created: d.created };
  // Atomic replace: a crash mid-write never leaves a truncated state file.
  fs.writeFileSync(`${stateFile}.tmp`, JSON.stringify(state, null, 1));
  fs.renameSync(`${stateFile}.tmp`, stateFile);

  for (const x of findings) console.log(x);
  console.log(`run audit: ${runs.length} run(s), ${deps.length} deployment(s) in the window; ${findings.length} finding(s); state ${Object.keys(state.runs).length} runs, ${Object.keys(state.deployments).length} deployments`);
  process.exit(findings.length ? 1 : 0);
}

main().catch((e) => { console.error(`run-audit: ${String(e.message).replace(/[^\x20-\x7e]/g, '?')}`); process.exit(1); });
