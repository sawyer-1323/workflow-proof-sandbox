#!/usr/bin/env node
'use strict';

// DS-3 evidence (round 7): the secret-boundary matrix, read-only.
// Run by the approver (or a supervised agent session, read-only) after the
// DS-3 runs on branch `ds3-leak`. For every environment job of the fixtures it
// reports, as SEPARATE columns:
//   - outcome:    refused before any step, or ran;
//   - ref:        the ref GitHub evaluated (the job's own DS3-RAN line if it
//                 ran; otherwise the refusal annotation, plus the run's
//                 DS3-CONTEXT ref);
//   - canary:     not reached / empty / reachable (hash prefix matches the
//                 approver's value or not);
//   - deployment: the deployment records created for that run and environment.
// Prints GitHub messages, refs, IDs and hash prefixes only; never a secret.
// Exit 0: every environment job refused before any step (PASS).
// Exit 1: any environment job ran a step (STOP), or an error.
//
// Usage: GH_TOKEN="$(gh auth token)" node scripts/audit/ds3-evidence.js \
//          --repo owner/name --since 2026-11-20T00:00:00Z [--branch ds3-leak] \
//          [--hashes <file with lines "<environment> <sha256 first 16 hex>">]

const fs = require('node:fs');
const { get, list, text, runIdOf, totalCount } = require('./gh.js');

const arg = (n, d) => { const i = process.argv.indexOf(`--${n}`); return i > 0 ? process.argv[i + 1] : d; };
const repo = arg('repo');
const since = arg('since');
const branch = arg('branch', 'ds3-leak');
const hashFile = arg('hashes');
const FIXTURE_PATHS = ['.github/workflows/ds3-leak.yml', '.github/workflows/probe.yml'];
const ENVS = ['review-agent', 'probe-agent', 'review', 'probe'];

function clean(s) { return String(s || '').replace(/[^\x20-\x7e]/g, '?').slice(0, 300); }

async function main() {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '') || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(since || '')) {
    console.error('usage: --repo owner/name --since YYYY-MM-DDTHH:MM:SSZ [--branch b] [--hashes file]'); process.exit(2);
  }
  const expected = {};
  if (hashFile) for (const l of fs.readFileSync(hashFile, 'utf8').split('\n')) { const [e, h] = l.trim().split(/\s+/); if (e && h) expected[e] = h; }

  const runsPath = `/repos/${repo}/actions/runs?branch=${encodeURIComponent(branch)}&created=${encodeURIComponent('>=' + since)}`;
  if ((await totalCount(runsPath)) > 1000) throw new Error('more than 1,000 runs on the branch in the window; use a later --since');
  const runs = (await list(runsPath, 'workflow_runs'))
    .filter((r) => FIXTURE_PATHS.includes(r.path));
  // Deployments of each environment in the window, keyed by the run their statuses name.
  const deps = {};
  for (const e of ENVS) {
    const all = (await list(`/repos/${repo}/deployments?environment=${encodeURIComponent(e)}`)).filter((d) => Date.parse(d.created_at) >= Date.parse(since));
    deps[e] = [];
    for (const d of all) {
      const st = await list(`/repos/${repo}/deployments/${d.id}/statuses`);
      const runIds = [...new Set(st.flatMap((s) => [runIdOf(s.log_url), runIdOf(s.target_url)]).filter(Boolean))];
      deps[e].push({ id: d.id, ref: d.ref, creator: d.creator && d.creator.login, runIds, states: st.map((s) => s.state) });
    }
  }

  const rows = [];
  let stop = false;
  for (const run of runs) {
    const jobs = await list(`/repos/${repo}/actions/runs/${run.id}/jobs?filter=all`, 'jobs');
    let contextRef = '-';
    const ctx = jobs.find((j) => j.name === 'context');
    if (ctx) {
      const log = await text(`/repos/${repo}/actions/jobs/${ctx.id}/logs`);
      const m = /DS3-CONTEXT event=(\S+) ref=(\S+)/.exec(log || '');
      if (m) contextRef = `${m[1]} ${m[2]}`;
    }
    for (const job of jobs) {
      const m = /^env-(review-agent|probe-agent|review|probe)(-nodeploy)?$/.exec(job.name);
      if (!m) continue;
      const env = m[1];
      const mode = m[2] ? 'deployment-false' : 'default';
      const ran = Array.isArray(job.steps) && job.steps.some((s) => /Report reach/.test(s.name) && s.status !== 'queued' && s.conclusion !== 'skipped');
      let ref = '';
      let canary = 'not reached';
      if (ran) {
        stop = true;
        const log = (await text(`/repos/${repo}/actions/jobs/${job.id}/logs`)) || '';
        const r = /DS3-RAN env=\S+ mode=\S+ event=(\S+) ref=(\S+)/.exec(log);
        ref = r ? `ran on ${r[1]} ${r[2]}` : 'ran (no DS3-RAN line found)';
        const c = /DS3-CANARY reachable sha256-16=([0-9a-f]{16})/.exec(log);
        if (c) canary = expected[env] ? (expected[env] === c[1] ? 'REACHABLE (hash matches)' : 'REACHABLE (hash differs)') : 'REACHABLE (no expected hash given)';
        else if (/DS3-CANARY empty/.test(log)) canary = 'ran, secret empty';
      } else {
        const ann = (await get(`/repos/${repo}/check-runs/${job.id}/annotations`)) || [];
        ref = `refused: ${clean(ann.map((a) => a.message).join(' | ')) || '(no annotation)'}`;
      }
      const d = deps[env].filter((x) => x.runIds.includes(run.id));
      rows.push([run.event, run.id, job.name, env, mode, ran ? 'RAN' : 'refused', ref, contextRef, canary,
        d.length ? d.map((x) => `${x.id}@${x.ref}[${x.states.join('/')}]`).join(',') : 'none']);
    }
  }
  const unlinked = ENVS.flatMap((e) => deps[e].filter((x) => x.runIds.length === 0).map((x) => `${e}:${x.id}@${x.ref}`));

  console.log(['event', 'run', 'job', 'environment', 'mode', 'outcome', 'ref evaluated', 'run context', 'canary', 'deployment records'].join('\t'));
  for (const r of rows) console.log(r.join('\t'));
  console.log(`deployments in the window not linked to any run: ${unlinked.length ? unlinked.join(',') : 'none'}`);
  console.log(`runs read: ${runs.length}; environment jobs: ${rows.length}`);
  if (rows.length === 0) { console.log('== DS-3: NO EVIDENCE (no fixture runs found)'); process.exit(1); }
  console.log(`== DS-3: ${stop ? 'STOP: an environment job ran on a non-main ref' : 'PASS: every environment job refused before any step'}`);
  process.exit(stop ? 1 : 0);
}

main().catch((e) => { console.error(`ds3-evidence: ${clean(e.message)}`); process.exit(1); });
