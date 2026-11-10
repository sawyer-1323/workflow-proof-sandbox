'use strict';

// Round 7: the D-1 run audit and the DS-3 evidence tool, against a local
// stand-in for the GitHub API. No request leaves the machine.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { execFile } = require('node:child_process');

const script = (...p) => path.join(__dirname, '..', 'scripts', ...p);
const R = '/repos/o/r';
const T0 = '2026-11-20T00:00:00Z';
const at = (h) => new Date(Date.parse(T0) + h * 3600e3).toISOString().replace(/\.\d{3}Z$/, 'Z');

function world() {
  return {
    mainFiles: [{ name: 'review.yml', sha: 'rv1' }, { name: 'probe.yml', sha: 'pb1' }, { name: 'ci.yml', sha: 'ci1' }],
    fileAt: {}, // `${path}@${sha}` -> blob sha
    runs: [], jobs: {}, deployments: { 'review-agent': [], 'probe-agent': [], review: [], probe: [] },
    statuses: {}, logs: {}, annotations: {},
  };
}
function serve(w) {
  const send = (res, code, body, type = 'application/json') => { res.writeHead(code, { 'content-type': type }); res.end(type === 'application/json' ? JSON.stringify(body) : body); };
  const server = http.createServer((req, res) => {
    if (req.headers.authorization !== 'Bearer t') return send(res, 401, {});
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const page = Number(u.searchParams.get('page') || '1');
    const pg = (a) => a.slice((page - 1) * 100, page * 100);
    let m;
    if (p === `${R}/contents/.github/workflows`) return send(res, 200, w.mainFiles);
    if ((m = new RegExp(`^${R}/contents/(.+)$`).exec(p))) {
      const k = `${m[1]}@${u.searchParams.get('ref')}`;
      return k in w.fileAt ? send(res, 200, { sha: w.fileAt[k] }) : send(res, 404, {});
    }
    if (p === `${R}/actions/runs`) {
      const br = u.searchParams.get('branch');
      const all = w.runs.filter((r) => !br || r.head_branch === br);
      return send(res, 200, { total_count: w.totalOverride ?? all.length, workflow_runs: pg(all) });
    }
    if ((m = new RegExp(`^${R}/actions/runs/(\\d+)/jobs$`).exec(p))) return send(res, 200, { jobs: pg(w.jobs[m[1]] || []) });
    if ((m = new RegExp(`^${R}/actions/jobs/(\\d+)/logs$`).exec(p))) return m[1] in w.logs ? send(res, 200, w.logs[m[1]], 'text/plain') : send(res, 404, {});
    if ((m = new RegExp(`^${R}/check-runs/(\\d+)/annotations$`).exec(p))) return send(res, 200, w.annotations[m[1]] || []);
    if (p === `${R}/deployments`) return send(res, 200, pg(w.deployments[u.searchParams.get('environment')] || []));
    if ((m = new RegExp(`^${R}/deployments/(\\d+)/statuses$`).exec(p))) return send(res, 200, pg(w.statuses[m[1]] || []));
    return send(res, 404, {});
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}
const run = (file, args, port) => new Promise((resolve) => {
  execFile(process.execPath, [file, ...args], { env: { ...process.env, GH_TOKEN: 't', GITHUB_API_URL: `http://127.0.0.1:${port}` } },
    (err, stdout, stderr) => resolve({ code: err ? err.code : 0, out: String(stdout) + String(stderr) }));
});
const ghRun = (id, o) => ({ id, path: '.github/workflows/probe.yml', run_number: id - 100, run_attempt: 1, event: 'workflow_dispatch',
  head_branch: 'main', head_sha: 'm1', triggering_actor: { login: 'owner' }, created_at: at(1), ...o });
const agentJob = (id, name = 'probe-agent') => ({ id, name, started_at: at(1), conclusion: 'success', steps: [{ name: 'Validate', status: 'completed', conclusion: 'success' }] });
const dep = (id, runId, o = {}) => ({ id, ref: 'main', creator: { login: 'github-actions[bot]' }, created_at: at(1), ...o, _run: runId });
function addDep(w, env, d) {
  w.deployments[env].push(d);
  w.statuses[d.id] = d._run ? [{ state: 'success', log_url: `https://github.com/o/r/actions/runs/${d._run}/job/1` }] : [];
}

test('D-1 run audit: clean window, then a deleted deployment and a deleted run are reported', async () => {
  const w = world();
  for (const id of [101, 102, 103]) { w.runs.push(ghRun(id)); w.jobs[id] = [agentJob(id * 10)]; addDep(w, 'probe-agent', dep(9000 + id, id)); }
  const server = await serve(w);
  const state = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'audit-')), 'state.json');
  const args = ['--repo', 'o/r', '--since', T0, '--approver', 'owner', '--state', state];
  try {
    const a = await run(script('audit', 'run-audit.js'), args, server.address().port);
    assert.equal(a.code, 0, a.out);
    assert.ok(a.out.includes('0 finding(s)'));
    // A token with deployments and Actions write deletes one deployment and one run.
    w.deployments['probe-agent'] = w.deployments['probe-agent'].filter((d) => d.id !== 9102);
    w.runs = w.runs.filter((r) => r.id !== 102);
    const b = await run(script('audit', 'run-audit.js'), args, server.address().port);
    assert.equal(b.code, 1);
    assert.match(b.out, /DELETED-DEPLOYMENT env=probe-agent id=9102 run=102/);
    assert.match(b.out, /DELETED-RUN workflow=\.github\/workflows\/probe\.yml run=102 number=2/);
    assert.match(b.out, /RUN-GAP workflow=\.github\/workflows\/probe\.yml number=2/);
    assert.ok(!b.out.includes('Bearer') && !b.out.includes(' t '));
  } finally { server.close(); }
});

test('D-1 run audit: missing deployment, foreign deployment, non-approver dispatch, branch workflow', async () => {
  const w = world();
  w.runs.push(ghRun(201));                       // agent job ran, no deployment at all
  w.jobs[201] = [agentJob(2010)];
  w.runs.push(ghRun(202, { triggering_actor: { login: 'cursor[bot]' } })); // dispatched by an App
  w.jobs[202] = [agentJob(2020)];
  addDep(w, 'probe-agent', dep(9202, 202));
  addDep(w, 'review-agent', dep(9300, null, { ref: 'refs/pull/5/merge' })); // not a main run
  w.runs.push(ghRun(203, { path: '.github/workflows/ds3-leak.yml', event: 'push', head_branch: 'ds3-leak', head_sha: 'b1', run_number: 1 }));
  w.runs.push(ghRun(204, { path: '.github/workflows/ci.yml', event: 'pull_request', head_branch: 'feature', head_sha: 'f1', run_number: 1 }));
  w.fileAt['.github/workflows/ci.yml@f1'] = 'ci2'; // edited on the branch
  const server = await serve(w);
  const state = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'audit-')), 'state.json');
  try {
    const r = await run(script('audit', 'run-audit.js'), ['--repo', 'o/r', '--since', T0, '--approver', 'owner', '--state', state], server.address().port);
    assert.equal(r.code, 1);
    assert.match(r.out, /MISSING-DEPLOYMENT workflow=\.github\/workflows\/probe\.yml run=201 job=probe-agent env=probe-agent/);
    assert.match(r.out, /NON-APPROVER-TRIGGER run=202 .* by=cursor\[bot\]/);
    assert.match(r.out, /FOREIGN-DEPLOYMENT env=review-agent id=9300 ref=refs\/pull\/5\/merge/);
    assert.match(r.out, /UNEXPECTED-WORKFLOW run=203 path=\.github\/workflows\/ds3-leak\.yml/);
    assert.match(r.out, /UNEXPECTED-WORKFLOW run=204 path=\.github\/workflows\/ci\.yml/);
    assert.ok(!/MISSING-DEPLOYMENT .*run=202/.test(r.out));
  } finally { server.close(); }
});

function ds3World({ leak }) {
  const w = world();
  const envs = ['review-agent', 'probe-agent', 'review', 'probe'];
  const runs = [
    { id: 301, path: '.github/workflows/ds3-leak.yml', event: 'pull_request', head_branch: 'ds3-leak', ref: 'refs/pull/7/merge' },
    { id: 302, path: '.github/workflows/ds3-leak.yml', event: 'push', head_branch: 'ds3-leak', ref: 'refs/heads/ds3-leak' },
    { id: 303, path: '.github/workflows/probe.yml', event: 'workflow_dispatch', head_branch: 'ds3-leak', ref: 'refs/heads/ds3-leak' },
  ];
  let jid = 1;
  for (const r of runs) {
    w.runs.push({ ...r, created_at: at(1) });
    const ctx = { id: jid++, name: 'context', steps: [{ name: 'Event and ref of this run', status: 'completed', conclusion: 'success' }] };
    w.logs[ctx.id] = `DS3-CONTEXT event=${r.event} ref=${r.ref} ref_name=x\n`;
    w.jobs[r.id] = [ctx];
    for (const e of envs) for (const nd of ['', '-nodeploy']) {
      const id = jid++;
      const ran = leak && nd && r.event === 'push' && e === 'probe';
      w.jobs[r.id].push({ id, name: `env-${e}${nd}`, steps: ran ? [{ name: 'Report reach (never prints the value)', status: 'completed', conclusion: 'success' }] : [] });
      if (ran) w.logs[id] = `DS3-RAN env=${e} mode=deployment-false event=push ref=${r.ref}\nDS3-CANARY reachable sha256-16=0123456789abcdef\n`;
      else w.annotations[id] = [{ message: `Branch "ds3-leak" is not allowed to deploy to ${e} due to environment protection rules.` }];
    }
  }
  addDep(w, 'review-agent', dep(9401, 301, { ref: 'refs/pull/7/merge' }));
  return w;
}

test('DS-3 evidence: all refused is PASS; refs and deployment records are reported separately', async () => {
  const server = await serve(ds3World({ leak: false }));
  try {
    const r = await run(script('audit', 'ds3-evidence.js'), ['--repo', 'o/r', '--since', T0], server.address().port);
    assert.equal(r.code, 0, r.out);
    assert.match(r.out, /== DS-3: PASS/);
    assert.match(r.out, /environment jobs: 24/);
    assert.match(r.out, /pull_request\t301\tenv-review-agent\treview-agent\tdefault\trefused\trefused: Branch "ds3-leak" is not allowed/);
    assert.match(r.out, /\tpull_request refs\/pull\/7\/merge\tnot reached\t9401@refs\/pull\/7\/merge\[success\]/);
  } finally { server.close(); }
});

test('DS-3 evidence: a deployment:false job that reads the canary is a STOP, with its ref and hash verdict', async () => {
  const server = await serve(ds3World({ leak: true }));
  const hashes = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ds3-')), 'h');
  fs.writeFileSync(hashes, 'probe 0123456789abcdef\n');
  try {
    const r = await run(script('audit', 'ds3-evidence.js'), ['--repo', 'o/r', '--since', T0, '--hashes', hashes], server.address().port);
    assert.equal(r.code, 1);
    assert.match(r.out, /push\t302\tenv-probe-nodeploy\tprobe\tdeployment-false\tRAN\tran on push refs\/heads\/ds3-leak\t.*REACHABLE \(hash matches\)\tnone/);
    assert.match(r.out, /== DS-3: STOP/);
  } finally { server.close(); }
});

test('D-1 run audit fails closed past the 1,000-run listing limit, and refuses other API hosts', async () => {
  const w = world();
  w.runs.push(ghRun(501));
  w.totalOverride = 1001;
  const server = await serve(w);
  const state = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'audit-')), 'state.json');
  const args = ['--repo', 'o/r', '--since', T0, '--approver', 'owner', '--state', state];
  try {
    const r = await run(script('audit', 'run-audit.js'), args, server.address().port);
    assert.equal(r.code, 1);
    assert.match(r.out, /exceed the 1,000/);
    assert.ok(!fs.existsSync(state), 'no state is written from a partial listing');
    const other = await new Promise((resolve) => {
      execFile(process.execPath, [script('audit', 'run-audit.js'), ...args],
        { env: { ...process.env, GH_TOKEN: 't', GITHUB_API_URL: 'https://example.com' } },
        (err, stdout, stderr) => resolve({ code: err ? err.code : 0, out: String(stdout) + String(stderr) }));
    });
    assert.equal(other.code, 1);
    assert.match(other.out, /GITHUB_API_URL must be https:\/\/api\.github\.com/);
  } finally { server.close(); }
});
