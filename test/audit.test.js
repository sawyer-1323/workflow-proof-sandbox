'use strict';

// Round 7: the D-1 run audit and the DS-3 evidence tool, against a local
// stand-in for the GitHub API. No request leaves the machine. Revision 9 adds
// redirects (to a second local server that records what reaches it), the
// unfiltered deployment listing, /environments, and the state-file hash check.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { execFile } = require('node:child_process');
const crypto = require('node:crypto');

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
    environments: ['review-agent', 'probe-agent', 'review', 'probe'].map((name, i) => ({ id: 700 + i, name, created_at: T0 })),
    redirects: {},        // pathname -> Location (answered 302)
    logRedirect: null,    // base URL: job logs answer 302 to `${base}/log/<id>`, as GitHub's do
    hidden: new Set(),    // deployment IDs left out of the unfiltered listing only
    requests: 0,
  };
}
// The redirect target: records every request, and serves job logs at /log/<id>.
function foreign(w) {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push({ url: req.url, authorization: req.headers.authorization || null });
    if (req.url.startsWith('/again/')) { res.writeHead(302, { location: `http://127.0.0.1:${server.address().port}/x` }); return res.end(); }
    const m = /^\/log\/(\d+)$/.exec(req.url);
    if (m && m[1] in w.logs) { res.writeHead(200, { 'content-type': 'text/plain' }); return res.end(w.logs[m[1]]); }
    res.writeHead(200, { 'content-type': 'application/json' }); res.end('[]');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, seen, base: `http://127.0.0.1:${server.address().port}` })));
}
function serve(w) {
  const send = (res, code, body, type = 'application/json') => { res.writeHead(code, { 'content-type': type }); res.end(type === 'application/json' ? JSON.stringify(body) : body); };
  const server = http.createServer((req, res) => {
    w.requests++;
    if (req.headers.authorization !== 'Bearer t') return send(res, 401, {});
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const page = Number(u.searchParams.get('page') || '1');
    const pg = (a) => a.slice((page - 1) * 100, page * 100);
    let m;
    if (p in w.redirects) { res.writeHead(302, { location: w.redirects[p] }); return res.end(); }
    if (p === `${R}/environments`) return send(res, 200, { total_count: w.environments.length, environments: pg(w.environments) });
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
    if ((m = new RegExp(`^${R}/actions/jobs/(\\d+)/logs$`).exec(p))) {
      if (w.logRedirect) { res.writeHead(302, { location: `${w.logRedirect}/log/${m[1]}` }); return res.end(); }
      return m[1] in w.logs ? send(res, 200, w.logs[m[1]], 'text/plain') : send(res, 404, {});
    }
    if ((m = new RegExp(`^${R}/check-runs/(\\d+)/annotations$`).exec(p))) return send(res, 200, w.annotations[m[1]] || []);
    if (p === `${R}/deployments`) {
      const e = u.searchParams.get('environment');
      const all = e ? (w.deployments[e] || []) : Object.values(w.deployments).flat().filter((d) => !w.hidden.has(d.id));
      return send(res, 200, pg(all));
    }
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
  (w.deployments[env] = w.deployments[env] || []).push({ ...d, environment: env });
  w.statuses[d.id] = d._run ? [{ state: 'success', log_url: `https://github.com/o/r/actions/runs/${d._run}/job/1` }] : [];
}
const tmpState = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'audit-')), 'state.json');
const auditArgs = (state, expect = 'none') => ['--repo', 'o/r', '--since', T0, '--approver', 'owner', '--state', state, '--expect-state', expect];
// The value to record after a run: the last line, "state sha256 <before> -> <after>".
const stateAfter = (out) => { const m = /^state sha256 (?:none|[0-9a-f]{64}) -> ([0-9a-f]{64})$/m.exec(out); assert.ok(m, out); return m[1]; };

test('D-1 run audit: clean window, then a deleted deployment and a deleted run are reported', async () => {
  const w = world();
  for (const id of [101, 102, 103]) { w.runs.push(ghRun(id)); w.jobs[id] = [agentJob(id * 10)]; addDep(w, 'probe-agent', dep(9000 + id, id)); }
  const server = await serve(w);
  const state = tmpState();
  try {
    const a = await run(script('audit', 'run-audit.js'), auditArgs(state), server.address().port);
    assert.equal(a.code, 0, a.out);
    assert.ok(a.out.includes('3 deployment(s) in the window (0 outside the expected environments); 4 environment(s); 0 finding(s)'), a.out);
    // A token with deployments and Actions write deletes one deployment and one run.
    w.deployments['probe-agent'] = w.deployments['probe-agent'].filter((d) => d.id !== 9102);
    w.runs = w.runs.filter((r) => r.id !== 102);
    const b = await run(script('audit', 'run-audit.js'), auditArgs(state, stateAfter(a.out)), server.address().port);
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
  const state = tmpState();
  try {
    const r = await run(script('audit', 'run-audit.js'), auditArgs(state), server.address().port);
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
  const state = tmpState();
  const args = auditArgs(state);
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

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

test('revision 9: the run audit refuses an HTTP redirect, and nothing reaches its Location', async () => {
  for (const p of [`${R}/contents/.github/workflows`, `${R}/environments`, `${R}/deployments`]) {
    const w = world();
    w.runs.push(ghRun(601)); w.jobs[601] = [agentJob(6010)]; addDep(w, 'probe-agent', dep(9601, 601));
    const target = await foreign(w);
    w.redirects[p] = `${target.base}${p}`;
    const server = await serve(w);
    const state = tmpState();
    try {
      const r = await run(script('audit', 'run-audit.js'), auditArgs(state), server.address().port);
      assert.equal(r.code, 1, `${p}: ${r.out}`);
      assert.match(r.out, new RegExp(`run-audit: GET ${esc(p)} refused a redirect \\(HTTP 302\\); not followed`));
      assert.equal(target.seen.length, 0, `${p}: a request reached the redirect target`);
      assert.ok(!fs.existsSync(state), `${p}: no state is written`);
      assert.ok(!r.out.includes('Bearer'));
    } finally { server.close(); target.server.close(); }
  }
});

test('revision 9: DS-3 evidence fetches job logs through their redirect without the token; any other redirect is refused', async () => {
  const w = ds3World({ leak: true });
  const target = await foreign(w);
  w.logRedirect = target.base;
  const hashes = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'ds3-')), 'h');
  fs.writeFileSync(hashes, 'probe 0123456789abcdef\n');
  const server = await serve(w);
  const ev = (args) => run(script('audit', 'ds3-evidence.js'), ['--repo', 'o/r', '--since', T0, '--hashes', hashes, ...args], server.address().port);
  try {
    const a = await ev([]);
    assert.equal(a.code, 1, a.out);
    assert.match(a.out, /push\t302\tenv-probe-nodeploy\tprobe\tdeployment-false\tRAN\tran on push refs\/heads\/ds3-leak\tpush refs\/heads\/ds3-leak\tREACHABLE \(hash matches\)/);
    assert.equal(target.seen.filter((s) => /^\/log\/\d+$/.test(s.url)).length, 4, 'three context logs and one RAN log');
    assert.ok(target.seen.every((s) => s.authorization === null), 'the token reached the log host');
    // The log host redirects again: refused, not followed.
    w.logRedirect = `${target.base}/again`;
    const b = await ev([]);
    assert.equal(b.code, 1);
    assert.match(b.out, /ds3-evidence: GET \/repos\/o\/r\/actions\/jobs\/1\/logs log download redirected again \(HTTP 302\); not followed/);
    // A log redirect to a URL that is not https: refused before any request.
    w.logRedirect = 'http://example.invalid';
    const c = await ev([]);
    assert.equal(c.code, 1);
    assert.match(c.out, /GET \/repos\/o\/r\/actions\/jobs\/1\/logs redirect to a non-https URL; not followed/);
    // A redirect on any other endpoint is refused.
    w.logRedirect = target.base;
    w.redirects[`${R}/check-runs/2/annotations`] = `${target.base}/x`;
    const d = await ev([]);
    assert.equal(d.code, 1);
    assert.match(d.out, /ds3-evidence: GET \/repos\/o\/r\/check-runs\/2\/annotations refused a redirect \(HTTP 302\); not followed/);
    assert.ok(!target.seen.some((s) => s.url === '/x'), 'a refused redirect was followed');
  } finally { server.close(); target.server.close(); }
});

test('revision 9: deployments and environments outside the expected four are reported, and remembered', async () => {
  const w = world();
  w.runs.push(ghRun(701)); w.jobs[701] = [agentJob(7010)]; addDep(w, 'probe-agent', dep(9701, 701));
  addDep(w, 'ds3-other', dep(9702, null, { ref: 'ds3-leak' })); // a branch workflow named a new environment
  addDep(w, 'staging', dep(9703, 701));                         // a main Actions deployment, still unexpected
  w.environments = w.environments.filter((x) => x.name !== 'probe');
  w.environments.push({ id: 780, name: 'ds3-other', created_at: at(1) }, { id: 781, name: 'empty-env', created_at: at(2) },
    { id: 782, name: 'café', created_at: at(3) });
  const server = await serve(w);
  const state = tmpState();
  try {
    const a = await run(script('audit', 'run-audit.js'), auditArgs(state), server.address().port);
    assert.equal(a.code, 1, a.out);
    assert.match(a.out, /^UNEXPECTED-ENVIRONMENT env=ds3-other id=9702 ref=ds3-leak creator=github-actions\[bot\]$/m);
    assert.match(a.out, /^FOREIGN-DEPLOYMENT env=ds3-other id=9702 ref=ds3-leak creator=github-actions\[bot\]$/m);
    assert.match(a.out, /^UNEXPECTED-ENVIRONMENT env=staging id=9703 ref=main creator=github-actions\[bot\]$/m);
    assert.ok(!/FOREIGN-DEPLOYMENT env=staging/.test(a.out));
    assert.match(a.out, /^UNEXPECTED-ENVIRONMENT env=ds3-other environment_id=780 created=2026-11-20T01:00:00Z$/m);
    assert.match(a.out, /^UNEXPECTED-ENVIRONMENT env=empty-env environment_id=781 created=/m);
    assert.match(a.out, /^UNEXPECTED-ENVIRONMENT env=caf\? environment_id=782 created=/m, 'printed as ASCII');
    assert.match(a.out, /^MISSING-ENVIRONMENT env=probe$/m);
    assert.ok(!/^MISSING-ENVIRONMENT env=(review-agent|probe-agent|review)$/m.test(a.out));
    assert.ok(!/MISSING-DEPLOYMENT/.test(a.out));
    assert.match(a.out, /3 deployment\(s\) in the window \(2 outside the expected environments\); 6 environment\(s\); 7 finding\(s\)/);
    // The unexpected deployment is deleted on GitHub; the state still knows it.
    w.deployments['ds3-other'] = [];
    const b = await run(script('audit', 'run-audit.js'), auditArgs(state, stateAfter(a.out)), server.address().port);
    assert.equal(b.code, 1);
    assert.match(b.out, /^DELETED-DEPLOYMENT env=ds3-other id=9702 run=\? created=/m);
  } finally { server.close(); }
});

test('revision 9: the run audit stops if the unfiltered deployment listing lacks one an environment listing has', async () => {
  const w = world();
  addDep(w, 'probe-agent', dep(9801, null));
  w.hidden.add(9801);
  const server = await serve(w);
  const state = tmpState();
  try {
    const r = await run(script('audit', 'run-audit.js'), auditArgs(state), server.address().port);
    assert.equal(r.code, 1);
    assert.match(r.out, /the unfiltered deployment listing lacks 1 deployment\(s\) of probe-agent; rerun the audit/);
    assert.ok(!fs.existsSync(state), 'no state is written');
  } finally { server.close(); }
});

test('revision 9: --expect-state is required, and a state file that differs stops the audit before any request', async () => {
  const w = world();
  w.runs.push(ghRun(901)); w.jobs[901] = [agentJob(9010)]; addDep(w, 'probe-agent', dep(9901, 901));
  const server = await serve(w);
  const port = server.address().port;
  const audit = (args) => run(script('audit', 'run-audit.js'), args, port);
  const state = tmpState();
  try {
    const noFlag = await audit(auditArgs(state).slice(0, -2));
    assert.equal(noFlag.code, 2);
    assert.match(noFlag.out, /--expect-state <sha256\|none>/);
    assert.equal((await audit(auditArgs(state, 'ABC'))).code, 2);
    assert.equal(w.requests, 0);

    const a = await audit(auditArgs(state));
    assert.equal(a.code, 0, a.out);
    const h = stateAfter(a.out);
    const bytes = fs.readFileSync(state);
    assert.equal(h, crypto.createHash('sha256').update(bytes).digest('hex'), 'the printed value is the file\'s SHA-256');

    const n = w.requests;
    for (const wrong of ['none', '0'.repeat(64)]) {
      const r = await audit(auditArgs(state, wrong));
      assert.equal(r.code, 1);
      assert.match(r.out, new RegExp(`state file sha256 is ${h}, not the --expect-state value ${wrong}; nothing was requested or written`));
      assert.equal(w.requests, n, 'no request was made');
      assert.deepStrictEqual(fs.readFileSync(state), bytes, 'the state file is unchanged');
    }
    // An edit (here: the deployment forgotten) is caught with the recorded value, before any request.
    const edited = JSON.parse(bytes.toString('utf8'));
    delete edited.deployments['9901'];
    fs.writeFileSync(state, JSON.stringify(edited, null, 1));
    const e = await audit(auditArgs(state, h));
    assert.equal(e.code, 1);
    assert.match(e.out, /not the --expect-state value/);
    assert.equal(w.requests, n);
    // A state file that went missing is caught too.
    const gone = await audit(auditArgs(tmpState(), h));
    assert.match(gone.out, /state file sha256 is none, not the --expect-state value/);
    // With the recorded file back, the recorded value lets the audit run.
    fs.writeFileSync(state, bytes);
    const ok = await audit(auditArgs(state, h));
    assert.equal(ok.code, 0, ok.out);
    assert.match(ok.out, new RegExp(`^state sha256 ${h} -> [0-9a-f]{64}$`, 'm'));
  } finally { server.close(); }
});
