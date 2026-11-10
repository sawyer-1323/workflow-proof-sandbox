'use strict';

// Unit tests for the artifact encryption, the S5 encoded-value detection, and
// the model proxy's local refusals (no request ever reaches an upstream host).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const http = require('node:http');
const { spawn, execFileSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const script = (...p) => path.join(root, 'scripts', ...p);
const { findEncoded } = require(script('validate-artifact.js'));
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'proof-'));

test('artifact encryption round-trips and rejects tampering', () => {
  const d = tmp();
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  fs.writeFileSync(path.join(d, 'pub.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  fs.mkdirSync(path.join(d, 'in', 'cases', 'a'), { recursive: true });
  fs.writeFileSync(path.join(d, 'in', 'cases', 'a', 'review.json'), '{"x":1}');
  const env = { ...process.env, ARTIFACT_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
  execFileSync(process.execPath, [script('artifact-crypt.js'), 'encrypt', path.join(d, 'pub.pem'), path.join(d, 'in'), path.join(d, 'enc.json')]);
  assert.ok(!fs.readFileSync(path.join(d, 'enc.json'), 'utf8').includes('"x":1'));
  execFileSync(process.execPath, [script('artifact-crypt.js'), 'decrypt', path.join(d, 'enc.json'), path.join(d, 'out')], { env });
  assert.equal(fs.readFileSync(path.join(d, 'out', 'cases', 'a', 'review.json'), 'utf8'), '{"x":1}');
  const e = JSON.parse(fs.readFileSync(path.join(d, 'enc.json'), 'utf8'));
  e.ct = Buffer.from('tampered').toString('base64');
  fs.writeFileSync(path.join(d, 'bad.json'), JSON.stringify(e));
  assert.throws(() => execFileSync(process.execPath, [script('artifact-crypt.js'), 'decrypt', path.join(d, 'bad.json'), path.join(d, 'out2')], { env, stdio: 'pipe' }));
});

test('encoded canaries are detected; rot13 is the documented residual', () => {
  const c = 'S5CANARYq8Zr2LmN0pXw4Tb7';
  const b64 = (s) => Buffer.from(s).toString('base64');
  assert.ok(findEncoded([`x ${c} y`], [c]));
  assert.ok(findEncoded([`x ${b64('ab' + c + 'cd')} y`], [c]));
  assert.ok(findEncoded([Buffer.from(c).toString('hex')], [c]));
  assert.ok(findEncoded([[...c].reverse().join('')], [c]));
  assert.ok(findEncoded([[...Buffer.from(c)].map((b) => '%' + b.toString(16)).join('')], [c]));
  assert.ok(findEncoded([c.slice(0, 12), 'unrelated text', c.slice(12)], [c]));
  assert.ok(!findEncoded(['an ordinary review with no canary'], [c]));
  const rot13 = c.replace(/[a-z]/gi, (ch) => String.fromCharCode((ch <= 'Z' ? 65 : 97) + ((ch.toLowerCase().charCodeAt(0) - 97 + 13) % 26)));
  assert.ok(!findEncoded([rot13], [c]));
});

test('the S5 stub cases get their expected outcomes', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'canary.txt'), 'S5CANARYq8Zr2LmN0pXw4Tb7\n');
  const head = 'a'.repeat(40);
  const base = 'b'.repeat(40);
  execFileSync(process.execPath, [script('probes', 'hostile-output-stub.js'), d, '7', head, base, path.join(d, 'canary.txt')],
    { env: { ...process.env, ANTHROPIC_API_KEY: 'proof-placeholder-not-a-key' }, stdio: 'pipe' });
  fs.writeFileSync(path.join(d, 'forbid'), 'S5CANARYq8Zr2LmN0pXw4Tb7\nproof-placeholder-not-a-key\n');
  const expected = fs.readFileSync(script('probes', 's5-cases.expected'), 'utf8').trim().split('\n').map((l) => l.split(' '));
  for (const [name, kind, want] of expected) {
    const dir = path.join(d, 's5', name);
    const args = kind === 'review'
      ? ['review', dir, '--pr', '7', '--head', head, '--forbid-file', path.join(d, 'forbid')]
      : ['patch', dir, '--task', '1', '--base', base, '--branch', 'agent/s5', '--expected-head', 'new', '--forbid-file', path.join(d, 'forbid')];
    let out;
    try { out = execFileSync(process.execPath, [script('validate-artifact.js'), ...args], { encoding: 'utf8' }); } catch (e) { out = String(e.stdout); }
    assert.equal(out.split(' ')[0], want, name);
    assert.ok(!out.includes('S5CANARY') && !out.includes('placeholder-not'), `${name}: output echoes a value`);
  }
});

function startProxy(extra = {}) {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const log = path.join(tmp(), 'mp.log');
  const env = {
    ...process.env, MP_UPSTREAM_KEY: 'test-key-not-real', MP_PORT: String(port), MP_PLACEHOLDER: 'proof-placeholder-not-a-key',
    MP_MODELS: 'model-a', MP_MAX_TOKENS: '100', MP_MAX_REQUESTS: '5', MP_SPEND_CAP_USD: '0.0001', MP_MAX_INPUT_TOKENS: '1000',
    MP_INPUT_USD_PER_MTOK: '3', MP_OUTPUT_USD_PER_MTOK: '15', MP_UPSTREAM_IPS: '192.0.2.1', MP_LOG: log, ...extra,
  };
  const child = spawn(process.execPath, [script('model-proxy.js')], { env, stdio: 'ignore' });
  return { child, port, log };
}
function call(port, { method = 'POST', p = '/v1/messages', headers = {}, body } = {}) {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: p, headers: { 'content-type': 'application/json', ...headers } }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', () => resolve(0));
    req.end(body === undefined ? undefined : JSON.stringify(body));
  });
}

test('model proxy refuses disallowed requests locally', async () => {
  const { child, port, log } = startProxy();
  await new Promise((r) => setTimeout(r, 600));
  try {
    const ok = { model: 'model-a', max_tokens: 10, messages: [] };
    const ph = { 'x-api-key': 'proof-placeholder-not-a-key' };
    assert.equal(await call(port, { method: 'GET', p: '/v1/models', headers: ph }), 405);
    assert.equal(await call(port, { p: '/v1/complete', headers: ph, body: ok }), 403);
    assert.equal(await call(port, { p: '/v1/messages?x=1', headers: ph, body: ok }), 403);
    assert.equal(await call(port, { headers: ph, body: { ...ok, model: 'model-b' } }), 403);
    assert.equal(await call(port, { headers: ph, body: { ...ok, max_tokens: 101 } }), 403);
    assert.equal(await call(port, { headers: { 'x-api-key': 'other' }, body: ok }), 403);
    assert.equal(await call(port, { headers: { ...ph, authorization: 'Bearer x' }, body: ok }), 403);
    // Fail closed: the exact input count needs the upstream count_tokens call,
    // which is unreachable here (TEST-NET address), so the request is refused
    // before any /v1/messages forward. The reservation and settlement paths are
    // exercised live by M6 and B4.
    assert.equal(await call(port, { headers: ph, body: { ...ok, max_tokens: 100 } }), 502);
    const logText = fs.readFileSync(log, 'utf8');
    assert.ok(logText.includes('input count unavailable') && !logText.includes('"decision":"forwarded"'));
    const text = fs.readFileSync(log, 'utf8');
    assert.ok(!text.includes('test-key-not-real') && !text.includes('model-b') && !text.includes('"other"'));
  } finally {
    child.kill();
  }
});

test('scan-dump detects the key canary raw, hashed and encoded; passes when clean', () => {
  const d = tmp();
  const dummy = 'sk-ant-api03-PROOFDUMMY' + 'a'.repeat(80) + 'AA';
  fs.writeFileSync(path.join(d, 'canary'), dummy);
  const run = (sub) => {
    try {
      const out = execFileSync(process.execPath, [script('probes', 'scan-dump.js'), path.join(d, sub)],
        { encoding: 'utf8', env: { ...process.env, CANARY_FILE: path.join(d, 'canary') } });
      return { code: 0, out };
    } catch (e) { return { code: e.status, out: String(e.stdout) }; }
  };
  fs.mkdirSync(path.join(d, 'clean', 'files'), { recursive: true });
  fs.writeFileSync(path.join(d, 'clean', 'files', '0'), 'nothing here');
  assert.equal(run('clean').code, 0);
  for (const [name, enc] of [['raw', (s) => s], ['b64', (s) => Buffer.from(s).toString('base64')],
    ['hex', (s) => Buffer.from(s).toString('hex')], ['rev', (s) => [...s].reverse().join('')]]) {
    fs.mkdirSync(path.join(d, name, 'files'), { recursive: true });
    fs.writeFileSync(path.join(d, name, 'files', '0'), `x ${enc(dummy)} y`);
    const r = run(name);
    assert.equal(r.code, 1, name);
    assert.ok(!r.out.includes(dummy), `${name}: scan output must not echo the canary`);
  }
});

// ---- round 6: persistent run budget counted from deployments ----
const { execFile } = require('node:child_process');
const runBudget = (env) => new Promise((resolve) => {
  execFile(process.execPath, [script('check-run-budget.js')], { env: { ...process.env, ...env } }, (err, stdout) => {
    resolve({ code: err ? err.code : 0, out: String(stdout) });
  });
});
// A local stand-in for the deployments API. `deps` newest first.
function mockApi(deps, { status = 200 } = {}) {
  const server = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    if (req.headers.authorization !== 'Bearer test-token') { res.writeHead(401); return res.end('{}'); }
    if (status !== 200) { res.writeHead(status); return res.end('{}'); }
    const m = /^\/repos\/o\/r\/deployments\/(\d+)\/statuses$/.exec(u.pathname);
    if (m) {
      const d = deps.find((x) => String(x.id) === m[1]);
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(d ? d.statuses : []));
    }
    if (u.pathname === '/repos/o/r/deployments' && u.searchParams.get('environment') === 'review-agent') {
      const page = Number(u.searchParams.get('page') || '1');
      const body = deps.slice((page - 1) * 100, page * 100).map(({ statuses, ...d }) => d);
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify(body));
    }
    res.writeHead(404); res.end('{}');
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}
const iso = (msAgo) => new Date(Date.now() - msAgo).toISOString().replace(/\.\d{3}Z$/, 'Z');
const dep = (id, msAgo, runId, extra = {}) => ({
  id, created_at: iso(msAgo), ref: 'main', creator: { login: 'github-actions[bot]' },
  statuses: runId ? [{ state: 'in_progress', target_url: `https://github.com/o/r/actions/runs/${runId}/job/9`, log_url: `https://github.com/o/r/actions/runs/${runId}/job/9` }] : [],
  ...extra,
});
const HOUR = 3600e3;

test('run budget: counts deployments in the window, includes itself, and fails closed', async () => {
  const deps = [dep(14, 1000, 777), dep(13, HOUR, 700), dep(12, 2 * HOUR, 650), dep(11, 50 * HOUR, 600)];
  const server = await mockApi(deps);
  const base = {
    GITHUB_API_URL: `http://127.0.0.1:${server.address().port}`, GITHUB_REPOSITORY: 'o/r', GITHUB_RUN_ID: '777',
    GITHUB_RUN_ATTEMPT: '1', GH_TOKEN: 'test-token', BUDGET_ENVIRONMENT: 'review-agent',
    WINDOW_START: iso(24 * HOUR), WINDOW_END: iso(-24 * HOUR), RUN_MAX: '3', MAX_ATTEMPTS: '1',
  };
  try {
    const ok = await runBudget(base);
    assert.equal(ok.code, 0, ok.out); // 3 in the window (the 50-hour-old one is outside), limit 3
    assert.ok(ok.out.includes('deployments counted: 3') && ok.out.includes('own deployment: 14'));
    assert.ok(!ok.out.includes('test-token'));
    assert.notEqual((await runBudget({ ...base, RUN_MAX: '2' })).code, 0, 'over the limit');
    assert.notEqual((await runBudget({ ...base, GITHUB_RUN_ATTEMPT: '2' })).code, 0, 'over the attempt cap');
    assert.notEqual((await runBudget({ ...base, GITHUB_RUN_ID: '778' })).code, 0, 'own deployment missing');
    assert.notEqual((await runBudget({ ...base, WINDOW_END: iso(HOUR) })).code, 0, 'window ended');
    assert.notEqual((await runBudget({ ...base, WINDOW_START: iso(-HOUR) })).code, 0, 'window not started');
    assert.notEqual((await runBudget({ ...base, WINDOW_START: '2026-11-01' })).code, 0, 'malformed window');
    assert.notEqual((await runBudget({ ...base, RUN_MAX: '' })).code, 0, 'unset limit');
    assert.notEqual((await runBudget({ ...base, GH_TOKEN: 'wrong' })).code, 0, 'API refused');
  } finally { server.close(); }
});

test('run budget: deployments from other refs or creators are counted and flagged, never filtered out', async () => {
  const deps = [dep(24, 1000, 801), dep(23, HOUR, null, { ref: 'refs/pull/5/merge' }), dep(22, 2 * HOUR, 790), dep(21, 3 * HOUR, 780)];
  const server = await mockApi(deps);
  const base = {
    GITHUB_API_URL: `http://127.0.0.1:${server.address().port}`, GITHUB_REPOSITORY: 'o/r', GITHUB_RUN_ID: '801',
    GITHUB_RUN_ATTEMPT: '1', GH_TOKEN: 'test-token', BUDGET_ENVIRONMENT: 'review-agent',
    WINDOW_START: iso(24 * HOUR), WINDOW_END: iso(-24 * HOUR), RUN_MAX: '3', MAX_ATTEMPTS: '1',
  };
  try {
    const r = await runBudget(base);
    assert.notEqual(r.code, 0, 'four deployments exceed 3 even though one is a pull request ref');
    assert.ok(r.out.includes('other 1'));
    const r4 = await runBudget({ ...base, RUN_MAX: '4' });
    assert.equal(r4.code, 0, r4.out);
    assert.ok(r4.out.includes('::warning::'));
  } finally { server.close(); }
});

test('run budget: a deleted deployment lowers the count (documented residual)', async () => {
  // Not a control: this pins the residual stated in ROUND-6.md. A token with
  // deployments write can delete inactive deployments; the counter then reads lower.
  const deps = [dep(34, 1000, 901), dep(32, 2 * HOUR, 890)];
  const server = await mockApi(deps);
  try {
    const r = await runBudget({
      GITHUB_API_URL: `http://127.0.0.1:${server.address().port}`, GITHUB_REPOSITORY: 'o/r', GITHUB_RUN_ID: '901',
      GITHUB_RUN_ATTEMPT: '1', GH_TOKEN: 'test-token', BUDGET_ENVIRONMENT: 'review-agent',
      WINDOW_START: iso(24 * HOUR), WINDOW_END: iso(-24 * HOUR), RUN_MAX: '2', MAX_ATTEMPTS: '1',
    });
    assert.equal(r.code, 0);
    // Deployment IDs are global, so a gap proves nothing. Detection is comparing
    // this list with an earlier run's printed list: an ID counted before and
    // missing now was deleted (the approver's audit, ROUND-6.md section 1).
    assert.ok(r.out.includes('counted IDs: 34,32'));
  } finally { server.close(); }
});

test('model proxy offline mode (dummy stage) refuses every allowlisted request before any upstream call', async () => {
  const { child, port, log } = startProxy({ MP_OFFLINE: '1', MP_SPEND_CAP_USD: '1' });
  await new Promise((r) => setTimeout(r, 600));
  try {
    const ph = { 'x-api-key': 'proof-placeholder-not-a-key' };
    const ok = { model: 'model-a', max_tokens: 10, messages: [] };
    assert.equal(await call(port, { headers: ph, body: ok }), 503);
    assert.equal(await call(port, { p: '/v1/messages/count_tokens', headers: ph, body: ok }), 503);
    assert.equal(await call(port, { p: '/v1/complete', headers: ph, body: ok }), 403); // allowlist still first
    assert.equal(await call(port, { headers: ph, body: { ...ok, max_tokens: 101 } }), 403); // max_tokens cap before offline
    assert.equal(await call(port, { headers: { 'x-api-key': 'other' }, body: ok }), 403); // client key before offline
    const text = fs.readFileSync(log, 'utf8');
    assert.ok(text.includes('"offline":true') && text.includes('offline stage'));
    assert.ok(!text.includes('"decision":"forwarded"') && !text.includes('upstream-error') && !text.includes('input count unavailable'));
  } finally { child.kill(); }
});

test('policy-guard: protected-path changes exit 3; other changes pass', () => {
  const d = tmp();
  const mk = (root) => {
    fs.mkdirSync(path.join(d, root, '.github', 'workflows'), { recursive: true });
    fs.mkdirSync(path.join(d, root, 'src'), { recursive: true });
    fs.writeFileSync(path.join(d, root, '.github', 'workflows', 'ci.yml'), 'name: ci\n');
    fs.writeFileSync(path.join(d, root, 'AGENTS.md'), 'policy\n');
    fs.writeFileSync(path.join(d, root, 'src', 'a.js'), '1\n');
  };
  const guard = (pr) => {
    try { execFileSync('bash', [script('policy-guard.sh'), path.join(d, 'base'), path.join(d, pr)], { stdio: 'pipe' }); return 0; }
    catch (e) { return e.status; }
  };
  for (const r of ['base', 'same', 'src', 'wf', 'newdir', 'agents', 'gone']) mk(r);
  fs.writeFileSync(path.join(d, 'src', 'src', 'a.js'), '2\n');
  fs.writeFileSync(path.join(d, 'wf', '.github', 'workflows', 'leak.yml'), 'on: push\n');
  fs.mkdirSync(path.join(d, 'newdir', '.cursor'));
  fs.writeFileSync(path.join(d, 'newdir', '.cursor', 'environment.json'), '{}');
  fs.writeFileSync(path.join(d, 'agents', 'AGENTS.md'), 'weakened\n');
  fs.unlinkSync(path.join(d, 'gone', 'AGENTS.md'));
  assert.equal(guard('same'), 0);
  assert.equal(guard('src'), 0);
  assert.equal(guard('wf'), 3);
  assert.equal(guard('newdir'), 3);
  assert.equal(guard('agents'), 3);
  assert.equal(guard('gone'), 3);
});

test('scan-dump hash-only mode (real key): the key on disk is only its SHA-256', () => {
  const d = tmp();
  const key = 'sk-ant-api03-HASHONLYTEST' + 'b'.repeat(80) + 'AA';
  const sha = require('node:crypto').createHash('sha256').update(key).digest('hex');
  fs.writeFileSync(path.join(d, 'canary'), `sha256:${sha}`);
  const run = (sub) => {
    try {
      const out = execFileSync(process.execPath, [script('probes', 'scan-dump.js'), path.join(d, sub)],
        { encoding: 'utf8', env: { ...process.env, CANARY_FILE: path.join(d, 'canary') } });
      return { code: 0, out };
    } catch (e) { return { code: e.status, out: String(e.stdout) }; }
  };
  fs.mkdirSync(path.join(d, 'clean', 'files'), { recursive: true });
  fs.writeFileSync(path.join(d, 'clean', 'files', '0'), 'nothing here');
  const clean = run('clean');
  assert.equal(clean.code, 0);
  assert.ok(clean.out.includes('hash-only') && clean.out.includes('exact substring matches: not run'));
  fs.mkdirSync(path.join(d, 'leak', 'files'), { recursive: true });
  fs.writeFileSync(path.join(d, 'leak', 'files', '0'), `env X=${key} trailing`);
  const leak = run('leak');
  assert.equal(leak.code, 1);
  assert.ok(leak.out.includes('hash matches (SHA-256 of candidate tokens == canary): 1') && !leak.out.includes(key));
});
