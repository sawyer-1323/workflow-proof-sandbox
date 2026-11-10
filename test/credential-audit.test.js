'use strict';

// Revision 8: credential-audit.sh, its pinned-fixture exemption, and what it must still flag.
// Runs the script's `selftest` profile on throwaway directories only. Every credential-shaped
// value is built at run time, so this file contains none (and needs no allowlist entry).

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const AUDIT = path.join(__dirname, '..', 'scripts', 'probes', 'credential-audit.sh');
const REPO_ALLOW = path.join(__dirname, '..', 'scripts', 'probes', 'credential-audit.allow');
const TOKEN = 'gh' + 'p_' + 'S'.repeat(36);                       // GitHub-token-shaped, synthetic
const KEY = ['-----BEGIN', ' RSA PRIVATE', ' KEY-----'].join('') + '\nAAAA\n';
// Paths as bash sees them. On Windows (Git Bash, local runs only) C:\x becomes /c/x, so the
// colon-separated AUDIT_* lists stay unambiguous. On Linux, paths are unchanged.
const posix = (p) => (process.platform === 'win32' ? p.replace(/^([A-Za-z]):/, (m, d) => '/' + d.toLowerCase()).replace(/\\/g, '/') : p);
const blob = (buf) => crypto.createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${buf.length}\0`), buf])).digest('hex');

function world() {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-'));
  const root = path.join(base, 'repo');                             // the repository root (pinned paths are relative to it)
  const home = path.join(base, 'home');
  const tmp = path.join(base, 'tmp');                               // stands in for /tmp and RUNNER_TEMP
  for (const d of [root, home, tmp]) fs.mkdirSync(d, { recursive: true });
  const fixture = Buffer.from(`const shaped = '${TOKEN}'; // synthetic\n`);
  fs.mkdirSync(path.join(root, 'test'), { recursive: true });
  fs.writeFileSync(path.join(root, 'test', 'fixture.js'), fixture);
  const allow = path.join(base, 'allow');
  fs.writeFileSync(allow, `# pinned\n${blob(fixture)} test/fixture.js\n`);
  return { base, root, home, tmp, allow, fixture };
}
function audit(w, extraEnv = {}) {
  const env = {
    PATH: process.env.PATH, HOME: posix(w.home),
    AUDIT_REPO_ROOT: posix(w.root), AUDIT_ALLOW_FILE: posix(w.allow),
    AUDIT_SCAN_DIRS: [w.home, w.root].map(posix).join(':'), AUDIT_TMP_DIRS: posix(w.tmp), ...extraEnv,
  };
  const r = spawnSync('bash', [AUDIT, 'selftest'], { env, encoding: 'utf8' });
  return { code: r.status, out: r.stdout + r.stderr };
}

test('clean directories pass', () => {
  const w = world(); fs.rmSync(path.join(w.root, 'test', 'fixture.js'));
  const r = audit(w);
  assert.equal(r.code, 0, r.out); assert.match(r.out, /== result: PASS/);
});

test('a pinned fixture at its exact path and blob is exempt, and listed', () => {
  const w = world(); const r = audit(w);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /INFO {3}pinned fixtures exempt under .*: test\/fixture\.js/);
});

test('an UNEXPECTED synthetic credential is still flagged', () => {
  const w = world();
  fs.writeFileSync(path.join(w.root, 'src-config.js'), `module.exports = { token: '${TOKEN}' };\n`);
  const r = audit(w);
  assert.equal(r.code, 1, r.out);
  assert.match(r.out, /FOUND {2}token-shaped strings under .*src-config\.js/);
  assert.match(r.out, /== result: FAIL/);
});

test('the same fixture relocated inside the repository is flagged', () => {
  const w = world();
  fs.mkdirSync(path.join(w.root, 'other'));
  fs.copyFileSync(path.join(w.root, 'test', 'fixture.js'), path.join(w.root, 'other', 'fixture.js'));
  const r = audit(w);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /FOUND .*other\/fixture\.js/);
});

test('the fixture edited at its pinned path is flagged', () => {
  const w = world();
  fs.appendFileSync(path.join(w.root, 'test', 'fixture.js'), '// one more line\n');
  const r = audit(w);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /FOUND .*test\/fixture\.js/);
});

test('a copy in a temporary directory is never exempt, even at the pinned relative path', () => {
  const w = world();
  fs.mkdirSync(path.join(w.tmp, 'test'));
  fs.copyFileSync(path.join(w.root, 'test', 'fixture.js'), path.join(w.tmp, 'test', 'fixture.js'));
  const r = audit(w);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /FOUND {2}token-shaped strings under \S*tmp: \S*tmp\/test\/fixture\.js/);
  // Even if the temporary directory were the repository root, temporary scans grant no exemption.
  const r2 = audit(w, { AUDIT_REPO_ROOT: posix(w.tmp), AUDIT_SCAN_DIRS: '', AUDIT_TMP_DIRS: posix(w.tmp) });
  assert.equal(r2.code, 1, r2.out); assert.doesNotMatch(r2.out, /exempt/);
});

test('private key material in a temporary directory is flagged (the CI failure mode)', () => {
  const w = world();
  fs.mkdirSync(path.join(w.tmp, 'artifact-x', 'cases'), { recursive: true });
  fs.writeFileSync(path.join(w.tmp, 'artifact-x', 'cases', 'review.json'), JSON.stringify({ body: KEY }));
  const r = audit(w);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /FOUND {2}private key material under .*review\.json/);
});

test('a token-shaped environment variable is flagged', () => {
  const w = world(); const r = audit(w, { SOME_VALUE: TOKEN });
  assert.equal(r.code, 1, r.out); assert.match(r.out, /FOUND {2}token-shaped value in env var SOME_VALUE/);
});

test('a stale allowlist (blob does not match) exempts nothing', () => {
  const w = world();
  fs.writeFileSync(w.allow, `${'0'.repeat(40)} test/fixture.js\n`);
  const r = audit(w);
  assert.equal(r.code, 1, r.out);
});

test('a duplicated allowlist entry exempts nothing', () => {
  const w = world();
  fs.appendFileSync(w.allow, fs.readFileSync(w.allow, 'utf8').split('\n')[1] + '\n');
  const r = audit(w);
  assert.equal(r.code, 1, r.out);
});

test('more than twenty hits are all counted', () => {
  const w = world();
  for (let i = 0; i < 25; i++) fs.writeFileSync(path.join(w.root, `f${i}.txt`), TOKEN);
  const r = audit(w);
  assert.equal(r.code, 1, r.out); assert.match(r.out, /\(\+5 more\)/);
});

test('the repository allowlist pins exactly the two reviewed fixtures, at their current blobs', () => {
  const lines = fs.readFileSync(REPO_ALLOW, 'utf8').split('\n').filter((l) => l && !l.startsWith('#'));
  const entries = lines.map((l) => l.split(' '));
  assert.deepEqual(entries.map((e) => e[1]).sort(), ['scripts/make-dummy-key.sh', 'test/proof-controls.test.js']);
  for (const [sha, rel] of entries) {
    assert.equal(blob(fs.readFileSync(path.join(__dirname, '..', rel))), sha, `${rel} changed: update the pin in a reviewed change`);
  }
});

test('an unknown profile is a usage error, and selftest needs its roots', () => {
  assert.equal(spawnSync('bash', [AUDIT, 'nope'], { encoding: 'utf8' }).status, 2);
  assert.notEqual(spawnSync('bash', [AUDIT, 'selftest'], { env: { PATH: process.env.PATH }, encoding: 'utf8' }).status, 0);
});
