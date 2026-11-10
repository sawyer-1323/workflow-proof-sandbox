'use strict';

// Unit tests for the publish-side artifact validator and the S4 (d) cases.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const root = path.join(__dirname, '..');
const validator = path.join(root, 'scripts', 'validate-artifact.js');
const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);

function run(args) {
  try {
    return execFileSync(process.execPath, [validator, ...args], { encoding: 'utf8' }).split(' ')[0];
  } catch (e) {
    return String(e.stdout).split(' ')[0];
  }
}

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'artifact-'));
}

test('a well-formed review is valid', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'review.json'), JSON.stringify({
    schema: 'review/1', pr_number: 7, head_sha: HEAD, verdict: 'no findings', body: 'Verdict: no findings',
  }));
  assert.equal(run(['review', d, '--pr', '7', '--head', HEAD]), 'VALID');
});

test('a source-only patch is valid', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'change.patch'),
    'diff --git a/src/arith.js b/src/arith.js\n--- a/src/arith.js\n+++ b/src/arith.js\n@@ -1 +1 @@\n-a\n+b\n');
  fs.writeFileSync(path.join(d, 'summary.json'), JSON.stringify({
    schema: 'implement/1', task: 3, base_sha: BASE, branch: 'agent/x', expected_head: 'new', summary: 'ok',
  }));
  assert.equal(run(['patch', d, '--task', '3', '--base', BASE, '--branch', 'agent/x', '--expected-head', 'new']), 'VALID');
});

test('every hostile case gets its expected outcome', () => {
  const d = tmp();
  execFileSync(process.execPath, [path.join(root, 'scripts', 'probes', 'write-malicious-artifacts.js'), d, '7', HEAD, BASE]);
  const expected = fs.readFileSync(path.join(root, 'scripts', 'probes', 'malicious-cases.expected'), 'utf8')
    .trim().split('\n').map((l) => l.split(' '));
  for (const [name, kind, want] of expected) {
    const dir = path.join(d, 'cases', name);
    const got = kind === 'review'
      ? run(['review', dir, '--pr', '7', '--head', HEAD])
      : run(['patch', dir, '--task', '1', '--base', BASE, '--branch', 'agent/s4d', '--expected-head', 'new']);
    assert.equal(got, want, name);
  }
});
