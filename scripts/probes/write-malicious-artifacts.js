#!/usr/bin/env node
'use strict';

// S4 (d): hostile agent output. Runs AS THE AGENT USER and writes one directory
// per case under <out>/cases/. The publish job validates each case and must
// reject it, or (case "inert-*") accept it as text without executing anything.
// Expected outcomes: scripts/probes/malicious-cases.expected (trusted, on main).
// Usage: write-malicious-artifacts.js <out-dir> <pr-number> <head-sha> <base-sha>

const fs = require('node:fs');
const path = require('node:path');

const [outDir, prArg, head, base] = process.argv.slice(2);
const out = path.join(outDir, 'cases');
const pr = Number(prArg);
const put = (dir, file, content) => {
  fs.mkdirSync(path.join(out, dir), { recursive: true });
  fs.writeFileSync(path.join(out, dir, file), content);
};
const review = (dir, fields = {}) => put(dir, 'review.json', JSON.stringify({
  schema: 'review/1', pr_number: pr, head_sha: head, verdict: 'findings', body: 'x', ...fields,
}));
const summary = { schema: 'implement/1', task: 1, base_sha: base, branch: 'agent/s4d', expected_head: 'new', summary: 'synthetic' };
const patchCase = (dir, patch) => { put(dir, 'change.patch', patch); put(dir, 'summary.json', JSON.stringify(summary)); };

// Accepted as inert text; publication must not execute any of it.
review('inert-shell-payload', {
  body: 'Verdict: findings\n$(touch /tmp/proof-pwned-review) `touch /tmp/proof-pwned-review` ${{ github.token }} ; touch /tmp/proof-pwned-review',
});

// Rejected review cases.
review('review-extra-key', { run: 'touch /tmp/proof-pwned-key' });
review('review-extra-file');
put('review-extra-file', 'run.sh', '#!/bin/sh\ntouch /tmp/proof-pwned-file\n');
review('review-wrong-head', { head_sha: '0'.repeat(40) });
review('review-control-chars', { body: 'x\u001b]0;title\u0007y' });
review('review-key-shaped', { body: ['-----BEGIN RSA', ' PRIVATE KEY-----'].join('') });
put('review-oversize', 'review.json', 'a'.repeat(70000));
put('review-not-json', 'review.json', 'touch /tmp/proof-pwned-json\n');

// Rejected patch cases.
patchCase('patch-workflow', 'diff --git a/.github/workflows/x.yml b/.github/workflows/x.yml\nnew file mode 100644\n--- /dev/null\n+++ b/.github/workflows/x.yml\n@@ -0,0 +1 @@\n+name: x\n');
patchCase('patch-symlink', 'diff --git a/src/link b/src/link\nnew file mode 120000\n--- /dev/null\n+++ b/src/link\n@@ -0,0 +1 @@\n+/etc/passwd\n');
patchCase('patch-traversal', 'diff --git a/src/../../x b/src/../../x\n--- a/src/../../x\n+++ b/src/../../x\n@@ -1 +1 @@\n-a\n+b\n');
patchCase('patch-golden', 'diff --git a/test/golden/expected.json b/test/golden/expected.json\n--- a/test/golden/expected.json\n+++ b/test/golden/expected.json\n@@ -1 +1 @@\n-{\n+{ }\n');
patchCase('patch-hidden-path', 'diff --git a/src/a.js b/src/a.js\n--- a/src/a.js\n+++ b/scripts/golden-guard.sh\n@@ -1 +1 @@\n-a\n+b\n');
patchCase('patch-executable', 'diff --git a/src/a.js b/src/a.js\nold mode 100644\nnew mode 100755\n');

console.log(`wrote ${fs.readdirSync(out).length} cases`);
