#!/usr/bin/env node
'use strict';

// Packages the agent's output into the artifact schema, in the AGENT job, as the
// runner user, after every agent process has been killed. It reduces free text
// to the schema: printable ASCII (other characters become '?') and a length cap.
// It prints counts only.
//
//   package-output.js review <claude.json> <pr> <head-sha> <out-dir>
//   package-output.js patch  <claude.json> <change.patch> <task> <base> <branch> <expected-head> <out-dir>

const fs = require('node:fs');
const path = require('node:path');

const ascii = (s, max) => String(s).replace(/[^\x20-\x7e\n\t]/g, '?').slice(0, max);
function resultText(file) {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.size > 1024 * 1024) return '';
    const j = JSON.parse(fs.readFileSync(file, 'utf8'));
    return j && typeof j === 'object' && typeof j.result === 'string' ? j.result : ''; // [U] CLI JSON layout
  } catch { return ''; }
}

const [kind, ...a] = process.argv.slice(2);
if (kind === 'review' && a.length === 4) {
  const [claude, pr, head, outDir] = a;
  const body = ascii(resultText(claude), 4000);
  const first = body.split('\n')[0];
  const verdict = first.startsWith('Verdict: no findings') ? 'no findings' : first.startsWith('Verdict: findings') ? 'findings' : 'no result';
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'review.json'), JSON.stringify({ schema: 'review/1', pr_number: Number(pr), head_sha: head, verdict, body }));
  console.log(`packaged review: verdict ${JSON.stringify(verdict)}, ${body.length} chars`);
} else if (kind === 'patch' && a.length === 7) {
  const [claude, patch, task, base, branch, eh, outDir] = a;
  fs.mkdirSync(outDir, { recursive: true });
  const st = fs.lstatSync(patch);
  if (!st.isFile()) { console.log('packaged patch: refused (not a regular file)'); process.exit(1); }
  fs.copyFileSync(patch, path.join(outDir, 'change.patch'));
  const summary = ascii(resultText(claude), 1000);
  fs.writeFileSync(path.join(outDir, 'summary.json'), JSON.stringify({ schema: 'implement/1', task: Number(task), base_sha: base, branch, expected_head: eh, summary }));
  console.log(`packaged patch: ${st.size} bytes, summary ${summary.length} chars`);
} else {
  console.error('usage error'); process.exit(2);
}
