#!/usr/bin/env node
'use strict';

// S5, trace side. Run by the approver (or the agent session, read-only) AFTER an
// S5 run, on everything a public viewer could see for that run: the extracted
// job logs (GET /repos/{owner}/{repo}/actions/runs/{id}/logs), the check-run
// annotations (GET .../check-runs/{id}/annotations, saved as JSON), and the
// downloaded artifact files (which must be encrypted envelopes only).
// Searches every file for the forbidden values in every encoding the validator
// detects. Prints file names and counts only, never a value.
// Usage: scan-public-channels.js <forbid-file> <dir-or-file> [...]

const fs = require('node:fs');
const path = require('node:path');
const { findEncoded } = require('../validate-artifact.js');

const [forbidFile, ...targets] = process.argv.slice(2);
const needles = fs.readFileSync(forbidFile, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l.length >= 8);
let files = 0, hits = 0, plaintextArtifacts = 0;
function scan(p) {
  const st = fs.lstatSync(p);
  if (st.isDirectory()) { for (const e of fs.readdirSync(p)) scan(path.join(p, e)); return; }
  if (!st.isFile()) return;
  files++;
  const text = fs.readFileSync(p).toString('latin1');
  if (findEncoded([text], needles)) { hits++; console.log(`FOUND  forbidden value in ${p}`); }
  if (/\.(json)$/.test(p) && /"(review|summary|body|files)"/.test(text) && !/"alg":"RSA-OAEP-256\+A256GCM"/.test(text)) {
    plaintextArtifacts++; console.log(`FOUND  plaintext agent output in ${p}`);
  }
}
for (const t of targets) scan(t);
console.log(`scanned ${files} file(s); forbidden-value hits ${hits}; plaintext artifacts ${plaintextArtifacts}`);
console.log(`== S5 public-channel result: ${hits === 0 && plaintextArtifacts === 0 ? 'PASS' : 'FAIL'}`);
process.exit(hits === 0 && plaintextArtifacts === 0 ? 0 : 1);
