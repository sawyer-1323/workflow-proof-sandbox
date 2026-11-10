#!/usr/bin/env node
'use strict';

// Validates an agent artifact in a PUBLISH job. The artifact is untrusted data:
// it is read, parsed and checked, and is never executed, sourced or
// interpolated into a shell command. Any doubt rejects it.
// Output never echoes agent-controlled text: REJECT lines carry a fixed reason,
// VALID lines carry counts only.
//
// Usage:
//   validate-artifact.js review <dir> --pr <n> --head <sha> [--forbid-file <f>]
//   validate-artifact.js patch  <dir> --task <n> --base <sha> --branch <b> --expected-head <new|sha> [--forbid-file <f>]
// --forbid-file: one known value per line (canaries, the placeholder key). The
//   artifact is rejected if any value appears raw, lower-cased, reversed, hex,
//   base64 (standard or URL-safe, any alignment), percent-encoded, or split by
//   separators within or across fields. Other encodings are NOT detected.
// Exit 0: valid. Exit 1: rejected. Exit 2: usage error.

const fs = require('node:fs');
const path = require('node:path');

const LIMITS = { reviewJson: 16 * 1024, reviewBody: 4000, summaryJson: 4 * 1024, summaryText: 1000, patch: 512 * 1024 };
const SHA_RE = /^[0-9a-f]{40}$/;
const BRANCH_RE = /^agent\/[a-z0-9][a-z0-9._-]{0,60}$/;
const TEXT_RE = /^[\x20-\x7e\n\t]*$/; // printable ASCII, newline, tab
const SECRET_RES = [
  new RegExp('(ghs|ghp|gho|ghu|ghr)_' + '[A-Za-z0-9]{20,}'),
  new RegExp('github_pat_' + '[A-Za-z0-9_]{20,}'),
  new RegExp('sk-' + 'ant-' + '[A-Za-z0-9_-]{10,}'),
  new RegExp('-----BEGIN' + '[A-Z ]*PRIVATE KEY'),
  new RegExp('MIIE[A-Za-z0-9+/]{2}' + 'IBAAKCAQEA'),
  new RegExp('AKIA' + '[0-9A-Z]{16}'),
];
const ALLOWED_PREFIXES = ['src/', 'test/', 'docs/', 'README.md'];
const DENIED_PREFIXES = ['.github/', '.git/', '.claude/', 'spec/', 'test/golden/', 'scripts/', 'toolchain/', 'docs/guides/'];
const DENIED_FILES = ['test/golden.test.js', 'AGENTS.md', 'CLAUDE.md', '.gitattributes', '.gitmodules', '.mcp.json', 'package.json', 'package-lock.json'];

class Reject extends Error {}
const reject = (msg) => { throw new Reject(msg); };

// ---- encoded-value detection ----
const strip = (s) => s.replace(/[^A-Za-z0-9]/g, '');
function variants(needle) {
  const b = Buffer.from(needle, 'utf8');
  const out = new Set([needle, needle.toLowerCase(), [...needle].reverse().join(''),
    b.toString('hex'), b.toString('hex').toUpperCase(),
    encodeURIComponent(needle), [...b].map((x) => '%' + x.toString(16).padStart(2, '0')).join(''),
    [...b].map((x) => '%' + x.toString(16).padStart(2, '0').toUpperCase()).join('')]);
  for (let pad = 0; pad < 3; pad++) {
    const enc = Buffer.concat([Buffer.alloc(pad, 0x41), b]).toString('base64');
    const skip = Math.ceil((pad * 4) / 3);
    const core = enc.slice(skip + 1, enc.replace(/=+$/, '').length - 2); // the alignment-independent middle
    if (core.length >= 8) { out.add(core); out.add(core.replace(/\+/g, '-').replace(/\//g, '_')); }
  }
  return [...out].filter((v) => v.length >= 6);
}
function findEncoded(texts, needles) {
  const all = texts.join('\n');
  const hay = [...texts, all, all.toLowerCase(), strip(all), strip(all).toLowerCase()];
  for (const n of needles) {
    if (n.length < 8) continue;
    const vs = variants(n);
    const vsStripped = vs.map(strip).filter((v) => v.length >= 6);
    for (const h of hay) {
      if (vs.some((v) => h.includes(v)) || vsStripped.some((v) => h.includes(v))) return true;
    }
    // Split anywhere: both pieces (each at least 8 alphanumerics) present in the
    // stripped text of all fields, in either order.
    const ns = strip(n);
    const hs = strip(all).toLowerCase();
    for (let k = 8; k <= ns.length - 8; k++) {
      if (hs.includes(ns.slice(0, k).toLowerCase()) && hs.includes(ns.slice(k).toLowerCase())) return true;
    }
  }
  return false;
}
function readForbid(file) {
  if (!file) return [];
  return fs.readFileSync(file, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l.length >= 8);
}

// ---- helpers ----
function parseArgs(argv) {
  const [kind, dir, ...rest] = argv;
  const opts = {};
  for (let i = 0; i < rest.length; i += 2) {
    if (!rest[i].startsWith('--') || rest[i + 1] === undefined) return null;
    opts[rest[i].slice(2)] = rest[i + 1];
  }
  return { kind, dir, opts };
}
function readExact(dir, expected) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { reject('artifact directory missing'); }
  const names = entries.map((e) => e.name).sort();
  const want = Object.keys(expected).sort();
  if (JSON.stringify(names) !== JSON.stringify(want)) reject(`unexpected set of files (${names.length} present, ${want.length} expected)`);
  const out = {};
  for (const e of entries) {
    const p = path.join(dir, e.name);
    const st = fs.lstatSync(p);
    if (!st.isFile() || st.isSymbolicLink()) reject('an entry is not a regular file');
    if (st.size > expected[e.name]) reject('a file exceeds its size limit');
    const buf = fs.readFileSync(p);
    const text = buf.toString('utf8');
    if (Buffer.from(text, 'utf8').compare(buf) !== 0) reject('a file is not valid UTF-8');
    out[e.name] = text;
  }
  return out;
}
function parseJsonObject(text, keys) {
  let v;
  try { v = JSON.parse(text); } catch { reject('JSON does not parse'); }
  if (v === null || typeof v !== 'object' || Array.isArray(v)) reject('JSON is not an object');
  if (JSON.stringify(Object.keys(v).sort()) !== JSON.stringify([...keys].sort())) reject('JSON keys are not exactly the schema keys');
  return v;
}
function checkText(s, max) {
  if (typeof s !== 'string') reject('a text field is not a string');
  if (s.length > max) reject('a text field exceeds its length limit');
  if (!TEXT_RE.test(s)) reject('a text field has characters outside printable ASCII');
  for (const re of SECRET_RES) if (re.test(s)) reject('a text field contains a credential-shaped string');
}

// ---- kinds ----
function validateReview(dir, opts) {
  if (!/^\d{1,7}$/.test(opts.pr || '') || !SHA_RE.test(opts.head || '')) return null;
  const files = readExact(dir, { 'review.json': LIMITS.reviewJson });
  const r = parseJsonObject(files['review.json'], ['schema', 'pr_number', 'head_sha', 'verdict', 'body']);
  if (r.schema !== 'review/1') reject('schema');
  if (r.pr_number !== Number(opts.pr)) reject('pr_number does not match the event');
  if (r.head_sha !== opts.head) reject('head_sha does not match the event');
  if (!['no findings', 'findings', 'no result'].includes(r.verdict)) reject('verdict is not an allowed value');
  checkText(r.body, LIMITS.reviewBody);
  if (findEncoded([r.body], readForbid(opts['forbid-file']))) reject('a forbidden value appears (raw or encoded)');
  return `review: verdict ${JSON.stringify(r.verdict)}, body ${r.body.length} chars`;
}

function checkPatchPath(p) {
  if (!p || p.length > 200) reject('a path is empty or too long');
  if (p.startsWith('/') || p.includes('\\') || p.includes('\0') || p.split('/').some((s) => s === '..' || s === '.' || s === '')) reject('an unsafe path');
  if (!/^[A-Za-z0-9._\-/]+$/.test(p)) reject('a path has unexpected characters');
  if (DENIED_FILES.includes(p) || DENIED_PREFIXES.some((d) => p.startsWith(d))) reject('a protected path');
  if (!ALLOWED_PREFIXES.some((a) => (a.endsWith('/') ? p.startsWith(a) : p === a))) reject('a path outside the allowed set');
}

function validatePatch(dir, opts) {
  if (!/^\d{1,7}$/.test(opts.task || '') || !SHA_RE.test(opts.base || '') || !BRANCH_RE.test(opts.branch || '')
    || !(opts['expected-head'] === 'new' || SHA_RE.test(opts['expected-head'] || ''))) return null;
  const files = readExact(dir, { 'change.patch': LIMITS.patch, 'summary.json': LIMITS.summaryJson });
  const s = parseJsonObject(files['summary.json'], ['schema', 'task', 'base_sha', 'branch', 'expected_head', 'summary']);
  if (s.schema !== 'implement/1') reject('schema');
  if (s.task !== Number(opts.task) || s.base_sha !== opts.base || s.branch !== opts.branch || s.expected_head !== opts['expected-head']) reject('summary does not match the dispatch');
  checkText(s.summary, LIMITS.summaryText);

  const patch = files['change.patch'];
  if (findEncoded([s.summary, patch], readForbid(opts['forbid-file']))) reject('a forbidden value appears (raw or encoded)');
  if (patch.length === 0) return 'patch: empty';
  for (const re of SECRET_RES) if (re.test(patch)) reject('the patch contains a credential-shaped string');
  if (/^GIT binary patch$/m.test(patch) || /^Binary files /m.test(patch)) reject('a binary patch');
  if (/^(old|new|new file|deleted file) mode (?!100644$)\d+$/m.test(patch)) reject('a file mode other than 100644');
  if (/^(rename|copy) (from|to) /m.test(patch)) reject('a rename or copy');
  const touched = new Set();
  const header = /^diff --git a\/(\S+) b\/(\S+)$/gm;
  let m, count = 0;
  while ((m = header.exec(patch)) !== null) {
    count++;
    if (m[1] !== m[2]) reject('a and b paths differ');
    checkPatchPath(m[1]);
    touched.add(m[1]);
  }
  const lines = patch.split('\n');
  if (lines.filter((l) => l.startsWith('diff ')).length !== count) reject('a diff header has an unexpected form');
  for (const line of lines) {
    let p = null;
    if (line.startsWith('--- a/') || line.startsWith('+++ b/')) p = line.slice(6);
    else if (line.startsWith('--- ') || line.startsWith('+++ ')) p = line.slice(4) === '/dev/null' ? null : '';
    if (p !== null && !touched.has(p)) reject('a file line names an unchecked path');
  }
  if (count === 0) reject('no diff headers');
  if (count > 50) reject('too many files');
  return `patch: ${count} file(s), ${patch.length} bytes`;
}

function main() {
  const a = parseArgs(process.argv.slice(2));
  if (!a) { console.error('usage error'); process.exit(2); }
  try {
    const result = a.kind === 'review' ? validateReview(a.dir, a.opts)
      : a.kind === 'patch' ? validatePatch(a.dir, a.opts) : null;
    if (result === null) { console.error('usage error'); process.exit(2); }
    console.log(`VALID  ${result}`);
  } catch (e) {
    if (e instanceof Reject) { console.log(`REJECT ${e.message}`); process.exit(1); }
    console.log('REJECT internal error'); process.exit(1);
  }
}

if (require.main === module) main();
module.exports = { validateReview, validatePatch, findEncoded, variants, Reject };
