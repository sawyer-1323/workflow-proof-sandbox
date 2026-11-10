#!/usr/bin/env node
'use strict';

// Encrypts agent output before it becomes a (public) workflow artifact, and
// decrypts it in the publish job. Hybrid: a random AES-256-GCM key, wrapped with
// RSA-OAEP-SHA256 to the public key committed at .github/proof/artifact-public.pem.
// The private half exists only as the ARTIFACT_PRIVATE_KEY secret of the publish
// environments (`review`, `probe`) and with the approver.
//
//   artifact-crypt.js encrypt <public-key.pem> <in-dir> <out-file>
//   artifact-crypt.js decrypt <in-file> <out-dir>      (env ARTIFACT_PRIVATE_KEY)
//
// Decryption treats the content as data: it writes regular files only, under
// relative paths matching a strict pattern, at most 4 levels deep, 600 files and
// 2 MiB in total. It never executes anything and prints counts only.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const MAX_TOTAL = 2 * 1024 * 1024;
const MAX_FILES = 600;
const REL_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+){0,3}$/;

function walk(dir, base = dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, base, out);
    else if (e.isFile()) out.push(path.relative(base, p).split(path.sep).join('/'));
  }
  return out;
}

function encrypt(pubFile, inDir, outFile) {
  const files = {};
  let total = 0;
  for (const rel of walk(inDir)) {
    if (!REL_RE.test(rel) || rel.split('/').includes('..')) throw new Error('bad path');
    const b = fs.readFileSync(path.join(inDir, rel));
    total += b.length;
    files[rel] = b.toString('base64');
  }
  if (total > MAX_TOTAL || Object.keys(files).length > MAX_FILES) throw new Error('too large');
  const plain = Buffer.from(JSON.stringify({ v: 1, files }), 'utf8');
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  const pub = crypto.createPublicKey(fs.readFileSync(pubFile));
  const wrapped = crypto.publicEncrypt({ key: pub, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, key);
  fs.writeFileSync(outFile, JSON.stringify({
    v: 1, alg: 'RSA-OAEP-256+A256GCM', key: wrapped.toString('base64'), iv: iv.toString('base64'),
    tag: c.getAuthTag().toString('base64'), ct: ct.toString('base64'),
  }));
  console.log(`encrypted ${Object.keys(files).length} file(s), ${total} bytes`);
}

function decrypt(inFile, outDir) {
  const pem = process.env.ARTIFACT_PRIVATE_KEY;
  if (!pem) throw new Error('ARTIFACT_PRIVATE_KEY missing');
  const st = fs.lstatSync(inFile);
  if (!st.isFile() || st.size > 4 * MAX_TOTAL) throw new Error('bad envelope file');
  const env = JSON.parse(fs.readFileSync(inFile, 'utf8'));
  if (env.v !== 1 || env.alg !== 'RSA-OAEP-256+A256GCM') throw new Error('bad envelope');
  const key = crypto.privateDecrypt({ key: crypto.createPrivateKey(pem), padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(env.key, 'base64'));
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(env.iv, 'base64'));
  d.setAuthTag(Buffer.from(env.tag, 'base64'));
  const plain = JSON.parse(Buffer.concat([d.update(Buffer.from(env.ct, 'base64')), d.final()]).toString('utf8'));
  if (plain.v !== 1 || !plain.files || typeof plain.files !== 'object') throw new Error('bad payload');
  const entries = Object.entries(plain.files);
  if (entries.length > MAX_FILES) throw new Error('too many files');
  let total = 0;
  fs.mkdirSync(outDir, { recursive: true, mode: 0o700 });
  for (const [rel, b64] of entries) {
    if (typeof rel !== 'string' || !REL_RE.test(rel) || rel.split('/').some((s) => s === '..' || s === '.')) throw new Error('bad path');
    const b = Buffer.from(String(b64), 'base64');
    total += b.length;
    if (total > MAX_TOTAL) throw new Error('too large');
    const dest = path.join(outDir, ...rel.split('/'));
    fs.mkdirSync(path.dirname(dest), { recursive: true, mode: 0o700 });
    fs.writeFileSync(dest, b, { mode: 0o600, flag: 'wx' });
  }
  console.log(`decrypted ${entries.length} file(s), ${total} bytes`);
}

try {
  const [cmd, a, b, c] = process.argv.slice(2);
  if (cmd === 'encrypt' && a && b && c) encrypt(a, b, c);
  else if (cmd === 'decrypt' && a && b) decrypt(a, b);
  else { console.error('usage: artifact-crypt.js encrypt <pub> <in-dir> <out> | decrypt <in> <out-dir>'); process.exit(2); }
} catch (e) {
  console.log(`artifact-crypt: refused (${e.message === 'bad path' || e.message === 'too large' || e.message.startsWith('bad') || e.message.startsWith('too') || e.message.endsWith('missing') ? e.message : 'decryption or parse failure'})`);
  process.exit(1);
}
