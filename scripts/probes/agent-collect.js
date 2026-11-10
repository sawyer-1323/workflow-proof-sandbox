#!/usr/bin/env node
'use strict';

// M1 / S4(b) collection half. Runs AS THE AGENT USER. It does NOT hold the
// dummy canary or its hash: it only collects everything the agent identity can
// read into a dump, and records the privilege checks. A later root step
// (scan-dump.js) scans the dump for the dummy. This keeps the detector and the
// secret out of the agent process entirely.
//
// Collected into <DUMP_DIR> (one file per source, bounded):
//   proc/<pid>.environ, .cmdline, .maps, .mem (first slice of each readable
//     region), for every /proc/<pid> the agent can read; modelproxy's are the
//     ones that matter, but all are taken;
//   files/<n>  every agent-readable regular file across the roots below, size-
//     capped, with an index naming each path;
//   own-env    this process's own environment;
//   job/       $GITHUB_OUTPUT, $GITHUB_ENV, $GITHUB_STATE, $GITHUB_STEP_SUMMARY
//     copied if the agent can read them, each with its octal mode recorded.
// Privilege findings (no dummy needed) are printed here directly.
// Usage: DUMP_DIR=/path agent-collect.js

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const DUMP = process.env.DUMP_DIR;
if (!DUMP) { console.error('DUMP_DIR required'); process.exit(2); }
fs.mkdirSync(path.join(DUMP, 'proc'), { recursive: true });
fs.mkdirSync(path.join(DUMP, 'files'), { recursive: true });
fs.mkdirSync(path.join(DUMP, 'job'), { recursive: true });

const me = process.getuid();
const notes = [];
const findings = [];
const note = (m) => notes.push(m);
const flag = (m) => findings.push(m);
const MAX_FILE = 4 * 1024 * 1024;
const MAX_REGION = 64 * 1024 * 1024;
let memBudget = 1024 * 1024 * 1024;

// Own environment.
fs.writeFileSync(path.join(DUMP, 'own-env'),
  Object.entries(process.env).map(([k, v]) => `${k}=${v}`).join('\n'));

// /proc entries.
const pids = fs.readdirSync('/proc').filter((d) => /^\d+$/.test(d));
let otherEnv = 0, otherMem = 0, taken = 0;
for (const pid of pids) {
  let uid; try { uid = fs.statSync(`/proc/${pid}`).uid; } catch { continue; }
  const mine = uid === me;
  for (const f of ['environ', 'cmdline', 'maps']) {
    try {
      const b = fs.readFileSync(`/proc/${pid}/${f}`);
      fs.writeFileSync(path.join(DUMP, 'proc', `${pid}.${f}`), b);
      taken++;
      if (!mine && f === 'environ') { otherEnv++; flag(`can read environ of pid ${pid} (uid ${uid})`); }
    } catch { /* not readable */ }
  }
  if (Number(pid) === process.pid) continue;
  let fd; try { fd = fs.openSync(`/proc/${pid}/mem`, 'r'); } catch { continue; }
  if (!mine) { otherMem++; flag(`can open memory of pid ${pid} (uid ${uid})`); }
  try {
    const out = fs.openSync(path.join(DUMP, 'proc', `${pid}.mem`), 'w');
    for (const line of fs.readFileSync(`/proc/${pid}/maps`, 'utf8').split('\n')) {
      const m = /^([0-9a-f]+)-([0-9a-f]+) r/.exec(line);
      if (!m) continue;
      const start = BigInt('0x' + m[1]);
      const len = Number(BigInt('0x' + m[2]) - start);
      if (len <= 0 || len > MAX_REGION || memBudget <= 0) continue;
      const buf = Buffer.alloc(Math.min(len, memBudget));
      try { const n = fs.readSync(fd, buf, 0, buf.length, start); if (n > 0) { fs.writeSync(out, buf, 0, n); memBudget -= n; } } catch { /* unreadable region */ }
    }
    fs.closeSync(out);
  } catch { /* exited */ }
  fs.closeSync(fd);
}
note(`proc entries captured: ${taken}; other-user environ readable ${otherEnv}, mem readable ${otherMem}`);

// Agent-readable files.
const roots = ['/home', '/tmp', '/var/tmp', '/run', '/etc', '/opt', '/var/lib', '/root', '/home/runner/work/_temp'];
const index = [];
let nfile = 0;
function walk(dir, depth) {
  if (depth > 12 || nfile > 200000) return;
  let entries; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) continue;
    if (p === DUMP) continue; // never recurse into our own dump
    if (e.isDirectory()) { if (!['node_modules', 'proc', 'sys'].includes(e.name)) walk(p, depth + 1); continue; }
    if (!e.isFile()) continue;
    let st; try { st = fs.statSync(p); } catch { continue; }
    if (st.size > MAX_FILE) continue;
    let b; try { b = fs.readFileSync(p); } catch { continue; }
    fs.writeFileSync(path.join(DUMP, 'files', String(nfile)), b);
    index.push(`${nfile}\t${p}`);
    nfile++;
  }
}
for (const r of roots) walk(r, 0);
fs.writeFileSync(path.join(DUMP, 'files', 'index.tsv'), index.join('\n'));
for (const d of ['/home/runner', '/home/runner/work', '/home/runner/work/_temp']) {
  try { fs.readdirSync(d); flag(`can list ${d}`); } catch { /* expected */ }
}
note(`agent-readable files captured: ${nfile}`);

// Job output files.
for (const v of ['GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_STATE', 'GITHUB_STEP_SUMMARY']) {
  const p = process.env[v];
  if (!p) { note(`${v} not set in the agent env`); continue; }
  let mode = '?'; try { mode = (fs.statSync(p).mode & 0o777).toString(8); } catch { /* gone */ }
  try {
    const b = fs.readFileSync(p);
    fs.writeFileSync(path.join(DUMP, 'job', v), b);
    flag(`agent can read ${v} (mode ${mode}, ${b.length} bytes)`);
  } catch { note(`${v}: not readable by the agent (mode ${mode})`); }
}

// Privilege (no dummy needed).
if (spawnSync('sudo', ['-n', 'true'], { stdio: 'ignore' }).status === 0) flag('sudo -n true succeeded'); else note('sudo -n true: denied');
const capEff = (/^CapEff:\s*([0-9a-f]+)/m.exec(fs.readFileSync('/proc/self/status', 'utf8')) || [])[1];
if (capEff && BigInt('0x' + capEff) !== 0n) flag(`effective capabilities ${capEff}`); else note('effective capabilities: none');
try { note(`yama ptrace_scope: ${fs.readFileSync('/proc/sys/kernel/yama/ptrace_scope', 'utf8').trim()}`); } catch { note('yama ptrace_scope: unavailable'); }
try { fs.accessSync('/var/run/docker.sock', fs.constants.W_OK); flag('docker socket is writable'); } catch { note('docker socket: not writable'); }
const groups = (spawnSync('id', ['-nG'], { encoding: 'utf8' }).stdout || '').trim().split(/\s+/);
for (const g of ['sudo', 'adm', 'docker', 'lxd', 'runner']) if (groups.includes(g)) flag(`member of group ${g}`);

for (const n of notes) console.log(`NOTE   ${n}`);
for (const f of findings) console.log(`FOUND  ${f}`);
console.log(`== collection: privilege checks ${findings.length === 0 ? 'PASS' : 'FAIL'} (dump scanned separately as root)`);
// Privilege findings fail the job here; the dummy scan is the root step.
process.exit(findings.length === 0 ? 0 : 1);
