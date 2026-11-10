#!/usr/bin/env node
'use strict';

// Static check (S4 a, M1 a): key secrets appear only where they belong.
// Rules, per workflow file under the given directory:
//   R1 no `secrets: inherit` and no `toJSON(secrets)` anywhere;
//   R2 no secret referenced outside a job (workflow-level env);
//   R3 `secrets.APP_PRIVATE_KEY` and `secrets.ARTIFACT_PRIVATE_KEY` appear only in
//      jobs named *-publish;
//   R4 every *-publish job uses environment `review` or `probe` and has `needs:`;
//   R5 no *-publish job checks out the PR head (`ref: ${{ github.event.pull_request.head...`
//      or `path: pr-head`) or runs the agent wrapper (`run-as-agent.sh`);
//   R6 jobs named *-agent use only environments `review-agent` or `probe-agent`
//      and reference only ANTHROPIC_API_KEY and S5_CANARY; ANTHROPIC_API_KEY only
//      in a step that runs start-model-proxy.sh and not run-as-agent.sh; a step
//      that runs run-as-agent.sh (agent code) references NO secret at all;
//   R7 every other job references no secret at all.
//   R8 (round 6, stage gating) every step that references ANTHROPIC_API_KEY has an
//      `if:` requiring vars.PROOF_STAGE == 'live'.
//   R9 (round 6, budget and containment) no workflow sets an environment's
//      `deployment:` key (the run budget counts deployments), and no workflow or
//      job requests `write-all`, `actions: write` or `deployments: write`.
//   R10 (round 7, dummy stage holds no App or artifact key) every *-publish job
//      has a job-level `if:` requiring vars.PROOF_STAGE == 'live'.
// The parser relies on this repository's layout (two-space indentation, job
// keys at two spaces, job settings at four) and fails if no job is found.
// Usage: check-key-references.js <workflows-dir>

const fs = require('node:fs');
const path = require('node:path');

const dir = process.argv[2] || '.github/workflows';
const errors = [];
const err = (f, m) => errors.push(`${f}: ${m}`);

for (const name of fs.readdirSync(dir).filter((n) => /\.ya?ml$/.test(n)).sort()) {
  const file = path.join(dir, name);
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  // No comment stripping: a secret reference hidden after a '#' still counts.
  const code = (l) => l;
  let inJobs = false;
  let job = null;
  const jobs = {};
  for (const raw of lines) {
    const line = code(raw);
    if (/secrets:\s*inherit/.test(line) || /toJSON\(\s*secrets\s*\)/.test(line)) err(name, 'R1 secrets: inherit or toJSON(secrets)');
    if (/^\s+deployment:/.test(line)) err(name, 'R9 an environment sets deployment: (the run budget counts deployments)');
    if (/write-all/.test(line) || /^\s*(actions|deployments):\s*write\b/.test(line)) err(name, `R9 write scope requested: ${line.trim()}`);
    if (/^jobs:\s*$/.test(line)) { inJobs = true; continue; }
    if (inJobs && /^\S/.test(line) && line.trim() !== '') { inJobs = false; job = null; }
    if (inJobs) {
      const m = /^  ([A-Za-z0-9_-]+):\s*$/.exec(line);
      if (m) { job = m[1]; jobs[job] = []; continue; }
      if (job) jobs[job].push(line);
    } else if (/secrets\./.test(line)) {
      err(name, `R2 secret referenced outside a job: ${line.trim()}`);
    }
  }
  if (lines.some((l) => /^jobs:\s*$/.test(l)) && Object.keys(jobs).length === 0) err(name, 'no jobs parsed (unexpected layout)');

  for (const [j, body] of Object.entries(jobs)) {
    const text = body.join('\n');
    const secrets = [...text.matchAll(/secrets\.([A-Za-z0-9_]+)/g)].map((x) => x[1]);
    const envLines = text.split('\n').filter((l) => /^    environment:/.test(l));
    if (envLines.length > 1) err(name, `job ${j} has more than one environment line`);
    if (envLines.length === 1 && !/^    environment:\s*[A-Za-z0-9_-]+\s*(#.*)?$/.test(envLines[0])) err(name, `job ${j} environment has an unexpected form`);
    const env = (/^    environment:\s*([A-Za-z0-9_-]+)/m.exec(text) || [])[1] || null;
    const isPublish = j.endsWith('-publish');
    const isAgent = j.endsWith('-agent');
    for (const k of ['APP_PRIVATE_KEY', 'ARTIFACT_PRIVATE_KEY']) if (secrets.includes(k) && !isPublish) err(name, `R3 job ${j} references ${k}`);
    if (isPublish) {
      if (!['review', 'probe'].includes(env)) err(name, `R4 publish job ${j} environment is ${env}`);
      if (!/^    needs:/m.test(text)) err(name, `R4 publish job ${j} has no needs:`);
      if (!/^    if:.*vars\.PROOF_STAGE\s*==\s*'live'/m.test(text)) err(name, `R10 publish job ${j} is not gated on PROOF_STAGE == live`);
      if (/ref:\s*\$\{\{\s*github\.event\.pull_request\.head/.test(text) || /path:\s*pr-head/.test(text)) err(name, `R5 publish job ${j} checks out the PR head`);
      if (/run-as-agent\.sh/.test(text)) err(name, `R5 publish job ${j} runs agent code`);
    } else if (isAgent) {
      if (env !== null && !['review-agent', 'probe-agent'].includes(env)) err(name, `R6 agent job ${j} environment is ${env}`);
      for (const s of secrets) if (!['ANTHROPIC_API_KEY', 'S5_CANARY'].includes(s)) err(name, `R6 agent job ${j} references secrets.${s}`);
      // Per step: steps start with "      - " (six spaces).
      const steps = []; let cur = null;
      for (const l of body) { if (/^      - /.test(l)) { cur = []; steps.push(cur); } if (cur) cur.push(l); }
      for (const st of steps) {
        const t = st.join('\n');
        const ss = [...t.matchAll(/secrets\.([A-Za-z0-9_]+)/g)].map((x) => x[1]);
        const agentStep = /run-as-agent\.sh/.test(t);
        if (ss.includes('ANTHROPIC_API_KEY') && (!/start-model-proxy\.sh/.test(t) || agentStep)) err(name, `R6 agent job ${j}: the model key is referenced outside the proxy-start step`);
        if (agentStep) for (const s of ss) err(name, `R6 agent job ${j}: a run-as-agent (agent code) step references secrets.${s}`);
        if (ss.includes('ANTHROPIC_API_KEY') && !/^\s+if:.*vars\.PROOF_STAGE\s*==\s*'live'/m.test(t)) err(name, `R8 agent job ${j}: the model-key step is not gated on PROOF_STAGE == live`);
      }
    } else {
      for (const s of secrets) err(name, `R7 job ${j} references secrets.${s}`);
      if (env !== null) err(name, `R7 job ${j} uses environment ${env}`);
    }
    console.log(`job ${name}:${j} env=${env || '-'} secrets=[${[...new Set(secrets)].join(',')}]`);
  }
}

for (const e of errors) console.log(`FAIL  ${e}`);
console.log(`== result: ${errors.length === 0 ? 'PASS' : 'FAIL'}`);
process.exit(errors.length === 0 ? 0 : 1);
