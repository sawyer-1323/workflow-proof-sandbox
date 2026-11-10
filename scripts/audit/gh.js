'use strict';

// Minimal read-only GitHub REST client for the approver's audit tools.
// GET only. The token comes from GH_TOKEN (for example GH_TOKEN="$(gh auth token)"
// for the one command) and is never printed. GITHUB_API_URL may point at a
// local stand-in for tests.

// The token is the approver's, so it goes only to GitHub's API, or to a local
// test stand-in on 127.0.0.1. Any other GITHUB_API_URL is refused.
const api = () => {
  const u = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
  if (u !== 'https://api.github.com' && !/^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(u)) throw new Error('GITHUB_API_URL must be https://api.github.com');
  return u;
};

// Filtered run listings return at most 1,000 results (GitHub REST docs), so a
// caller that needs the whole set checks total_count first and fails closed.
async function totalCount(path) {
  const sep = path.includes('?') ? '&' : '?';
  const body = await get(`${path}${sep}per_page=1`);
  if (!body || !Number.isInteger(body.total_count)) throw new Error(`no total_count for ${path.split('?')[0]}`);
  return body.total_count;
}

async function raw(path, accept = 'application/vnd.github+json') {
  const token = process.env.GH_TOKEN;
  if (!token) throw new Error('GH_TOKEN is not set');
  const r = await fetch(`${api()}${path}`, {
    headers: { authorization: `Bearer ${token}`, accept, 'x-github-api-version': '2022-11-28' },
    redirect: 'follow',
  });
  return r;
}

async function get(path) {
  const r = await raw(path);
  if (r.status === 404) return null;
  if (r.status !== 200) throw new Error(`GET ${path.split('?')[0]} returned ${r.status}`);
  return r.json();
}

// Paginates list endpoints. `key` names the array inside an object response
// (for example `workflow_runs`, `jobs`); omit it for plain-array endpoints.
async function list(path, key, maxPages = 20) {
  const out = [];
  for (let page = 1; page <= maxPages; page++) {
    const sep = path.includes('?') ? '&' : '?';
    const body = await get(`${path}${sep}per_page=100&page=${page}`);
    if (body === null) break;
    const items = key ? body[key] : body;
    if (!Array.isArray(items)) throw new Error(`unexpected list shape for ${path.split('?')[0]}`);
    out.push(...items);
    if (items.length < 100) return out;
  }
  throw new Error(`more than ${maxPages} pages for ${path.split('?')[0]}; narrow the window`);
}

async function text(path) {
  const r = await raw(path, 'application/vnd.github.v3.raw');
  if (r.status === 404 || r.status === 410) return null;
  if (r.status !== 200) throw new Error(`GET ${path.split('?')[0]} returned ${r.status}`);
  return r.text();
}

// The run ID named by a deployment status URL (".../actions/runs/<id>/...").
const runIdOf = (u) => { const m = /\/actions\/runs\/(\d+)(\/|$)/.exec(String(u || '')); return m ? Number(m[1]) : null; };

module.exports = { get, list, text, runIdOf, totalCount };
