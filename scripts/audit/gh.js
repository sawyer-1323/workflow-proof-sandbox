'use strict';

// Minimal read-only GitHub REST client for the approver's audit tools.
// GET only. The token comes from GH_TOKEN (for example GH_TOKEN="$(gh auth token)"
// for the one command) and is never printed. GITHUB_API_URL may point at a
// local stand-in for tests.

// The token is the approver's, so it goes only to GitHub's API, or to a local
// test stand-in on 127.0.0.1. Any other GITHUB_API_URL is refused.
const LOCAL = /^http:\/\/127\.0\.0\.1:\d{2,5}$/;
const api = () => {
  const u = (process.env.GITHUB_API_URL || 'https://api.github.com').replace(/\/+$/, '');
  if (u !== 'https://api.github.com' && !LOCAL.test(u)) throw new Error('GITHUB_API_URL must be https://api.github.com');
  return u;
};
const isRedirect = (r) => r.type === 'opaqueredirect' || r.status === 0 || (r.status >= 300 && r.status < 400);
const pathOnly = (p) => p.split('?')[0];

// Filtered run listings return at most 1,000 results (GitHub REST docs), so a
// caller that needs the whole set checks total_count first and fails closed.
async function totalCount(path) {
  const sep = path.includes('?') ? '&' : '?';
  const body = await get(`${path}${sep}per_page=1`);
  if (!body || !Number.isInteger(body.total_count)) throw new Error(`no total_count for ${pathOnly(path)}`);
  return body.total_count;
}

// Revision 9: a redirect is never followed with the token. `manual` returns
// the 3xx response itself, so nothing is sent to its Location; the callers
// below refuse it.
async function raw(path, accept = 'application/vnd.github+json') {
  const token = process.env.GH_TOKEN;
  if (!token) throw new Error('GH_TOKEN is not set');
  return fetch(`${api()}${path}`, {
    headers: { authorization: `Bearer ${token}`, accept, 'x-github-api-version': '2022-11-28' },
    redirect: 'manual',
  });
}

const refused = (path, r) => new Error(`GET ${pathOnly(path)} refused a redirect (HTTP ${r.status}); not followed`);

async function get(path) {
  const r = await raw(path);
  if (isRedirect(r)) throw refused(path, r);
  if (r.status === 404) return null;
  if (r.status !== 200) throw new Error(`GET ${pathOnly(path)} returned ${r.status}`);
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
    if (!Array.isArray(items)) throw new Error(`unexpected list shape for ${pathOnly(path)}`);
    out.push(...items);
    if (items.length < 100) return out;
  }
  throw new Error(`more than ${maxPages} pages for ${pathOnly(path)}; narrow the window`);
}

// Job logs are the one documented redirect: GitHub answers 302 with a
// short-lived signed download URL [V]. Only `/repos/<o>/<r>/actions/jobs/<id>/logs`
// may redirect, and its download is one GET with NO Authorization header (the
// token never leaves api.github.com), to an https URL (or the local stand-in in
// tests), following no further redirect. Every other 3xx is refused.
const JOB_LOGS = /^\/repos\/[\w.-]+\/[\w.-]+\/actions\/jobs\/\d+\/logs$/;
async function text(path) {
  let r = await raw(path, 'application/vnd.github.v3.raw');
  if (isRedirect(r)) {
    if (!JOB_LOGS.test(path)) throw refused(path, r);
    let u;
    try { u = new URL(r.headers.get('location') || ''); } catch { throw new Error(`GET ${pathOnly(path)} redirect has no valid Location; not followed`); }
    if (u.protocol !== 'https:' && !(LOCAL.test(api()) && LOCAL.test(u.origin))) throw new Error(`GET ${pathOnly(path)} redirect to a non-https URL; not followed`);
    r = await fetch(u, { redirect: 'manual' });
    if (isRedirect(r)) throw new Error(`GET ${pathOnly(path)} log download redirected again (HTTP ${r.status}); not followed`);
  }
  if (r.status === 404 || r.status === 410) return null;
  if (r.status !== 200) throw new Error(`GET ${pathOnly(path)} returned ${r.status}`);
  return r.text();
}

// The run ID named by a deployment status URL (".../actions/runs/<id>/...").
const runIdOf = (u) => { const m = /\/actions\/runs\/(\d+)(\/|$)/.exec(String(u || '')); return m ? Number(m[1]) : null; };

module.exports = { get, list, text, runIdOf, totalCount };
