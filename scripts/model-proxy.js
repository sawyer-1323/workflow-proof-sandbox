#!/usr/bin/env node
'use strict';

// Trusted model proxy. Runs as the dedicated unprivileged uid `modelproxy`,
// started before any agent process. It is the only process that holds the
// model key; the agent's client talks to it on 127.0.0.1 with a placeholder.
//
// Enforced:
//   - method and path allowlist: POST /v1/messages and POST /v1/messages/count_tokens,
//     with no query string or exactly `beta=true` [U: the exact set the Claude
//     CLI needs is unverified; anything else is refused and logged];
//   - model allowlist; max_tokens cap (required on /v1/messages);
//   - per-run request cap and spend-estimate cap (worst case before sending,
//     actual usage after the response);
//   - auth: rejects any Authorization header and any x-api-key other than the
//     placeholder; injects the real key itself; forwards an allowlist of headers;
//   - upstream is fixed: api.anthropic.com:443 at pinned IPs (no DNS, no other
//     host, no CONNECT, no absolute-URI requests);
//   - request and response size limits;
//   - logs request METADATA only (never prompt or response content), one JSON
//     line per request; agent-controlled values are logged only if allowlisted.
//
// Configuration (environment, read once at start):
//   MP_UPSTREAM_KEY (secret; removed from process.env after reading), MP_PORT,
//   MP_PLACEHOLDER, MP_MODELS (comma list), MP_MAX_TOKENS, MP_MAX_REQUESTS,
//   MP_SPEND_CAP_USD, MP_INPUT_USD_PER_MTOK, MP_OUTPUT_USD_PER_MTOK,
//   MP_UPSTREAM_IPS (comma list of IPv4), MP_LOG (file path), MP_OFFLINE (1 = dummy
//   stage: refuse every request before any upstream call)

const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const fs = require('node:fs');

const UPSTREAM_HOST = 'api.anthropic.com';
const PATHS = new Map([['/v1/messages', { spend: true }], ['/v1/messages/count_tokens', { spend: false }]]);
const QUERIES = new Set(['', 'beta=true']);
const FORWARD_HEADERS = ['content-type', 'accept', 'anthropic-version', 'anthropic-beta'];
const MAX_REQ_BYTES = 6 * 1024 * 1024;
const MAX_RESP_BYTES = 16 * 1024 * 1024;

const key = process.env.MP_UPSTREAM_KEY || '';
delete process.env.MP_UPSTREAM_KEY;
const num = (n) => Number(process.env[n]);
const cfg = {
  port: num('MP_PORT'),
  placeholder: process.env.MP_PLACEHOLDER || '',
  models: new Set((process.env.MP_MODELS || '').split(',').map((s) => s.trim()).filter(Boolean)),
  maxTokens: num('MP_MAX_TOKENS'),
  maxRequests: num('MP_MAX_REQUESTS'),
  spendCap: num('MP_SPEND_CAP_USD'),
  inPrice: num('MP_INPUT_USD_PER_MTOK'),
  outPrice: num('MP_OUTPUT_USD_PER_MTOK'),
  // Hard reservation inputs. maxInput caps the exact input-token count of one
  // request; cacheMult prices every input token as a cache write at the most
  // expensive TTL (2x input for the 1-hour cache), so a reservation never
  // underestimates a cache miss.
  maxInput: num('MP_MAX_INPUT_TOKENS'),
  cacheMult: Number(process.env.MP_CACHE_WRITE_MULT || '2'),
  ips: (process.env.MP_UPSTREAM_IPS || '').split(',').filter(Boolean),
  log: process.env.MP_LOG,
  // MP_OFFLINE=1: refuse every allowlisted request before any upstream call.
  offline: process.env.MP_OFFLINE === '1',
};
const bad = !key || !cfg.placeholder || cfg.models.size === 0 || !cfg.log
  || ![cfg.port, cfg.maxTokens, cfg.maxRequests, cfg.spendCap, cfg.inPrice, cfg.outPrice, cfg.maxInput].every((v) => Number.isFinite(v) && v > 0)
  || !(Number.isFinite(cfg.cacheMult) && cfg.cacheMult >= 1.25)
  || cfg.ips.length === 0 || !cfg.ips.every((ip) => net.isIPv4(ip));
if (bad) { console.error('model-proxy: invalid configuration'); process.exit(2); }

let forwarded = 0;
let spent = 0;     // settled cost of completed requests
let reserved = 0;  // worst-case cost held by requests still in flight
let seq = 0;
const log = (e) => fs.appendFileSync(cfg.log, JSON.stringify({ t: new Date().toISOString(), ...e }) + '\n');
const usd = (inTok, outTok) => (inTok * cfg.inPrice + outTok * cfg.outPrice) / 1e6;
// Worst case for one request: every input token billed as a cache write at the
// highest multiplier, plus the full max_tokens of output (thinking included).
const reservationFor = (inTok, maxTokens) => usd(inTok * cfg.cacheMult, maxTokens);
// Settled cost from reported usage. Cache writes are priced at cacheMult, the
// conservative TTL, so settlement never undercounts.
const settledFor = (u) => usd(u.input_tokens + cfg.cacheMult * u.cache_creation_input_tokens + 0.1 * u.cache_read_input_tokens, u.output_tokens);
// Fields that do not contribute input tokens and are not count_tokens inputs.
const NOT_COUNTED = new Set(['max_tokens', 'stream', 'metadata', 'temperature', 'top_p', 'top_k', 'stop_sequences', 'service_tier']);

// Exact input-token count from the upstream count_tokens endpoint. Fails closed:
// any error or unparseable reply means the request is refused, never forwarded.
function countInput(body, clientHeaders, cb) {
  const countBody = {};
  for (const [k, v] of Object.entries(body)) if (!NOT_COUNTED.has(k)) countBody[k] = v;
  const payload = Buffer.from(JSON.stringify(countBody));
  const headers = { host: UPSTREAM_HOST, 'x-api-key': key, 'content-type': 'application/json',
    'content-length': String(payload.length), 'accept-encoding': 'identity' };
  for (const h of ['anthropic-version', 'anthropic-beta']) if (typeof clientHeaders[h] === 'string') headers[h] = clientHeaders[h];
  const r = https.request({ host: UPSTREAM_HOST, servername: UPSTREAM_HOST, port: 443, method: 'POST',
    path: '/v1/messages/count_tokens', headers, lookup, timeout: 60000 }, (ur) => {
    let text = '';
    ur.on('data', (c) => { text += c.toString('utf8'); if (text.length > 65536) ur.destroy(); });
    ur.on('end', () => {
      try {
        const n = JSON.parse(text).input_tokens;
        if (ur.statusCode === 200 && Number.isInteger(n) && n >= 0) return cb(null, n);
      } catch { /* fall through */ }
      cb(new Error(`count_tokens status ${ur.statusCode}`));
    });
  });
  r.on('timeout', () => r.destroy(new Error('timeout')));
  r.on('error', (e) => cb(e));
  r.end(payload);
}

function refuse(res, meta, status, reason) {
  log({ ...meta, decision: 'refuse', status, reason });
  res.writeHead(status, { 'content-type': 'application/json', connection: 'close' });
  res.end(JSON.stringify({ type: 'error', error: { type: 'proxy_refused', message: reason } }));
}

function lookup(hostname, options, cb) {
  const ip = cfg.ips[seq % cfg.ips.length];
  if (options && options.all) return cb(null, [{ address: ip, family: 4 }]);
  return cb(null, ip, 4);
}

const server = http.createServer({ maxHeaderSize: 32 * 1024 }, (req, res) => {
  const meta = { n: ++seq };
  if (req.method !== 'POST') return refuse(res, meta, 405, 'method not allowed');
  if (!req.url.startsWith('/')) return refuse(res, meta, 403, 'absolute URI not allowed');
  const [path, query = ''] = req.url.split('?', 2);
  const rule = PATHS.get(path);
  if (!rule || !QUERIES.has(query)) return refuse(res, meta, 403, 'path not allowlisted');
  meta.path = path;
  if (req.headers.authorization !== undefined || req.headers['proxy-authorization'] !== undefined) {
    return refuse(res, meta, 403, 'client authorization header rejected');
  }
  const clientKey = req.headers['x-api-key'];
  if (clientKey !== undefined && clientKey !== cfg.placeholder) return refuse(res, meta, 403, 'client x-api-key rejected');

  const chunks = [];
  let size = 0;
  let aborted = false;
  req.on('data', (c) => {
    size += c.length;
    if (size > MAX_REQ_BYTES && !aborted) { aborted = true; refuse(res, meta, 413, 'request too large'); req.destroy(); }
    else if (!aborted) chunks.push(c);
  });
  req.on('end', () => {
    if (aborted) return;
    meta.req_bytes = size;
    let body;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return refuse(res, meta, 400, 'body is not JSON'); }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return refuse(res, meta, 400, 'body is not an object');
    if (typeof body.model !== 'string' || !cfg.models.has(body.model)) return refuse(res, meta, 403, 'model not allowlisted');
    meta.model = body.model;
    // Dummy stage (PROOF_STAGE=dummy): the proxy holds only the synthetic dummy
    // and never contacts the upstream. Every local check still runs first and
    // the request is logged (path, model), so the run records which endpoints
    // the client calls; the refusal comes just before the first upstream call.
    const offline = () => refuse(res, meta, 503, 'offline stage: no upstream request');
    if (!rule.spend) return cfg.offline ? offline() : forward(0); // count_tokens is not billed
    if (!Number.isInteger(body.max_tokens) || body.max_tokens < 1 || body.max_tokens > cfg.maxTokens) {
      return refuse(res, meta, 403, 'max_tokens missing or above cap');
    }
    meta.max_tokens = body.max_tokens;
    if (forwarded + 1 > cfg.maxRequests) return refuse(res, meta, 429, 'request cap reached');
    if (cfg.offline) return offline();
    countInput(body, req.headers, (err, inTok) => {
      if (err) return refuse(res, meta, 502, 'input count unavailable');
      meta.input_tokens_counted = inTok;
      if (inTok > cfg.maxInput) return refuse(res, meta, 413, 'input tokens above cap');
      const worst = reservationFor(inTok, body.max_tokens);
      // Hard cap: settled spend + every in-flight reservation + this one.
      if (spent + reserved + worst > cfg.spendCap) return refuse(res, meta, 429, 'spend cap reached');
      if (forwarded + 1 > cfg.maxRequests) return refuse(res, meta, 429, 'request cap reached');
      reserved += worst;
      forwarded++;
      forward(worst);
    });
  });

  function forward(worst) {
    const rule = PATHS.get(meta.path);
    let settled = false;
    const settle = (cost) => {
      if (settled || !rule.spend) return;
      settled = true;
      reserved -= worst;
      spent += cost;
    };
    const headers = { host: UPSTREAM_HOST, 'x-api-key': key, 'accept-encoding': 'identity' };
    for (const h of FORWARD_HEADERS) if (typeof req.headers[h] === 'string') headers[h] = req.headers[h];
    meta.beta_headers = typeof req.headers['anthropic-beta'] === 'string' ? req.headers['anthropic-beta'].split(',').length : 0;
    const payload = Buffer.concat(chunks);
    headers['content-length'] = String(payload.length);

    const up = https.request({
      host: UPSTREAM_HOST, servername: UPSTREAM_HOST, port: 443, method: 'POST',
      path: req.url, headers, lookup, timeout: 600000,
    }, (ur) => {
      meta.status = ur.statusCode;
      meta.request_id = typeof ur.headers['request-id'] === 'string' ? ur.headers['request-id'].slice(0, 80) : undefined;
      const out = {};
      for (const [k, v] of Object.entries(ur.headers)) if (!['set-cookie', 'connection', 'transfer-encoding'].includes(k)) out[k] = v;
      res.writeHead(ur.statusCode, out);
      let respBytes = 0;
      let tail = '';
      const usage = { input_tokens: 0, output_tokens: 0, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 };
      const take = (text) => {
        for (const m of text.matchAll(/"usage"\s*:\s*(\{[^{}]*\})/g)) {
          try {
            const u = JSON.parse(m[1]);
            for (const k of Object.keys(usage)) if (Number.isFinite(u[k])) usage[k] = Math.max(usage[k], u[k]);
          } catch { /* partial */ }
        }
      };
      ur.on('data', (c) => {
        respBytes += c.length;
        if (respBytes > MAX_RESP_BYTES) { settle(worst); log({ ...meta, decision: 'abort', reason: 'response too large' }); ur.destroy(); res.destroy(); return; }
        const text = tail + c.toString('utf8');
        take(text);
        tail = text.slice(-2048);
        res.write(c);
      });
      ur.on('end', () => {
        res.end();
        // Settle to actual usage when it was reported; otherwise keep the full
        // reservation as spent. Settlement never exceeds what was reserved
        // except through a usage report above the reservation, which is logged.
        const reportedAny = usage.input_tokens + usage.output_tokens + usage.cache_creation_input_tokens + usage.cache_read_input_tokens > 0;
        const actual = reportedAny ? settledFor(usage) : worst;
        if (rule.spend && actual > worst) meta.over_reservation_usd = Number((actual - worst).toFixed(4));
        settle(actual);
        log({ ...meta, decision: 'forwarded', resp_bytes: respBytes, usage, run_requests: forwarded, run_spend_usd: Number(spent.toFixed(4)) });
      });
      ur.on('close', () => settle(worst)); // a stream closed without 'end' keeps the full reservation
    });
    up.on('timeout', () => up.destroy(new Error('timeout')));
    up.on('error', (e) => {
      settle(worst);
      log({ ...meta, decision: 'upstream-error', error: e.code || 'error' });
      if (!res.headersSent) refuse(res, meta, 502, 'upstream error'); else res.destroy();
    });
    up.end(payload);
  }
});

server.on('connect', (req, socket) => {
  log({ n: ++seq, decision: 'refuse', status: 405, reason: 'CONNECT not allowed' });
  socket.end('HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n');
});
server.on('clientError', (err, socket) => socket.destroy());
server.listen(cfg.port, '127.0.0.1', () => {
  log({ decision: 'start', port: cfg.port, models: [...cfg.models], max_tokens: cfg.maxTokens, max_requests: cfg.maxRequests, spend_cap_usd: cfg.spendCap, upstream_ips: cfg.ips.length, offline: cfg.offline });
});
