'use strict';
/**
 * demoConsole: the /demo page for judges. Mounted ONLY when DEMO_MODE=true, and even then it answers
 * only loopback clients using a localhost Host header (404 otherwise, so it also resists DNS rebinding).
 * Every POST needs the custom header X-Demo-Console: 1, so another website cannot drive it cross-site.
 * It never changes detection logic: it just drives the real app + engine.
 *   victim   : the browser holds the device key; the server relays the real /login so the cookie is real.
 *   attacker : steals the victim's cookie and replays it server-side (real HTTP to this app). It refuses any
 *              target that is not this app on loopback, and never returns the full cookie to the browser.
 *   feed     : events read from the engine's demo feed (only events after the last reset).
 * Layer switches live in the engine (it 404s them unless DEMO_MODE=true there too).
 */
const crypto = require('node:crypto');
const path = require('node:path');
const express = require('express');

const LOCAL_ADDRS = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);
const COPYABLE = ['user-agent', 'accept-language', 'accept-encoding', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform'];
const LAZY = { ip: '198.51.100.20', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0', lang: 'de-DE,de;q=0.9', enc: 'gzip', platform: '"Windows"' };
const PLUMBING = /^(GET|POST) \/auth\//;

const hostnameOf = (hostHeader) => String(hostHeader || '').replace(/:\d+$/, '').toLowerCase();

function isLocalRequest(req) {
  return LOCAL_ADDRS.has(req.socket && req.socket.remoteAddress) && LOCAL_HOSTS.has(hostnameOf(req.headers.host));
}

// Returns the URL to attack (always rewritten to http://127.0.0.1:<port>) or throws {code}.
function checkTarget(target, ownPort) {
  if (target === undefined || target === null || target === '') return `http://127.0.0.1:${ownPort}`;
  let u;
  try { u = new URL(String(target)); } catch { throw Object.assign(new Error('bad target'), { code: 'non_local_target' }); }
  if (u.protocol !== 'http:' || u.username || u.password || !LOCAL_HOSTS.has(u.hostname.toLowerCase())) {
    throw Object.assign(new Error('refusing non-local target'), { code: 'non_local_target' });
  }
  if (Number(u.port || 80) !== Number(ownPort)) throw Object.assign(new Error('only this demo app may be attacked'), { code: 'not_this_app' });
  return `http://127.0.0.1:${ownPort}`;
}

function maskCookie(v) {
  const s = String(v);
  return s.length <= 8 ? '•'.repeat(s.length) : `${s.slice(0, 4)}${'•'.repeat(16)}${s.slice(-4)}`; // fixed width: hides the length too
}

function rawCookie(req, name) {
  const m = new RegExp(`(?:^|;\\s*)${name}=([^;]*)`).exec(req.headers.cookie || '');
  return m ? m[1] : null;
}

// express-session signs the cookie as "s:<sid>.<hmac>". Returns the sid only if the signature checks out.
function sidFromCookie(raw, secret) {
  if (!raw) return null;
  let v;
  try { v = decodeURIComponent(raw); } catch { return null; }
  if (!v.startsWith('s:')) return null;
  const body = v.slice(2);
  const dot = body.lastIndexOf('.');
  if (dot < 1) return null;
  const sid = body.slice(0, dot);
  const mac = crypto.createHmac('sha256', secret).update(sid).digest('base64').replace(/=+$/, '');
  const a = Buffer.from(mac); const b = Buffer.from(body.slice(dot + 1));
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? sid : null;
}

function verdictFor(status, body) {
  if (status === 200) return { verdict: 'succeeded', summary: `ATTACK SUCCEEDED: ${body.message || 'transfer went through'}` };
  if (status === 403 && body.error === 'step_up_required') return { verdict: 'stopped', summary: 'STOPPED: passkey step-up required, and the attacker has no passkey. Transfer not executed.' };
  if (status === 401) return { verdict: 'stopped', summary: 'STOPPED: session terminated. Transfer not executed.' };
  if (status === 400) return { verdict: 'error', summary: `Rejected by the app (${body.error || 'bad request'}). Press Reset demo to restore the balance.` };
  return { verdict: 'error', summary: `Unexpected response (HTTP ${status})` };
}

function shapeEvent(e) {
  const signals = (e.signals || []).map((s) => ({ name: String(s.name), weight: Number(s.weight), detail: String(s.detail || '') }))
    .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight));
  return {
    id: e.id, ts: e.ts, session: e.session_id, ip: e.ip, route: e.route, score: e.score, action: e.action, signals,
    rationale: e.rationale || null, provider: e.provider || e.rationale_source || null, model: e.model || null,
  };
}

function createDemoRouter({ engine, store, env }) {
  const router = express.Router();
  const state = { stolen: null, floor: null }; // floor: only events after this id are shown (null = set on first page load)
  const dir = path.join(__dirname, 'demo-console');

  router.use((req, res, next) => (isLocalRequest(req) ? next() : res.status(404).send('Not found')));
  router.use((req, res, next) => {
    if (req.method !== 'GET' && req.get('x-demo-console') !== '1') return res.status(403).json({ error: 'missing_demo_header' });
    return next();
  });

  router.get('/', (_req, res) => res.type('html').send(shell()));
  router.get('/static/demo.js', (_req, res) => res.sendFile(path.join(dir, 'demo.js')));
  router.get('/static/demo.css', (_req, res) => res.sendFile(path.join(dir, 'demo.css')));

  const engineError = (res, e) => (e.status === 404
    ? res.status(503).json({ error: 'engine_demo_mode_off', message: 'Start the risk engine with DEMO_MODE=true as well.' })
    : res.status(503).json({ error: 'engine_unavailable', message: e.message }));

  const ensureFloor = async () => { if (state.floor === null) state.floor = (await engine.demoEvents(0)).latest_id; };

  router.get('/api/state', async (_req, res) => {
    try {
      await ensureFloor(); // a fresh start shows a clean feed, not history from earlier runs
      res.json({ demo: true, layers: await engine.demoLayers(), stolen: state.stolen ? { masked: state.stolen.masked } : null });
    } catch (e) { engineError(res, e); }
  });

  router.post('/api/layers', async (req, res) => {
    const b = req.body || {};
    const body = {};
    for (const k of ['layer1', 'device_key']) {
      if (b[k] !== undefined) { if (typeof b[k] !== 'boolean') return res.status(400).json({ error: 'bad_request' }); body[k] = b[k]; }
    }
    if (!Object.keys(body).length) return res.status(400).json({ error: 'bad_request' });
    try { return res.json({ layers: await engine.demoLayers(body) }); } catch (e) { return engineError(res, e); }
  });

  router.post('/api/reset', async (req, res) => {
    try {
      const sid = sidFromCookie(rawCookie(req, 'sid'), env.SESSION_SECRET);
      if (sid) await new Promise((r) => store.destroy(sid, () => r()));
      state.stolen = null;
      const layers = await engine.demoLayers({ layer1: true, device_key: true });
      state.floor = (await engine.demoEvents(0)).latest_id;
      res.clearCookie('sid');
      res.json({ ok: true, layers });
    } catch (e) { engineError(res, e); }
  });

  // Victim login: the server relays the real POST /login using the browser's own headers (so the baseline
  // matches what the browser sends later) and the browser's public key; the Set-Cookie goes back to the browser.
  router.post('/api/victim/login', async (req, res) => {
    const pubkey = String((req.body && req.body.pubkey) || '').trim();
    if (!pubkey) return res.status(400).json({ error: 'pubkey_required' });
    const headers = { 'content-type': 'application/x-www-form-urlencoded' };
    for (const h of COPYABLE) if (req.get(h)) headers[h] = req.get(h);
    try {
      const r = await fetch(`http://127.0.0.1:${req.socket.localPort}/login`, {
        method: 'POST', redirect: 'manual', headers, signal: AbortSignal.timeout(5000),
        body: new URLSearchParams({ username: env.DEMO_USER, password: env.DEMO_PASSWORD, pubkey }),
      });
      if (r.status !== 302) return res.status(502).json({ error: 'victim_login_failed', status: r.status });
      for (const c of r.headers.getSetCookie()) res.append('Set-Cookie', c);
      state.stolen = null; // any earlier stolen cookie belongs to a previous session
      return res.json({ ok: true, user: env.DEMO_USER });
    } catch (e) { return res.status(502).json({ error: 'victim_login_failed', message: e.message }); }
  });

  router.post('/api/attacker/steal', (req, res) => {
    const cookie = rawCookie(req, 'sid');
    if (!cookie) return res.status(409).json({ error: 'no_victim_session', message: 'The victim is not logged in.' });
    const headers = {};
    for (const h of COPYABLE) if (req.get(h)) headers[h] = req.get(h);
    state.stolen = { cookie, headers, masked: maskCookie(cookie) };
    return res.json({ masked: state.stolen.masked, copied_headers: Object.keys(headers), note: 'Only the cookie and headers were taken. The device key cannot be copied out of the browser.' });
  });

  router.post('/api/attacker/replay', async (req, res) => {
    const b = req.body || {};
    const mode = b.mode === 'perfect' ? 'perfect' : b.mode === 'lazy' ? 'lazy' : null;
    if (!mode) return res.status(400).json({ error: 'bad_mode' });
    let base;
    try { base = checkTarget(b.target, req.socket.localPort); } catch (e) {
      return res.status(403).json({ error: e.code, message: 'The attacker simulator only runs against this demo app on localhost.' });
    }
    if (!state.stolen) return res.status(409).json({ error: 'nothing_stolen', message: 'Steal the session cookie first.' });
    const amount = Number.isFinite(b.amount) && b.amount > 0 && b.amount <= 100000 ? b.amount : 5000;
    const sent = { cookie: `sid=${state.stolen.cookie}`, accept: 'application/json', 'content-type': 'application/json' };
    let shown;
    if (mode === 'lazy') {
      Object.assign(sent, { 'user-agent': LAZY.ua, 'accept-language': LAZY.lang, 'accept-encoding': LAZY.enc, 'sec-ch-ua-platform': LAZY.platform, 'x-forwarded-for': LAZY.ip });
      shown = { ip: `${LAZY.ip} (via X-Forwarded-For; needs TRUST_PROXY=loopback)`, user_agent: LAZY.ua };
    } else {
      Object.assign(sent, state.stolen.headers); // identical UA + headers; same socket IP as the victim
      shown = { ip: 'same as the victim (127.0.0.1)', user_agent: state.stolen.headers['user-agent'] || '' };
    }
    try {
      const r = await fetch(`${base}/transfer`, { method: 'POST', redirect: 'manual', headers: sent, body: JSON.stringify({ to: 'mallory', amount }), signal: AbortSignal.timeout(8000) });
      const body = await r.json().catch(() => ({}));
      return res.json({ mode, amount, request: shown, status: r.status, body, ...verdictFor(r.status, body) });
    } catch (e) { return res.status(502).json({ error: 'replay_failed', message: e.message }); }
  });

  router.get('/api/feed', async (req, res) => {
    try {
      await ensureFloor();
      const { events } = await engine.demoEvents(state.floor);
      res.json({ events: events.map(shapeEvent).filter((e) => req.query.plumbing === '1' || !PLUMBING.test(e.route || '')) });
    } catch (e) { engineError(res, e); }
  });

  return router;
}

const shell = () => `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SessionGuard demo console</title><link rel="stylesheet" href="/demo/static/demo.css">
<header class="bar">
  <h1>SessionGuard <span>demo console</span></h1>
  <div class="controls">
    <button id="reset" class="ghost">Reset demo</button>
    <label class="switch"><input type="checkbox" id="layer1" checked> Layer 1 checks</label>
    <label class="switch"><input type="checkbox" id="devkey" checked> Device key</label>
    <button id="story" class="primary">Run full story</button>
  </div>
</header>
<div id="caption" class="caption" aria-live="polite">Pick an action, or press “Run full story”. Toggle the layers to see what each one stops.</div>
<main class="grid">
  <section class="panel" id="victim"><h2>Victim <small>demo bank</small></h2>
    <div class="balance"><span>Balance</span><b id="bal">…</b></div>
    <p class="muted" id="vstatus">Logging in…</p>
    <div class="row"><button id="v-dash">View dashboard</button><button id="v-xfer">Transfer $500</button></div>
    <div id="v-out" class="result" hidden></div>
    <button id="v-relogin" class="link">Log in again (new session, keeps the feed)</button>
  </section>
  <section class="panel" id="attacker"><h2>Attacker <small>simulator</small></h2>
    <p class="muted">Attacker simulator, runs against this demo app only</p>
    <button id="a-steal">1. Steal session cookie</button>
    <div id="a-cookie" class="mono" hidden></div>
    <fieldset class="mode"><legend>Copy quality</legend>
      <label><input type="radio" name="mode" value="lazy" checked> Lazy copy <small>different user-agent and IP</small></label>
      <label><input type="radio" name="mode" value="perfect"> Perfect copy <small>identical headers and IP</small></label>
    </fieldset>
    <button id="a-replay" class="danger">2. Replay stolen session and transfer $5,000</button>
    <div id="a-out" class="result" hidden></div>
  </section>
  <section class="panel" id="guard"><h2>SessionGuard <small>live feed</small></h2>
    <label class="muted"><input type="checkbox" id="plumbing"> include proof plumbing events</label>
    <div id="feed" class="feed"><p class="muted" id="feed-empty">No events yet.</p></div>
  </section>
</main>
<script src="/static/devicekey.js"></script><script src="/demo/static/demo.js"></script>`;

module.exports = { createDemoRouter, isLocalRequest, checkTarget, maskCookie, sidFromCookie };
