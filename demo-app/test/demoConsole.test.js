'use strict';
// Demo console: DEMO_MODE gating, localhost-only, reset, attacker target refusal, and that the layer
// toggles change outcomes as described. Real app + real engine; Node crypto stands in for the browser key.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { startStack } = require('../../scripts/stack');
const { isLocalRequest, checkTarget, maskCookie } = require('../demoConsole');

const BROWSER = { 'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/130 Victim', 'accept-language': 'en-US', 'accept-encoding': 'gzip, br', 'sec-ch-ua-platform': '"Linux"' };
const DEMO = { DEMO_MODE: 'true' };
let on; let off;
test.before(async () => {
  on = await startStack({ engineEnv: DEMO, appEnv: { ...DEMO, TRUST_PROXY: 'loopback' } });
  off = await startStack();
});
test.after(() => { on.stop(); off.stop(); });

const api = (s, path, { method, body, cookie, headers = {} } = {}) => fetch(`${s.direct}/demo/api${path}`, {
  method: method || (body === undefined ? 'GET' : 'POST'), redirect: 'manual',
  headers: { ...BROWSER, 'content-type': 'application/json', 'x-demo-console': '1', ...(cookie ? { cookie } : {}), ...headers },
  body: body === undefined ? undefined : JSON.stringify(body),
});
const json = async (r) => ({ status: r.status, body: await r.json().catch(() => ({})) });
const spki = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

async function victim(s = on) {
  const r = await api(s, '/victim/login', { body: { pubkey: spki() } });
  assert.equal(r.status, 200);
  return r.headers.getSetCookie()[0].split(';')[0];
}
async function attack(mode, { target } = {}) {
  const cookie = await victim();
  assert.equal((await api(on, '/attacker/steal', { body: {}, cookie })).status, 200);
  return json(await api(on, '/attacker/replay', { body: { mode, amount: 5000, target } }));
}
const layers = async (b) => json(await api(on, '/layers', { body: b }));
test.beforeEach(async () => { await api(on, '/reset', { body: {} }); });

test('without DEMO_MODE the console does not exist', async () => {
  for (const p of ['/demo', '/demo/static/demo.js', '/demo/api/state', '/demo/api/feed']) assert.equal((await fetch(`${off.direct}${p}`)).status, 404, p);
  for (const p of ['/layers', '/reset', '/victim/login', '/attacker/steal', '/attacker/replay']) assert.equal((await api(off, p, { body: { layer1: false } })).status, 404, p);
});

test('with DEMO_MODE the page loads, ships a CSP and no inline script', async () => {
  const r = await fetch(`${on.direct}/demo`);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
  const html = await r.text();
  assert.match(html, /Run full story/); assert.match(html, /Transfer \$500/); assert.match(html, /runs against this demo app only/);
  assert.doesNotMatch(html, /<script(?![^>]*\ssrc=)[^>]*>/);
  assert.equal((await fetch(`${on.direct}/demo/static/demo.js`)).status, 200);
});

test('only localhost: foreign Host header and non-loopback peers get 404', async () => {
  const status = await new Promise((resolve) => http.get({ host: '127.0.0.1', port: new URL(on.direct).port, path: '/demo', headers: { host: 'evil.example.com' } }, (r) => { r.resume(); resolve(r.statusCode); }));
  assert.equal(status, 404);
  const fake = (remote, host) => ({ socket: { remoteAddress: remote }, headers: { host } });
  assert.equal(isLocalRequest(fake('127.0.0.1', 'localhost:3000')), true);
  assert.equal(isLocalRequest(fake('::ffff:127.0.0.1', '127.0.0.1:3000')), true);
  assert.equal(isLocalRequest(fake('203.0.113.9', 'localhost:3000')), false);
  assert.equal(isLocalRequest(fake('127.0.0.1', 'demo.example.com')), false);
});

test('POSTs need the demo header (blocks cross-site drive-by)', async () => {
  const r = await fetch(`${on.direct}/demo/api/reset`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' });
  assert.equal(r.status, 403);
});

test('steal masks the cookie: only first and last 4 characters appear', async () => {
  const cookie = await victim();
  const raw = cookie.slice('sid='.length);
  const r = await json(await api(on, '/attacker/steal', { body: {}, cookie }));
  assert.equal(r.status, 200);
  assert.equal(r.body.masked, maskCookie(raw));
  assert.ok(r.body.masked.startsWith(raw.slice(0, 4)) && r.body.masked.endsWith(raw.slice(-4)));
  assert.ok(!JSON.stringify(r.body).includes(raw.slice(8, 30)), 'full cookie must never reach the browser');
});

test('reset: clears stolen cookie, kills the old victim session, empties the feed, restores layers', async () => {
  const cookie = await victim();
  await api(on, '/attacker/steal', { body: {}, cookie });
  await layers({ device_key: false, layer1: false });
  const before = await json(await api(on, '/feed', { cookie }));
  assert.ok(before.body.events.length > 0);
  const r = await json(await api(on, '/reset', { body: {}, cookie }));
  assert.deepEqual(r.body.layers, { layer1: true, device_key: true });
  assert.equal((await json(await api(on, '/feed'))).body.events.length, 0);
  assert.equal((await json(await api(on, '/state'))).body.stolen, null);
  assert.equal((await json(await api(on, '/attacker/replay', { body: { mode: 'perfect' } }))).status, 409); // nothing stolen
  const me = await fetch(`${on.direct}/api/me`, { headers: { cookie, accept: 'application/json' } });
  assert.equal(me.status, 401); // old session destroyed
});

test('attacker endpoint refuses non-local targets (and anything that is not this app)', async () => {
  const port = new URL(on.direct).port;
  const cookie = await victim();
  await api(on, '/attacker/steal', { body: {}, cookie });
  const bad = ['http://example.com', 'https://127.0.0.1', `http://10.0.0.5:${port}`, `http://127.0.0.1.evil.com:${port}`,
    `http://localhost@evil.com:${port}`, `ftp://127.0.0.1:${port}`, 'http://127.0.0.1:1', 'not a url'];
  for (const target of bad) {
    const r = await json(await api(on, '/attacker/replay', { body: { mode: 'perfect', target } }));
    assert.equal(r.status, 403, target);
    assert.ok(['non_local_target', 'not_this_app'].includes(r.body.error), target);
  }
  assert.equal((await json(await api(on, '/feed'))).body.events.some((e) => e.route === 'POST /transfer'), false, 'refused targets send nothing');
  assert.equal(checkTarget(`http://localhost:${port}`, port), `http://127.0.0.1:${port}`);
  const ok = await json(await api(on, '/attacker/replay', { body: { mode: 'perfect', target: `http://localhost:${port}` } }));
  assert.equal(ok.status, 200);
});

test('layers ON: lazy copy is terminated (layer 1 + device key both fire)', async () => {
  const r = await attack('lazy');
  assert.equal(r.body.status, 401); assert.equal(r.body.verdict, 'stopped');
  const names = r.body.body.signals.map((s) => s.name);
  assert.ok(names.includes('user_agent_mismatch') && names.includes('ip_change') && names.includes('proof_missing'));
});

test('layers ON: perfect copy passes layer 1 and is stopped by the device key', async () => {
  const r = await attack('perfect');
  assert.equal(r.body.status, 403); assert.equal(r.body.body.error, 'step_up_required');
  assert.deepEqual(r.body.body.signals.map((s) => s.name), ['proof_missing']); // layer 1 silent
  assert.equal(r.body.verdict, 'stopped');
});

test('device key OFF: the perfect copy succeeds; turning it back ON stops it', async () => {
  await layers({ device_key: false });
  const open = await attack('perfect');
  assert.equal(open.body.status, 200); assert.equal(open.body.verdict, 'succeeded');
  assert.match(open.body.body.message, /\$5000 to mallory/);
  await layers({ device_key: true });
  const closed = await attack('perfect');
  assert.equal(closed.body.status, 403); assert.equal(closed.body.verdict, 'stopped');
});

test('layer 1 OFF alone: lazy copy is no longer caught by layer 1 but the device key still blocks it', async () => {
  await layers({ layer1: false });
  const r = await attack('lazy');
  assert.equal(r.body.status, 403);
  assert.deepEqual(r.body.body.signals.map((s) => s.name), ['proof_missing']);
});

test('both layers OFF: even a lazy copy succeeds (what each layer buys)', async () => {
  await layers({ layer1: false, device_key: false });
  assert.equal((await attack('lazy')).body.status, 200);
});

test('victim stays allowed with both layers on (key signs presence + transfer)', async () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const r = await api(on, '/victim/login', { body: { pubkey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64') } });
  const cookie = r.headers.getSetCookie()[0].split(';')[0];
  const call = (path, init = {}) => fetch(`${on.direct}${path}`, { ...init, headers: { ...BROWSER, accept: 'application/json', cookie, 'content-type': 'application/json', ...(init.headers || {}) } });
  const nonce = (await (await call('/auth/challenge', { method: 'POST' })).json()).nonce;
  const sig = crypto.sign('sha256', Buffer.from(`${nonce}|POST /transfer`), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  const tx = await call('/transfer', { method: 'POST', body: JSON.stringify({ to: 'alice', amount: 500 }), headers: { 'x-device-proof': `${nonce}.${sig}` } });
  assert.equal(tx.status, 200);
});

test('feed items carry badge data, signals and a provider once the rationale lands', async () => {
  await attack('lazy');
  let ev;
  for (let i = 0; i < 40 && !(ev && ev.rationale); i++) {
    await new Promise((r) => setTimeout(r, 250));
    ev = (await json(await api(on, '/feed'))).body.events.find((e) => e.action === 'terminate');
  }
  assert.ok(ev, 'terminate event in feed');
  assert.ok(ev.score > 70 && ev.signals.length > 0 && ev.rationale && ev.provider);
  assert.ok(!('session_id' in ev) && !JSON.stringify(ev).includes('sid='));
});

test('layer toggles reject bad input', async () => {
  assert.equal((await layers({})).status, 400);
  assert.equal((await layers({ layer1: 'no' })).status, 400);
});
