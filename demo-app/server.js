'use strict';
/**
 * demo-app: the protected app. Login (single demo user from .env) that also binds a browser
 * device key to the session, dashboard, fake "transfer", passkey setup + step-up, /admin.
 * Sessions live in Redis (connect-redis); createApp() takes injectable stores so tests need no Redis.
 * Order matters: static -> security headers -> session -> riskGuard -> routes. /admin has its own
 * session and is excluded from the user session + guard.
 */
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');
const webauthn = require('@simplewebauthn/server');
const { createRiskGuard } = require('./riskGuard');
const { createPasskeyStore } = require('./passkeys');
const { createAdminRouter } = require('./admin');
const { parseTrustProxy } = require('./trustProxy');
const { createDemoRouter } = require('./demoConsole');
const views = require('./views');

const ROOT = path.join(__dirname, '..');
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const isAdminPath = (p) => p === '/admin' || p.startsWith('/admin/');
const isDemoPath = (p) => p === '/demo' || p.startsWith('/demo/');

const CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
  + "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

function createApp({ store, adminStore = new session.MemoryStore(), env = process.env }) {
  for (const k of ['SESSION_SECRET', 'ENGINE_API_KEY', 'DEMO_USER', 'DEMO_PASSWORD', 'RISK_ENGINE_URL']) {
    if (!env[k]) throw new Error(`${k} is not set (see .env.example)`);
  }
  const guard = createRiskGuard({
    engineUrl: env.RISK_ENGINE_URL, apiKey: env.ENGINE_API_KEY, exposeSignals: env.EXPOSE_SIGNALS === 'true',
    timeoutMs: Number(env.ENGINE_TIMEOUT_MS || 1500),
  });
  const engine = guard.engine;
  const passkeys = createPasskeyStore(env.PASSKEY_STORE_PATH || path.join(ROOT, 'data', 'passkeys.json'));
  const rp = {
    id: env.WEBAUTHN_RP_ID || 'localhost', name: 'Demo bank',
    origins: (env.WEBAUTHN_ORIGINS || `http://localhost:${env.APP_PORT || 3000}`).split(',').map((s) => s.trim()).filter(Boolean),
  };
  const requireDeviceKey = env.REQUIRE_DEVICE_KEY !== 'false';
  const demoOn = env.DEMO_MODE === 'true'; // the /demo console exists only then (and only for localhost)

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', parseTrustProxy(env.TRUST_PROXY)); // A1: default false = socket address only

  app.use((_req, res, next) => {
    res.set({ 'Content-Security-Policy': CSP, 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store' });
    next();
  });
  app.use('/static', express.static(path.join(__dirname, 'public')));
  app.get('/static/vendor/simplewebauthn-browser.js', (_req, res) => res.sendFile(path.join(ROOT, 'node_modules', '@simplewebauthn', 'browser', 'dist', 'bundle', 'index.umd.min.js')));

  app.use(express.urlencoded({ extended: false }));
  app.use(express.json());

  const userSession = session({
    name: 'sid', store, secret: env.SESSION_SECRET, resave: false, saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 60 * 60 * 1000 },
  });
  const skip = (p) => isAdminPath(p) || (demoOn && isDemoPath(p)); // own auth / not a user session
  app.use((req, res, next) => (skip(req.path) ? next() : userSession(req, res, next)));
  app.use((req, res, next) => (skip(req.path) ? next() : guard.middleware(req, res, next)));
  app.use('/admin', createAdminRouter({ engine, env, store: adminStore }));
  if (demoOn) app.use('/demo', createDemoRouter({ engine, store, env }));

  const requireLogin = (req, res, next) => {
    if (req.session.user) return next();
    const isPageLoad = req.method === 'GET' && req.accepts(['html', 'json']) === 'html';
    return isPageLoad ? res.redirect('/login') : res.status(401).json({ error: 'login_required' });
  };
  const endSession = (req, res, status, body) => req.session.destroy(() => { res.clearCookie('sid'); res.status(status).json(body); });

  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.get('/', (req, res) => res.redirect(req.session.user ? '/dashboard' : '/login'));
  app.get('/login', (_req, res) => res.send(views.loginForm()));

  app.post('/login', (req, res, next) => {
    const { username = '', password = '', pubkey = '' } = req.body || {};
    const ok = safeEqual(username, env.DEMO_USER) & safeEqual(password, env.DEMO_PASSWORD);
    if (!ok) return res.status(401).send(views.loginForm('Invalid credentials'));
    const key = String(pubkey).trim();
    if (requireDeviceKey && !key) return res.status(400).send(views.loginForm('Device key missing: this app needs JavaScript and WebCrypto.'));
    return req.session.regenerate(async (err) => { // new session id: no fixation, and a fresh key binding
      if (err) return next(err);
      req.session.user = env.DEMO_USER;
      req.session.balance = 10000;
      try {
        await guard.evaluate(req); // first call for this session id = baseline
        if (key) await engine.bind(req.sessionID, key); // B2: bound at creation; engine refuses any rebind
      } catch (e) {
        console.error(`[login] ${e.message}`);
        return req.session.destroy(() => res.status(503).send(views.loginForm('Could not set up a protected session')));
      }
      return req.session.save((e) => (e ? next(e) : res.redirect('/dashboard')));
    });
  });
  app.post('/logout', (req, res) => req.session.destroy(() => { res.clearCookie('sid'); res.redirect('/login'); }));

  // --- device-bound key plumbing (B3) -----------------------------------------------------------------
  app.post('/auth/challenge', requireLogin, async (req, res) => {
    try { res.json(await engine.nonce(req.sessionID)); } catch (e) { res.status(e.status === 409 ? 409 : 503).json({ error: 'no_challenge' }); }
  });
  // Reaching this handler means riskGuard already verified the presence proof in X-Device-Proof.
  app.post('/auth/presence', requireLogin, (_req, res) => res.status(204).end());

  // --- passkey step-up (C2) -------------------------------------------------------------------------
  app.get('/stepup', requireLogin, (_req, res) => res.send(views.stepupPage()));
  app.post('/stepup/options', requireLogin, async (req, res) => {
    const cred = passkeys.get(req.session.user);
    if (!cred) return res.status(409).json({ error: 'no_passkey_registered' });
    const options = await webauthn.generateAuthenticationOptions({
      rpID: rp.id, allowCredentials: [{ id: cred.id, transports: cred.transports }], userVerification: 'preferred', timeout: 20000,
    });
    req.session.webauthn = { challenge: options.challenge, exp: Date.now() + 60000 };
    return res.json(options);
  });
  app.post('/stepup/verify', requireLogin, async (req, res) => {
    const fail = async (why) => {
      const client = String((req.body && req.body.reason) || '').replace(/[^\w.-]/g, '').slice(0, 40);
      console.warn(`[stepup] FAILED (${why}${client ? `; browser reported ${client}` : ''}); terminating session`);
      await engine.outcome({ ...guard.context(req), success: false }).catch(() => {});
      return endSession(req, res, 401, { error: 'step_up_failed', message: 'Step-up failed; session terminated.' });
    };
    const pending = req.session.webauthn;
    delete req.session.webauthn; // a challenge is single use
    const cred = passkeys.get(req.session.user);
    if (!pending || pending.exp < Date.now() || !req.body || !req.body.response || !cred) return fail('no pending challenge, response or passkey');
    let result;
    try {
      result = await webauthn.verifyAuthenticationResponse({
        response: req.body.response, expectedChallenge: pending.challenge, expectedOrigin: rp.origins, expectedRPID: rp.id,
        credential: { id: cred.id, publicKey: Buffer.from(cred.publicKey, 'base64url'), counter: cred.counter, transports: cred.transports },
      });
    } catch (e) { return fail(e.message); }
    if (!result.verified) return fail('assertion not verified');
    passkeys.update(req.session.user, { counter: result.authenticationInfo.newCounter });
    const out = await engine.outcome({ ...guard.context(req), success: true });
    return res.json({ ok: true, elevated_seconds: out.elevated_seconds });
  });

  // --- passkey registration (writes: the guard demands a device proof for the POSTs) ------------------
  app.get('/passkey/setup', requireLogin, (_req, res) => res.send(views.passkeyPage()));
  app.post('/passkey/register/options', requireLogin, async (req, res) => {
    // An existing passkey is never silently replaced (a hijacked session must not add its own).
    if (passkeys.get(req.session.user)) return res.status(409).json({ error: 'passkey_already_registered' });
    const options = await webauthn.generateRegistrationOptions({
      rpName: rp.name, rpID: rp.id, userName: req.session.user, userID: new TextEncoder().encode(req.session.user),
      attestationType: 'none', authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    });
    req.session.webauthn = { challenge: options.challenge, exp: Date.now() + 60000 };
    return res.json(options);
  });
  app.post('/passkey/register/verify', requireLogin, async (req, res) => {
    const pending = req.session.webauthn;
    delete req.session.webauthn;
    if (!pending || pending.exp < Date.now() || !req.body || !req.body.response) return res.status(400).json({ error: 'no_pending_registration' });
    if (passkeys.get(req.session.user)) return res.status(409).json({ error: 'passkey_already_registered' });
    try {
      const r = await webauthn.verifyRegistrationResponse({
        response: req.body.response, expectedChallenge: pending.challenge, expectedOrigin: rp.origins, expectedRPID: rp.id,
      });
      if (!r.verified) return res.status(400).json({ error: 'not_verified' });
      const c = r.registrationInfo.credential;
      passkeys.set(req.session.user, { id: c.id, publicKey: Buffer.from(c.publicKey).toString('base64url'), counter: c.counter, transports: c.transports || [] });
      return res.json({ ok: true });
    } catch (e) { return res.status(400).json({ error: 'registration_failed', message: e.message }); }
  });

  // --- the demo "bank" ---------------------------------------------------------------------------------
  app.get('/api/me', requireLogin, (req, res) => res.json({ user: req.session.user, balance: req.session.balance, risk: req.risk }));
  app.get('/dashboard', requireLogin, (req, res) => res.send(views.dashboardPage(req.session.user, req.session.balance)));
  app.post('/transfer', requireLogin, (req, res) => {
    const { to, amount } = req.body || {};
    if (typeof to !== 'string' || !to || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'bad_request' });
    if (amount > req.session.balance) return res.status(400).json({ error: 'insufficient_funds' });
    req.session.balance -= amount;
    return res.json({ ok: true, message: `Transferred $${amount} to ${to} (demo: no money moved)`, balance: req.session.balance });
  });

  app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'internal_error' }); });
  return app;
}

async function main() {
  require(path.join(ROOT, 'scripts', 'ensure-env.js')).ensureEnv();
  const { createClient } = require('redis');
  const RedisStore = require('connect-redis').default;
  const client = createClient({ url: process.env.REDIS_URL });
  client.on('error', (e) => console.error('[redis]', e.message));
  await client.connect();
  const app = createApp({ store: new RedisStore({ client, prefix: 'sess:' }), adminStore: new RedisStore({ client, prefix: 'admin:' }) });
  const port = Number(process.env.APP_PORT || 3000);
  app.listen(port, '127.0.0.1', () => console.log(`[app] listening on http://localhost:${port}`));
}

module.exports = { createApp };
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
