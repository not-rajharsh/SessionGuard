// demo.js: the /demo console client. Everything from the server is rendered with textContent only
// (feed text includes attacker-controlled User-Agent strings). Victim actions run in THIS browser with the
// real non-extractable device key (SG from /static/devicekey.js); attacker actions run server-side.
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = String(text); if (cls) e.className = cls; return e; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const money = (n) => `$${Number(n).toLocaleString('en-US')}`;
let busy = false;

async function api(path, body) {
  const r = await fetch(`/demo/api${path}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'content-type': 'application/json', 'x-demo-console': '1' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}
const caption = (t) => { $('caption').textContent = t; };

function show(box, cls, text, detail) {
  box.hidden = false; box.className = `result ${cls}`; box.textContent = text;
  if (detail !== undefined) box.append(el('pre', typeof detail === 'string' ? detail : JSON.stringify(detail, null, 2)));
}

// ---------------- victim ----------------
async function victimLogin() {
  $('vstatus').textContent = 'Logging in and binding a device key…';
  const pubkey = await SG.generate(); // non-extractable key; only the public half leaves the browser
  const r = await api('/victim/login', { pubkey });
  if (!r.body.ok) { $('vstatus').textContent = 'Login failed. Is the stack running with DEMO_MODE=true?'; throw new Error('victim login failed'); }
  $('vstatus').textContent = 'Logged in as demo · device key bound (non-extractable)';
  await viewDashboard(true);
}

async function viewDashboard(quiet) {
  try {
    const p = await SG.presence(); // the heartbeat a real page would send
    if (!p.ok) throw new Error(`presence ${p.status}`);
    const r = await fetch('/api/me', { headers: { accept: 'application/json' } });
    const j = await r.json().catch(() => ({}));
    if (r.status === 200) {
      $('bal').textContent = money(j.balance);
      if (!quiet) show($('v-out'), 'ok', `SUCCESS: dashboard loaded for ${j.user}. Risk ${j.risk ? j.risk.action : 'allow'}, score ${j.risk ? j.risk.score : 0}.`);
      return { status: 200 };
    }
    return quiet ? { status: r.status } : victimBlocked(r.status, j);
  } catch (e) { return quiet ? { status: 401 } : victimBlocked(401, { error: e.message }); }
}

function victimBlocked(status, j) {
  if (status === 403 && j.error === 'step_up_required') show($('v-out'), 'mid', 'STEP-UP required: SessionGuard wants a passkey check.');
  else show($('v-out'), 'bad', 'BLOCKED: session ended. Use “Log in again” or Reset demo.');
  return { status };
}

async function victimTransfer(amount) {
  try {
    const r = await SG.fetchWithProof('/transfer', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ to: 'alice', amount }) });
    const j = await r.json().catch(() => ({}));
    if (r.status === 200) { $('bal').textContent = money(j.balance); show($('v-out'), 'ok', `SUCCESS: ${j.message}`); return { status: 200 }; }
    return victimBlocked(r.status, j);
  } catch (e) { return victimBlocked(401, { error: e.message }); }
}

// ---------------- attacker ----------------
async function steal() {
  const r = await api('/attacker/steal', {});
  if (r.status !== 200) { show($('a-out'), 'mid', r.body.message || 'Could not steal a cookie.'); return false; }
  $('a-cookie').hidden = false; $('a-cookie').textContent = `sid = ${r.body.masked}`;
  show($('a-out'), '', `Cookie captured (${r.body.copied_headers.length} request headers observed too). The device key was NOT in it.`);
  return true;
}

const mode = () => document.querySelector('input[name=mode]:checked').value;
const setMode = (m) => { document.querySelector(`input[name=mode][value=${m}]`).checked = true; };

async function replay() {
  const r = await api('/attacker/replay', { mode: mode(), amount: 5000 });
  const b = r.body;
  if (r.status !== 200) { show($('a-out'), 'mid', b.message || `Replay refused (${b.error})`); return b; }
  const cls = b.verdict === 'succeeded' ? 'bad' : b.verdict === 'stopped' ? 'ok' : 'mid';
  show($('a-out'), cls, b.summary, `${mode() === 'lazy' ? 'Lazy' : 'Perfect'} copy · IP: ${b.request.ip}\nUser-Agent: ${b.request.user_agent}\n\nHTTP ${b.status}\n${JSON.stringify(b.body, null, 2)}`);
  if (b.verdict === 'succeeded') await viewDashboard(true); // the victim's balance visibly drops
  return b;
}

// ---------------- live feed ----------------
const seen = new Map();
const LABEL = { allow: 'ALLOWED', challenge: 'STEP-UP', terminate: 'TERMINATED' };

function renderWhy(box, e) {
  box.replaceChildren();
  if (!e.rationale) { box.className = 'why pending'; box.textContent = 'Writing rationale…'; return; }
  box.className = 'why'; box.append(document.createTextNode(e.rationale));
  if (e.provider) box.append(el('span', `via ${e.provider}`, 'prov'));
}

function renderEvent(e) {
  const box = el('div', undefined, `ev ${e.action} enter`);
  const head = el('div', undefined, 'head');
  head.append(el('span', LABEL[e.action] || e.action, 'badge'), el('span', `score ${e.score}`, 'score'),
    el('span', `${new Date(e.ts * 1000).toLocaleTimeString()} · ${e.route || ''} · ${e.ip}`, 'meta'));
  const chips = el('div', undefined, 'chips');
  const live = e.signals.filter((s) => s.weight !== 0).slice(0, 4);
  for (const s of live) { const c = el('span', `${s.name} ${s.weight > 0 ? '+' : ''}${s.weight}`, `chip ${s.weight < 0 ? 'neg' : 'pos'}`); c.title = s.detail; chips.append(c); }
  if (!live.length) chips.append(el('span', 'no signals', 'chip'));
  const why = el('div'); renderWhy(why, e);
  box.append(head, chips, why);
  return { box, why, hadRationale: !!e.rationale };
}

async function pollFeed() {
  try {
    const r = await api(`/feed${$('plumbing').checked ? '?plumbing=1' : ''}`);
    if (r.status !== 200) return;
    const feed = $('feed');
    for (const e of r.body.events) {
      const cur = seen.get(e.id);
      if (!cur) {
        const n = renderEvent(e); seen.set(e.id, n);
        $('feed-empty').hidden = true; feed.prepend(n.box);
      } else if (!cur.hadRationale && e.rationale) { cur.hadRationale = true; renderWhy(cur.why, e); }
    }
  } catch { /* console keeps polling */ }
}
function clearFeed() { seen.clear(); for (const n of [...$('feed').querySelectorAll('.ev')]) n.remove(); $('feed-empty').hidden = false; }

// ---------------- layers, reset, story ----------------
async function setLayer(key, box) {
  const r = await api('/layers', { [key]: box.checked });
  if (r.status !== 200) { box.checked = !box.checked; caption(r.body.message || 'Layer switches need DEMO_MODE=true on the app and the engine.'); return; }
  syncLayers(r.body.layers);
}
function syncLayers(l) {
  $('layer1').checked = l.layer1; $('devkey').checked = l.device_key;
  caption(`Layer 1 checks: ${l.layer1 ? 'ON' : 'OFF'} · Device key: ${l.device_key ? 'ON' : 'OFF'}${!l.device_key ? '. Try a Perfect copy: nothing but the cookie is checked now.' : ''}`);
}

async function resetDemo() {
  const r = await api('/reset', {});
  if (r.status !== 200) throw new Error(r.body.message || 'reset failed');
  clearFeed(); $('a-out').hidden = true; $('a-cookie').hidden = true; $('v-out').hidden = true;
  syncLayers(r.body.layers); setMode('lazy');
  await victimLogin();
  caption('Demo reset. Victim logged in, device key bound, both layers ON.');
}

function lock(on) { busy = on; for (const b of document.querySelectorAll('button')) b.disabled = on; }
async function guarded(fn) { if (busy) return; lock(true); try { await fn(); } catch (e) { caption(`Error: ${e.message}`); } finally { lock(false); } }

async function runStory() {
  const gap = () => sleep(2000);
  caption('Starting the story: resetting the demo…'); await resetDemo(); await gap();
  caption('1 of 4 · A normal user transfers $500. The device key signs this exact request; SessionGuard allows it.');
  await victimTransfer(500); await gap();
  caption('2 of 4 · The attacker steals the session cookie (think infostealer malware). The device key is non-extractable, so it stays behind.');
  await steal(); await gap();
  caption('3 of 4 · Lazy copy: different browser and IP. Layer 1 flags it and the session is terminated.');
  setMode('lazy'); await replay(); await gap();
  caption('4 of 4 · Perfect copy: new victim session, same headers and IP, so layer 1 sees nothing. The missing device-key proof stops the transfer.');
  await victimLogin(); await steal(); setMode('perfect'); await replay();
  await sleep(1200);
  caption('Done. Layer 1 catches careless copies; only the device key stops a perfect copy. Toggle “Device key” off and replay a Perfect copy to see it succeed.');
}

$('v-dash').onclick = () => guarded(() => viewDashboard(false));
$('v-xfer').onclick = () => guarded(() => victimTransfer(500));
$('v-relogin').onclick = () => guarded(async () => { await victimLogin(); caption('Victim logged in again with a fresh session and key.'); });
$('a-steal').onclick = () => guarded(steal);
$('a-replay').onclick = () => guarded(replay);
$('reset').onclick = () => guarded(resetDemo);
$('story').onclick = () => guarded(runStory);
$('layer1').onchange = (e) => setLayer('layer1', e.target);
$('devkey').onchange = (e) => setLayer('device_key', e.target);
$('plumbing').onchange = clearFeed;

(async () => {
  const st = await api('/state');
  if (st.status !== 200) { caption(st.body.message || 'Console unavailable: start the stack with DEMO_MODE=true.'); return; }
  $('layer1').checked = st.body.layers.layer1; $('devkey').checked = st.body.layers.device_key;
  const me = await viewDashboard(true); // quiet: reuse the session if this browser still has a live one
  if (me.status === 200) $('vstatus').textContent = 'Logged in as demo · device key bound (non-extractable)';
  else await guarded(victimLogin);
  pollFeed(); setInterval(pollFeed, 1500);
})();
