'use strict';
// console: `npm run console`. Starts the risk engine and the demo app with DEMO_MODE=true (the /demo
// console is off otherwise) and TRUST_PROXY=loopback (so the Lazy copy's different IP is visible to layer 1),
// then prints the URL. Needs Redis (REDIS_URL). Ctrl+C stops both. Not used by `npm run demo` or the tests.
const path = require('node:path');
const { spawn } = require('node:child_process');
const { ensureEnv, ROOT } = require('./ensure-env');
const { startEngine, waitFor } = require('./engine');

async function main() {
  ensureEnv();
  const { createClient } = require('redis');
  const probe = createClient({ url: process.env.REDIS_URL, socket: { reconnectStrategy: false } });
  probe.on('error', () => {});
  try { await probe.connect(); await probe.ping(); await probe.quit(); } catch {
    throw new Error(`Redis not reachable at ${process.env.REDIS_URL}. Start it with "redis-server" or "docker run -p 6379:6379 redis:7".`);
  }
  const enginePort = process.env.ENGINE_PORT || 8000;
  const appPort = process.env.APP_PORT || 3000;
  const demoEnv = { DEMO_MODE: 'true', TRUST_PROXY: 'loopback' };
  const children = [startEngine({ port: enginePort, env: demoEnv })];
  const cleanup = () => children.forEach((c) => c.kill());
  process.on('SIGINT', () => { cleanup(); process.exit(0); });
  process.on('SIGTERM', () => { cleanup(); process.exit(0); });
  await waitFor(`http://127.0.0.1:${enginePort}/health`);
  children.push(spawn(process.execPath, [path.join(ROOT, 'demo-app', 'server.js')], { stdio: 'inherit', env: { ...process.env, ...demoEnv } }));
  await waitFor(`http://127.0.0.1:${appPort}/health`);
  console.log(`\n  Demo console ready. Open:  http://localhost:${appPort}/demo\n  (Ctrl+C to stop. Use the same hostname "localhost" the page was opened with.)\n`);
  children.forEach((c) => c.on('exit', (code) => { cleanup(); process.exit(code ?? 0); }));
}
main().catch((e) => { console.error(`\n[console] ${e.message}`); process.exit(1); });
