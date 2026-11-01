'use strict';
// engineClient: thin authenticated client for the risk engine's service endpoints.
// The engine key never reaches the browser; only server code uses this.
function createEngineClient({ engineUrl, apiKey, timeoutMs = 1500 }) {
  if (!engineUrl || !apiKey) throw new Error('engineClient: engineUrl and apiKey are required');
  const headers = { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` };

  async function call(method, path, body) {
    const res = await fetch(`${engineUrl}${path}`, {
      method, headers, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(timeoutMs),
    });
    const json = await res.json().catch(() => null);
    if (!res.ok) throw Object.assign(new Error(`engine ${path} returned HTTP ${res.status}`), { status: res.status });
    return json;
  }

  return {
    evaluate: (body) => call('POST', '/evaluate', body),
    bind: (session_id, public_key) => call('POST', '/bind', { session_id, public_key }),
    nonce: (session_id) => call('POST', '/nonce', { session_id }),
    outcome: (body) => call('POST', '/stepup/outcome', body),
    admin: (path) => call('GET', path),
    // demo console only (the engine 404s these unless DEMO_MODE=true)
    demoLayers: (body) => call(body ? 'POST' : 'GET', '/demo/layers', body),
    demoEvents: (afterId = 0) => call('GET', `/demo/events?after_id=${Number(afterId) || 0}&limit=200`),
  };
}

module.exports = { createEngineClient };
