# session-guard — Phase 2

Demo bank app (Express + Redis sessions) protected by a FastAPI risk engine, a device-bound browser
key, passkey step-up, async LLM rationales and an admin dashboard. Everything here targets the local
demo app only.

## Run
    redis-server                  # or: docker run -p 6379:6379 redis:7
    npm run setup                 # venv + pip + npm + Playwright Chromium
    npm run demo                  # 3 scenarios + summary (creates/upgrades .env, registers the demo passkey)
    npm test                      # pytest + node tests + browser tests (Chromium)

No Chromium download access? `export PW_CHROMIUM_PATH=/path/to/chromium`.
Dashboard: run `npm run engine` and `npm run app`, open http://localhost:3000/admin
(`ADMIN_USER` / `ADMIN_PASSWORD` in `.env`). Demo user: `DEMO_USER` / `DEMO_PASSWORD`.
Judges' console: `npm run console`, then open http://localhost:3000/demo (see "Demo console" below).
Other scripts: `npm run register-passkey [-- --force]`, `npm run netsim`.

## Layers, and what each one does NOT protect against

| Layer | What it does | Does NOT protect against |
|---|---|---|
| **1. Deterministic checks** (IP, ASN, UA, header fingerprint, impossible travel) | Catches a replay from a different place or client. | An attacker who copies the victim's UA, headers and IP (the *adaptive attacker*: score 0, allowed; kept as a test, `layer1_gap`). The header fingerprint is a **weak** signal (weight 10): headers are copyable. Geo data is a tiny demo table. |
| **2. Device-bound key** (non-extractable WebCrypto key, single-use 30 s nonces, per-action proofs) | A stolen cookie without the key cannot do `/transfer` (needs its own proof) or read after the 30 s presence window. The key cannot be copied out of the browser. | **Malware or XSS running on the victim's own device/origin can still *use* the key** (ask it to sign): it just can't copy it. Reads inside the 30 s window after a legitimate presence proof are not stopped by layer 2. Login-time compromise (attacker has the password and logs in with their own key). Real-time phishing relays during login. A compromised server, engine or Redis. |
| **3. Passkey step-up** (WebAuthn via SimpleWebAuthn) | A "challenge" verdict needs a real passkey assertion; success grants 5 min of elevated trust, failure or a 60 s timeout terminates. | An attacker who also controls the victim's authenticator. The elevated window suppresses *challenge* verdicts (never *terminate*) for 5 minutes. The timeout is enforced at the next request, not by a timer. Demo passkeys live in a **virtual** authenticator, not hardware. |
| **4. LLM rationale** | Writes a paragraph for analysts, async, after the decision. | It protects nothing: it can never change the action. Treat its text as untrusted (it is escaped, truncated, and has a template fallback). |
| **5. Dashboard** | Session list, score timeline, signals, rationale. | Hardening of the admin login itself: single password, no rate limit, no MFA (demo-grade). |

Also out of scope: behavioral biometrics / model training (Phase 3), CSRF tokens beyond SameSite=Lax,
and the demo's JSON passkey store (use a database in production).

## How it fits together
- **Fusion** (`risk-engine/app/scoring.py`): clamped sum. IP +10, ASN +20, UA +30, fingerprint +10, travel +40;
  `proof_valid` **-25**; `proof_stale` +35, `proof_missing` +50, `proof_expired` +50 (step-up);
  `proof_invalid` +80 (terminate). <30 allow, 30-70 challenge, >70 terminate.
- **Binding:** the login form generates the key *before* submitting and sends only the public key, so the
  session is born bound. The engine's `/bind` is service-only, atomic and refuses any rebind; a new key
  needs a new full login (new session id).
- **Proofs:** signature over `"<nonce>|<purpose>"`, purpose = `presence` or `METHOD path`, nonce single use.
- **Unbound sessions** (`REQUIRE_DEVICE_KEY=false`, non-browser tooling) behave exactly like Phase 1.
- **Events** live in SQLite, keyed by a short hash of the session id (the id itself is a bearer token and is
  never stored or shown). Live state is in Redis.

## Configuration (`.env`, see `.env.example`)
- `TRUST_PROXY` (default **blank = trust nobody**): `X-Forwarded-For` is read only when the TCP peer is in
  this list of proxy IPs/CIDRs, and then only the right-most untrusted hop is used. Hop counts are rejected;
  `true` is mapped to `loopback` with a warning. `npm run demo` sets `loopback` for its edge simulator
  (`scripts/netsim.js`), which stands in for a real proxy so one machine can fake different locations.
- `EXPOSE_SIGNALS=true` is demo-only; set `false` in production.
- `LLM_PROVIDER=muse|ollama|openai_compatible|template`, `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`,
  `LLM_TIMEOUT_SECONDS`, `LLM_MAX_TOKENS`, `LLM_REASONING_EFFORT`, `LLM_FALLBACK_CHAIN`. See
  [LLM rationales](#llm-rationales) below.
- Tunables: `PROOF_MAX_AGE_SECONDS` (30), `NONCE_TTL_SECONDS` (30), `ELEVATED_SECONDS` (300),
  `STEPUP_TIMEOUT_SECONDS` (60).
- WebAuthn needs `localhost` or HTTPS; origins default to `http://localhost:$APP_PORT`.

## LLM rationales

Rationales are written asynchronously *after* the deterministic decision. They are for analysts only and
can never change the action.

Providers (all use the OpenAI-style `POST /chat/completions`):

| `LLM_PROVIDER` | Default base URL | Default model | Notes |
|---|---|---|---|
| `muse` (default) | `https://api.meta.ai/v1` | `muse-spark-1.1` | Set `LLM_API_KEY`. If the reply text is empty, retries once with doubled `LLM_MAX_TOKENS` (at least 1024) and `reasoning_effort=minimal`. |
| `ollama` | `http://localhost:11434/v1` | `llama3.1` | Local; no key needed. |
| `openai_compatible` | `https://api.openai.com/v1` | none (required) | Any OpenAI-compatible endpoint; set `LLM_MODEL` and usually `LLM_BASE_URL`/`LLM_API_KEY`. |
| `template` | — | — | No LLM; deterministic template only. |

`LLM_BASE_URL` and `LLM_MODEL` override a provider's defaults. `LLM_MAX_TOKENS` (default 512) and
`LLM_REASONING_EFFORT` (default blank; Muse's empty-reply retry uses `minimal`) are configurable too.

**Fallback chain.** Set `LLM_FALLBACK_CHAIN` to a comma-separated list, e.g.
`LLM_FALLBACK_CHAIN=muse,ollama,template`. Providers are tried in order; a timeout, HTTP error, empty
reply or unknown provider moves on to the next. If none succeed, the deterministic template is used. With
no chain configured, the engine tries `LLM_PROVIDER` and then the template.

**Privacy.** Only sanitized, truncated signals are sent to the LLM: a small JSON document containing the
already-made decision, the route, signal names/weights, and attacker-controlled strings confined to
`untrusted_data` fields. Raw session ids, cookies, passwords, device keys and the full request never leave
the engine. The model's output is treated as untrusted: cleaned, truncated, stored separately, and rendered
as text (never HTML).

## Notes on Phase 1 tests
All Phase 1 tests still pass. Two test *settings* changed because the defaults became secure: the Phase 1
non-browser e2e test now sets `REQUIRE_DEVICE_KEY=false` (its curl-style login has no device key), and it
keeps `TRUST_PROXY=true`, which is now interpreted as `loopback`. The fingerprint weight changed (35 -> 10);
no Phase 1 assertion depended on it.

## Demo console (`/demo`)
`npm run console` starts the engine and app with `DEMO_MODE=true` (and `TRUST_PROXY=loopback`) and prints the URL:
**http://localhost:3000/demo**. Three panels: the victim's bank (this browser holds the real non-extractable key),
an attacker simulator (steals the cookie, replays it server-side), and SessionGuard's live feed with rationales.
Top bar: *Reset demo*, layer switches (*Layer 1 checks*, *Device key*), and *Run full story*.
- Off unless `DEMO_MODE=true` (exactly); then served only to loopback clients with a localhost `Host`. POSTs need `X-Demo-Console: 1`.
- The attacker endpoint only attacks this app: any other target (non-loopback host, other port) is refused with 403.
- The layer switches are an engine-side demo filter (`/demo/layers`, 404 unless the engine has `DEMO_MODE=true` too). They
  only drop a layer's signals before fusion; checks, weights and thresholds are untouched, and with `DEMO_MODE` off the
  filter cannot be changed.
- The victim is `127.0.0.1`, which is not in the demo geo table, so a Lazy copy fires IP + user-agent + fingerprint
  (and the device key), not ASN or impossible travel.
- Perfect copy with the device key ON ends in STEP-UP (the attacker has no passkey), not instant termination.
