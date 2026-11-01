# SessionGuard

**Stolen session cookies stop working the moment the attacker is no longer the user, and you can see why.**

SessionGuard is a continuous-authentication layer for web apps. It defends against session hijacking: infostealer malware copies a logged-in user's cookie, and the attacker walks in without a password or MFA prompt. SessionGuard binds each session to the browser that created it, scores every request, forces a Passkey step-up when something looks wrong, and writes a plain-English rationale for every decision.

> Built for the Meta Global AI Developer Hackathon (Oct 26 – Nov 4, 2026). Track: Indie Developer. Theme: Push the Frontier.

<!-- TODO: add a screenshot or GIF of the demo console here: ![demo](docs/demo.gif) -->

## The problem

Multi-factor authentication protects the login. It does nothing for the session afterwards. Whoever holds the cookie *is* the user. Infostealer malware exports browser cookies in bulk, and the attacker replays them from another machine.

## What it does

A request passes through up to four layers. Each layer catches attackers the previous one misses.

| Layer | What it does | What it does NOT stop |
|---|---|---|
| **1. Deterministic checks** (IP, ASN, user-agent, header fingerprint, impossible travel) | Catches a lazy replay from a different place or client. | An attacker who copies the victim's user-agent, headers and IP. Layer 1 allows this (score 0). That gap is kept as a test. Header fingerprints are a weak signal because headers are copyable. |
| **2. Device-bound key** (non-extractable WebCrypto key, single-use 30s nonces, per-action proofs) | A stolen cookie without the key cannot perform `/transfer`, and cannot read after the 30s presence window. The key cannot be copied out of the browser. | **Malware running on the victim's own device can still *use* the key** (ask the browser to sign); it just can't copy it. Login-time compromise and live phishing relays are also out of scope. |
| **3. Passkey step-up** (WebAuthn) | A "challenge" verdict requires a real Passkey assertion. Success grants 5 minutes of elevated trust, failure or timeout terminates the session. | An attacker who also controls the victim's authenticator. |
| **4. Explainer** (LLM, async) | Writes a short rationale per decision for analysts. | It protects nothing. It can never change the action. |

**Decision policy:** score under 30 allows, 30–70 forces step-up, over 70 terminates the session.

## Demo

The demo console shows the whole attack on one screen: a victim, an attacker simulator, and a live SessionGuard feed.

1. Victim makes a normal transfer. Allowed.
2. The attacker steals the session cookie.
3. **Lazy copy** (different browser and IP) is blocked by layer 1.
4. **Perfect copy** (identical user-agent, headers and IP) passes layer 1 and is stopped by the device-bound key. Toggle the device key off in the console and the same attack succeeds.

The attacker simulator is a script that runs the same replay a person would do by hand, against this demo app only.

## Quickstart

Requirements: Node 20.12+, Python 3.10+, Redis.

```bash
git clone <this-repo-url> && cd <repo-folder>
redis-server                  # or: docker run -p 6379:6379 redis:7
npm run setup                 # venv + pip + npm + Playwright Chromium
npm run demo                  # three attack scenarios + summary
npm test                      # pytest + node tests + browser tests
```

<!-- TODO: add the exact command and URL to start the demo console (DEMO_MODE=true ...) -->

Dashboard: run `npm run engine` and `npm run app`, then open `http://localhost:3000/admin`. Demo and admin credentials are generated into `.env` on first run (see `.env.example`). `.env` is git-ignored.

## How it works

- **Fusion** (`risk-engine/app/scoring.py`): clamped sum of signals. IP change +10, ASN +20, user-agent +30, fingerprint +10, impossible travel +40; valid proof -25; stale +35, missing +50, expired +50, invalid +80.
- **Binding:** the login page generates the key before submitting and sends only the public key, so the session is born bound. Rebinding is refused; a new key needs a new full login.
- **Proofs:** a signature over `"<nonce>|<purpose>"`, where purpose is `presence` or `METHOD path`. Each nonce is single-use.
- **Events** live in SQLite, keyed by a short hash of the session id (the id is a bearer token and is never stored). Live state is in Redis.
- **Fails closed:** if the engine errors, the app returns 503 instead of letting the request through (configurable).

## The AI explainer

After each decision, an async job turns the fired signals into a short analyst-style rationale and stores it next to the event. The dashboard shows which provider wrote it.

- Providers: `muse` (Meta Muse Spark, default), `ollama` (local Llama), `openai_compatible` (any OpenAI-style endpoint), and `template` (deterministic, no LLM).
- `LLM_FALLBACK_CHAIN` (for example `muse,ollama,template`) tries providers in order on timeout or error. The template is always the last resort, so the system works with the LLM off.
- **The LLM never decides.** The action is computed first, independently. Even if a model replies "ALLOW", the decision does not change (tested).
- **Prompt-injection hardening:** attacker-controlled strings (user-agent, headers) are truncated, sanitized and sent only as quoted data fields. A test confirms an injected user-agent does not change the outcome. Output is escaped on the dashboard (XSS test included).

**Implementation status (honest):** the Muse Spark adapter is implemented and tested against a stub server. It has **not** been verified against the live API, because no API key was available. The demo runs on the template provider unless a key or a local Ollama model is configured.

## Testing

`npm test` runs Python (risk engine), Node (app and middleware) and browser tests with a real WebAuthn virtual authenticator. Covered: legitimate vs replayed sessions, the adaptive attacker, proof replay and cross-action reuse, forced rebinding, spoofed `X-Forwarded-For`, fail-closed behavior, passkey step-up, prompt injection and dashboard XSS.

## Limitations

- Attacks are simulated against our own demo app. There is no evaluation on real-world traffic.
- Malware that controls the victim's live browser can still use the device key.
- The geo-IP table is a small demo table. Demo passkeys use a virtual authenticator, not hardware.
- The admin login is demo-grade (single password, no rate limit, no MFA). The passkey store is a JSON file.
- No behavioral biometrics. That layer is planned, not built.
- Muse Spark has not been tested live (see above).

## Built during the hackathon

All code in this repository was written between Oct 26 and Nov 4, 2026, and the commit history shows it. The code was written with the Muse Code agent. Third-party libraries are used as dependencies and are not claimed as our work: Express, FastAPI, Redis, SQLite, SimpleWebAuthn, Playwright, scikit-learn (if used), and the Node and Python standard libraries.

## Security and ethics

Everything here targets the local demo app. The attacker simulator refuses non-local targets. The (planned) behavioral layer would collect timing statistics only, never key identities or typed text. Only sanitized signals are ever sent to an LLM.

## License

MIT. See `LICENSE`.
