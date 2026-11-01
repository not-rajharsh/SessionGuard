"""main: FastAPI risk engine. POST /evaluate -> {score, signals, action}.

Per call: terminated? -> baseline (login call)? -> step-up timeout? -> layer 1
checks -> layer 2 device proof (only for sessions bound to a device key) ->
fusion -> step-up handling -> log event -> (async) rationale.
Other service endpoints: /bind (once per session, never rebindable), /nonce,
/stepup/outcome, /admin/sessions*. All need `Authorization: Bearer $ENGINE_API_KEY`.
Unbound sessions (no device key) behave exactly like Phase 1.
Run: uvicorn --factory app.main:create_app --host 127.0.0.1 --port 8000
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import math
import re
import time
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Path
from pydantic import BaseModel, Field, field_validator

from .checks import WEIGHTS, Observation, Signal, run_checks
from .config import Settings, get_settings
from .events import EventLog
from .explain import Explanation, explain, template_explanation
from .geo import GeoDB
from .proof import new_nonce, parse_public_key, signed_message, verify_signature
from .scoring import decide
from .store import MemoryStore, RedisStore

log = logging.getLogger("risk")


def session_ref(session_id: str) -> str:
    """Short hash shown in logs/dashboard. The real session id is a bearer token."""
    return hashlib.sha256(session_id.encode()).hexdigest()[:12]


class Context(BaseModel):
    session_id: str = Field(min_length=8, max_length=256)
    ip: str
    user_agent: str = Field(max_length=1024)
    fingerprint_hash: str = Field(min_length=1, max_length=128)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: str) -> str:
        return str(ipaddress.ip_address(v))  # raises ValueError -> 422


class EvaluateRequest(Context):
    kind: Literal["read", "write", "auth"] = "read"  # auth = proof/step-up/login plumbing
    route: str = Field(default="", max_length=300)
    proof_nonce: str | None = Field(default=None, max_length=128)
    proof_signature: str | None = Field(default=None, max_length=256)
    proof_purpose: str | None = Field(default=None, max_length=256)


class OutcomeRequest(Context):
    success: bool


class BindRequest(BaseModel):
    session_id: str = Field(min_length=8, max_length=256)
    public_key: str = Field(min_length=40, max_length=400)


class NonceRequest(BaseModel):
    session_id: str = Field(min_length=8, max_length=256)


class LayersRequest(BaseModel):
    layer1: bool | None = None
    device_key: bool | None = None


class SignalOut(BaseModel):
    name: str
    weight: int
    detail: str


class EvaluateResponse(BaseModel):
    score: int
    signals: list[SignalOut]
    action: Literal["allow", "challenge", "terminate"]


def _clean_route(route: str) -> str:
    return re.sub(r"[^\x20-\x7e]", "?", route)[:120]


def create_app(settings: Settings | None = None, store=None, geo: GeoDB | None = None,
               events: EventLog | None = None, clock=time.time, explain_fn=None) -> FastAPI:
    s = settings or get_settings()
    if not s.engine_api_key:
        raise RuntimeError("ENGINE_API_KEY is not set (see .env.example)")
    store = store or (
        MemoryStore(s.state_ttl_seconds) if s.risk_state == "memory"
        else RedisStore(s.redis_url, s.state_ttl_seconds)
    )
    geo = geo or GeoDB.from_json(s.geo_path)
    events = events or EventLog(s.sqlite_path)
    explain_fn = explain_fn or (lambda sigs, ctx: explain(sigs, ctx, settings=s))
    app = FastAPI(title="session-guard risk engine")

    # DEMO_MODE only: the console can switch a layer's signals off to show what each layer buys.
    # Outside DEMO_MODE nothing can change this dict and _layer_on() is always True, so the
    # checks, weights and thresholds behave exactly as before.
    layers = {"layer1": True, "device_key": True}

    def _layer_on(name: str) -> bool:
        return (not s.demo_mode) or layers[name]

    def require_key(authorization: str = Header(default="")):
        if not hmac.compare_digest(authorization, f"Bearer {s.engine_api_key}"):
            raise HTTPException(status_code=401, detail="unauthorized")

    # --- rationale (async, after the decision; can never change it) ----------------------
    def _explain_and_store(event_id: int, signal_dicts: list[dict], ctx: dict) -> None:
        try:
            ex = explain_fn(signal_dicts, ctx)
        except Exception:  # noqa: BLE001
            ex = Explanation(text=template_explanation(signal_dicts, ctx), source="template", provider="template", model="template", latency_ms=0)
        # ex might be old style
        provider = getattr(ex, 'provider', None) or getattr(ex, 'source', 'template')
        model = getattr(ex, 'model', '') or ''
        latency_ms = getattr(ex, 'latency_ms', 0) or 0
        source = getattr(ex, 'source', provider)
        events.set_rationale(event_id, ex.text, source, provider=provider, model=model, latency_ms=latency_ms)

    def _log_event(background: BackgroundTasks, c: Context, now: float, route: str, score: int,
                   action: str, signals: list[Signal], rationale: str | None = None) -> None:
        event_id = events.record(session_id=session_ref(c.session_id), ip=c.ip,
                                 user_agent=c.user_agent, fingerprint_hash=c.fingerprint_hash,
                                 route=route, score=score, action=action, signals=signals, ts=now)
        if action == "terminate":
            log.warning("ALERT session=%s score=%d signals=%s", session_ref(c.session_id), score,
                        [x.name for x in signals])
        if rationale is not None:
            events.set_rationale(event_id, rationale, "template", provider="template", model="template", latency_ms=0)
        elif not any(x.weight > 0 for x in signals):
            events.set_rationale(event_id, "No risk signals fired; the request matched the session baseline.", "template", provider="template", model="template", latency_ms=0)
        else:
            background.add_task(_explain_and_store, event_id, [x.to_dict() for x in signals],
                                {"score": score, "action": action, "route": route})

    # --- layer 2 ---------------------------------------------------------------------------
    def _check_proof(sid: str, binding: str, req: EvaluateRequest, now: float) -> tuple[str, str]:
        rec = store.pop_nonce(req.proof_nonce)  # single use, consumed even if the signature is bad
        if rec is None:
            return "expired", "challenge nonce unknown, expired or already used"
        if rec["exp"] < now:
            return "expired", "challenge nonce expired"
        if rec["sid"] != sid:
            return "invalid", "challenge was issued to a different session"
        msg = signed_message(req.proof_nonce, req.proof_purpose or "")
        if not verify_signature(binding, msg, req.proof_signature):
            return "invalid", "signature does not match the bound device key for this action"
        return "ok", ""

    def _proof_signals(sid: str, binding: str, req: EvaluateRequest, now: float) -> list[Signal]:
        if req.proof_nonce and req.proof_signature:
            verdict, why = _check_proof(sid, binding, req, now)
            if verdict == "ok":
                store.set_last_proof(sid, now)
                return [Signal("proof_valid", WEIGHTS["proof_valid"],
                               f"device key signed '{req.proof_purpose}'", {"purpose": req.proof_purpose or ""})]
            name = "proof_expired" if verdict == "expired" else "proof_invalid"
            return [Signal(name, WEIGHTS[name], f"device proof rejected: {why}", {"reason": why})]
        if req.kind == "auth":
            return []  # must stay reachable so the client can obtain/refresh proofs
        if req.kind == "write":
            return [Signal("proof_missing", WEIGHTS["proof_missing"],
                           "state-changing request without a device proof")]
        last = store.get_last_proof(sid)
        if last is not None and now - last <= s.proof_max_age:
            return [Signal("proof_valid", WEIGHTS["proof_valid"],
                           f"device presence proven {now - last:.0f}s ago", {"age_seconds": round(now - last)})]
        age = "ever" if last is None else f"in the last {now - last:.0f}s"
        return [Signal("proof_stale", WEIGHTS["proof_stale"], f"no device proof received {age}")]

    # ---------------------------------------------------------------------------------------
    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/evaluate", response_model=EvaluateResponse, dependencies=[Depends(require_key)])
    def evaluate(req: EvaluateRequest, background: BackgroundTasks):
        sid, now = req.session_id, clock()
        cur = Observation(req.ip, req.user_agent, req.fingerprint_hash, now)
        route = _clean_route(req.route)

        def finish(score: int, action: str, signals: list[Signal]) -> EvaluateResponse:
            _log_event(background, req, now, route, score, action, signals)
            return EvaluateResponse(score=score, action=action,
                                    signals=[SignalOut(name=x.name, weight=x.weight, detail=x.detail)
                                             for x in signals])

        if store.is_terminated(sid):
            return finish(100, "terminate",
                          [Signal("session_terminated", 100, "session was already terminated")])

        binding = store.get_binding(sid)
        baseline = store.get_baseline(sid)
        if baseline is None:
            if binding is not None:  # never silently re-baseline a bound session
                store.mark_terminated(sid)
                return finish(100, "terminate",
                              [Signal("state_expired", 100, "session state expired; log in again")])
            store.set_baseline(sid, cur)  # trust-on-first-use: the app calls this at login
            store.set_last_seen(sid, cur)
            return finish(0, "allow", [])

        pending = store.get_stepup_pending(sid)
        if pending is not None and now - pending > s.stepup_timeout:
            store.mark_terminated(sid)
            return finish(100, "terminate",
                          [Signal("stepup_timeout", 100, "passkey step-up was not completed in time")])

        last_seen = store.get_last_seen(sid) or baseline
        signals = (run_checks(baseline, last_seen, cur, geo,
                              max_kmh=s.max_travel_kmh, min_km=s.min_travel_km)
                   if _layer_on("layer1") else [])
        if binding is not None and _layer_on("device_key"):
            signals += _proof_signals(sid, binding, req, now)
        score, action = decide(signals)

        if action == "challenge":
            if store.get_elevated_until(sid) > now:
                action = "allow"
                signals.append(Signal("stepup_elevated", 0, "recent passkey step-up is still valid"))
            elif pending is None:
                store.set_stepup_pending(sid, now)
        if action == "allow":
            store.set_last_seen(sid, cur)  # only allowed requests move the reference point
        elif action == "terminate":
            store.mark_terminated(sid)
        return finish(score, action, signals)

    @app.post("/bind", dependencies=[Depends(require_key)])
    def bind(req: BindRequest):
        """Called by the app inside the login handler only; never exposed to browsers."""
        sid = req.session_id
        if store.is_terminated(sid):
            raise HTTPException(409, "session terminated")
        if store.get_baseline(sid) is None:
            raise HTTPException(409, "no baseline: evaluate the login request first")
        try:
            parse_public_key(req.public_key)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        if not store.set_binding(sid, req.public_key.strip()):  # atomic: first writer wins
            raise HTTPException(409, "session is already bound to a device key")
        store.set_last_proof(sid, clock())  # login itself counts as the first presence
        return {"bound": True}

    @app.post("/nonce", dependencies=[Depends(require_key)])
    def nonce(req: NonceRequest):
        sid = req.session_id
        if store.is_terminated(sid) or store.get_binding(sid) is None:
            raise HTTPException(409, "session is terminated or has no device key")
        n = new_nonce()
        store.put_nonce(n, sid, clock() + s.nonce_ttl, int(math.ceil(s.nonce_ttl)) + 1)
        return {"nonce": n, "expires_in": s.nonce_ttl}

    @app.post("/stepup/outcome", dependencies=[Depends(require_key)])
    def stepup_outcome(req: OutcomeRequest, background: BackgroundTasks):
        sid, now = req.session_id, clock()
        if store.is_terminated(sid):
            return {"action": "terminate", "elevated_seconds": 0}
        if req.success:
            store.set_elevated_until(sid, now + s.elevated_seconds)
            store.clear_stepup_pending(sid)
            _log_event(background, req, now, "stepup", 0, "allow",
                       [Signal("stepup_passed", 0, "passkey assertion verified")],
                       rationale=f"Passkey assertion verified; trust elevated for {s.elevated_seconds:.0f} s.")
            return {"action": "allow", "elevated_seconds": s.elevated_seconds}
        store.mark_terminated(sid)
        _log_event(background, req, now, "stepup", 100, "terminate",
                   [Signal("stepup_failed", 100, "passkey step-up failed or was abandoned")])
        return {"action": "terminate", "elevated_seconds": 0}

    # --- dashboard data (the app proxies these behind its admin login) ------------------------
    @app.get("/admin/sessions", dependencies=[Depends(require_key)])
    def admin_sessions():
        now, rows = clock(), events.sessions()
        for r in rows:
            r["status"] = ("terminated" if r["terminated"]
                           else "active" if now - r["last_ts"] <= s.state_ttl_seconds else "expired")
        return {"sessions": rows}

    @app.get("/admin/sessions/{ref}", dependencies=[Depends(require_key)])
    def admin_session(ref: str = Path(pattern=r"^[0-9a-f]{12}$")):
        return {"ref": ref, "events": events.session_events(ref)}

    if s.demo_mode:  # routes do not exist at all (404) unless DEMO_MODE=true
        @app.get("/demo/layers", dependencies=[Depends(require_key)])
        def demo_layers_get():
            return dict(layers)

        @app.post("/demo/layers", dependencies=[Depends(require_key)])
        def demo_layers_set(req: LayersRequest):
            for k, v in req.model_dump().items():
                if v is not None:
                    layers[k] = v
            return dict(layers)

        @app.get("/demo/events", dependencies=[Depends(require_key)])
        def demo_events(after_id: int = 0, limit: int = 200):
            return {"latest_id": events.latest_id(),
                    "events": events.after(max(0, after_id), max(1, min(limit, 500)))}

    return app
