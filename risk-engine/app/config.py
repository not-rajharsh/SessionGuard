"""config: environment-driven settings.

Loads ../.env (repo root) if present, then reads os.environ at call time so
tests can override values. Secrets are never defaulted: ENGINE_API_KEY must be
set explicitly or the engine refuses to start.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[2]
try:
    load_dotenv(ROOT / ".env")
except Exception:
    pass


@dataclass(frozen=True)
class Settings:
    engine_api_key: str
    redis_url: str
    risk_state: str  # "redis" (default) or "memory" (tests only)
    sqlite_path: str
    state_ttl_seconds: int
    max_travel_kmh: float
    min_travel_km: float
    geo_path: str
    # layer 2 (device-bound proof)
    proof_max_age: float = 30.0        # presence proof must be this fresh for reads
    nonce_ttl: float = 30.0            # single-use challenge lifetime
    # passkey step-up
    elevated_seconds: float = 300.0    # trust window after a passed step-up
    stepup_timeout: float = 60.0       # challenge not satisfied in time -> terminate
    # LLM explanations
    llm_provider: str = "muse"         # muse (default) | ollama | openai_compatible | template
    llm_base_url: str = ""
    llm_model: str = ""
    llm_api_key: str = ""
    llm_timeout: float = 5.0
    llm_max_tokens: int = 512
    llm_reasoning_effort: str = ""     # e.g. "minimal"; Muse also retries with "minimal" if the reply is empty
    llm_fallback_chain: str = ""
    # demo console only: enables /demo/* endpoints (layer switches, event feed). Off = byte-for-byte Phase 2.
    demo_mode: bool = False


def get_settings() -> Settings:
    llm_provider = os.environ.get("LLM_PROVIDER", "muse").strip().lower()
    # backward compat
    if llm_provider == "openai":
        llm_provider = "openai_compatible"
    if llm_provider == "none":
        llm_provider = "template"
    return Settings(
        engine_api_key=os.environ.get("ENGINE_API_KEY", ""),
        redis_url=os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0"),
        risk_state=os.environ.get("RISK_STATE", "redis"),
        sqlite_path=os.environ.get("SQLITE_PATH", str(ROOT / "data" / "events.db")),
        state_ttl_seconds=int(os.environ.get("STATE_TTL_SECONDS", "3600")),
        max_travel_kmh=float(os.environ.get("MAX_TRAVEL_KMH", "900")),
        min_travel_km=float(os.environ.get("MIN_TRAVEL_KM", "100")),
        geo_path=os.environ.get(
            "GEO_DB_PATH", str(Path(__file__).parent / "data" / "geo_demo.json")
        ),
        proof_max_age=float(os.environ.get("PROOF_MAX_AGE_SECONDS", "30")),
        nonce_ttl=float(os.environ.get("NONCE_TTL_SECONDS", "30")),
        elevated_seconds=float(os.environ.get("ELEVATED_SECONDS", "300")),
        stepup_timeout=float(os.environ.get("STEPUP_TIMEOUT_SECONDS", "60")),
        llm_provider=llm_provider,
        llm_base_url=os.environ.get("LLM_BASE_URL", ""),
        llm_model=os.environ.get("LLM_MODEL", ""),
        llm_api_key=os.environ.get("LLM_API_KEY", ""),
        llm_timeout=float(os.environ.get("LLM_TIMEOUT_SECONDS", "5")),
        llm_max_tokens=int(os.environ.get("LLM_MAX_TOKENS", "512")),
        llm_reasoning_effort=os.environ.get("LLM_REASONING_EFFORT", "").strip(),
        llm_fallback_chain=os.environ.get("LLM_FALLBACK_CHAIN", ""),
        demo_mode=os.environ.get("DEMO_MODE", "").strip().lower() == "true",
    )
