"""events: append-only SQLite log of every evaluation, plus the rationale.

One short-lived connection per call keeps it safe under FastAPI's threadpool and
background tasks. `session_id` holds a short HASH of the real session id
(session_ref), never the bearer token itself. The rationale is written later,
asynchronously, by set_rationale(). Older databases are migrated in place.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .checks import Signal

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  session_id TEXT NOT NULL,
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  fingerprint_hash TEXT NOT NULL,
  score INTEGER NOT NULL,
  action TEXT NOT NULL,
  signals TEXT NOT NULL,
  route TEXT NOT NULL DEFAULT '',
  rationale TEXT,
  rationale_source TEXT,
  provider TEXT,
  model TEXT,
  latency_ms INTEGER
)"""
_MIGRATIONS = {
    "route": "ALTER TABLE events ADD COLUMN route TEXT NOT NULL DEFAULT ''",
    "rationale": "ALTER TABLE events ADD COLUMN rationale TEXT",
    "rationale_source": "ALTER TABLE events ADD COLUMN rationale_source TEXT",
    "provider": "ALTER TABLE events ADD COLUMN provider TEXT",
    "model": "ALTER TABLE events ADD COLUMN model TEXT",
    "latency_ms": "ALTER TABLE events ADD COLUMN latency_ms INTEGER",
}


class EventLog:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.execute(_SCHEMA)
            have = {r["name"] for r in c.execute("PRAGMA table_info(events)")}
            for col, ddl in _MIGRATIONS.items():
                if col not in have:
                    c.execute(ddl)

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def record(self, *, session_id, ip, user_agent, fingerprint_hash, score, action,
               signals: list[Signal], route: str = "", ts: float | None = None) -> int:
        with self._conn() as c:
            cur = c.execute(
                "INSERT INTO events (ts, session_id, ip, user_agent, fingerprint_hash,"
                " score, action, signals, route) VALUES (?,?,?,?,?,?,?,?,?)",
                (ts if ts is not None else time.time(), session_id, ip, user_agent,
                 fingerprint_hash, score, action,
                 json.dumps([s.to_dict() for s in signals]), route),
            )
            return int(cur.lastrowid)

    def set_rationale(self, event_id: int, text: str, source: str, provider: str = None, model: str = None, latency_ms: int = None) -> None:
        with self._conn() as c:
            if provider is not None or model is not None or latency_ms is not None:
                c.execute("UPDATE events SET rationale=?, rationale_source=?, provider=?, model=?, latency_ms=? WHERE id=?",
                          (text, source, provider, model, latency_ms, event_id))
            else:
                c.execute("UPDATE events SET rationale=?, rationale_source=? WHERE id=?",
                          (text, source, event_id))

    def get(self, event_id: int) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
        return {**dict(r), "signals": json.loads(r["signals"])} if r else None

    def recent(self, limit: int = 50) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "signals": json.loads(r["signals"])} for r in rows]

    # --- demo console feed (read-only) ------------------------------------------------
    def after(self, after_id: int = 0, limit: int = 200) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM events WHERE id>? ORDER BY id ASC LIMIT ?",
                             (after_id, limit)).fetchall()
        return [{**dict(r), "signals": json.loads(r["signals"])} for r in rows]

    def latest_id(self) -> int:
        with self._conn() as c:
            return int(c.execute("SELECT COALESCE(MAX(id),0) FROM events").fetchone()[0])

    # --- dashboard queries ------------------------------------------------------------
    def sessions(self, limit: int = 50) -> list[dict]:
        sql = """
        SELECT session_id AS ref, MIN(ts) AS first_ts, MAX(ts) AS last_ts, COUNT(*) AS events,
               MAX(score) AS max_score,
               MAX(CASE WHEN action='terminate' THEN 1 ELSE 0 END) AS terminated,
               (SELECT e2.score  FROM events e2 WHERE e2.session_id=e.session_id ORDER BY e2.id DESC LIMIT 1) AS last_score,
               (SELECT e2.action FROM events e2 WHERE e2.session_id=e.session_id ORDER BY e2.id DESC LIMIT 1) AS last_action
        FROM events e GROUP BY session_id ORDER BY last_ts DESC LIMIT ?"""
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, (limit,)).fetchall()]

    def session_events(self, ref: str, limit: int = 500) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM events WHERE session_id=? ORDER BY id ASC LIMIT ?",
                             (ref, limit)).fetchall()
        return [{**dict(r), "signals": json.loads(r["signals"])} for r in rows]
