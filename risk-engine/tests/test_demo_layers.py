"""Tests for the demo-only layer switches and event feed (enabled only with DEMO_MODE=true)."""
from dataclasses import replace

from fastapi.testclient import TestClient

from app.main import create_app
from app.store import MemoryStore
from conftest import HEADERS, NYC, UA_B, FP_B, evaluate, login_bound, names


def demo_client(settings, events, clock, demo=True):
    store = MemoryStore()
    c = TestClient(create_app(replace(settings, demo_mode=demo), store=store, events=events, clock=clock))
    return c


def test_endpoints_do_not_exist_without_demo_mode(settings, events, clock):
    c = demo_client(settings, events, clock, demo=False)
    assert c.get("/demo/layers", headers=HEADERS).status_code == 404
    assert c.post("/demo/layers", json={"layer1": False}, headers=HEADERS).status_code == 404
    assert c.get("/demo/events", headers=HEADERS).status_code == 404


def test_demo_endpoints_need_the_api_key(settings, events, clock):
    c = demo_client(settings, events, clock)
    assert c.get("/demo/layers").status_code == 401
    assert c.get("/demo/events").status_code == 401


def test_layer1_switch_changes_outcome(settings, events, clock):
    c = demo_client(settings, events, clock)
    login_bound(c)
    # different UA + fingerprint + IP, with a valid-looking read (presence window still fresh from login)
    on = evaluate(c, ip=NYC, ua=UA_B, fp=FP_B)
    assert {"user_agent_mismatch", "fingerprint_mismatch", "ip_change"} <= names(on)
    c.post("/demo/layers", json={"layer1": False}, headers=HEADERS)
    off = evaluate(c, ip=NYC, ua=UA_B, fp=FP_B)
    assert not names(off) & {"user_agent_mismatch", "fingerprint_mismatch", "ip_change", "impossible_travel"}


def test_device_key_switch_changes_outcome(settings, events, clock):
    c = demo_client(settings, events, clock)
    login_bound(c)
    on = evaluate(c, kind="write", route="POST /transfer")  # no proof
    assert on["action"] == "challenge" and "proof_missing" in names(on)
    c.post("/demo/layers", json={"device_key": False}, headers=HEADERS)
    off = evaluate(c, kind="write", route="POST /transfer")
    assert off["action"] == "allow" and not any(n.startswith("proof_") for n in names(off))


def test_layers_default_on_and_partial_update(settings, events, clock):
    c = demo_client(settings, events, clock)
    assert c.get("/demo/layers", headers=HEADERS).json() == {"layer1": True, "device_key": True}
    r = c.post("/demo/layers", json={"device_key": False}, headers=HEADERS).json()
    assert r == {"layer1": True, "device_key": False}


def test_events_feed_is_incremental(settings, events, clock):
    c = demo_client(settings, events, clock)
    evaluate(c)
    first = c.get("/demo/events", headers=HEADERS).json()
    assert len(first["events"]) == 1 and first["latest_id"] == first["events"][0]["id"]
    evaluate(c)
    nxt = c.get(f"/demo/events?after_id={first['latest_id']}", headers=HEADERS).json()
    assert len(nxt["events"]) == 1 and nxt["events"][0]["id"] > first["latest_id"]
