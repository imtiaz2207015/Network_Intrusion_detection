import pytest

KEY = {"X-Service-Key": "test-sensor-key"}
FAKE = {"what": "Claude says what", "risk": "Claude says risk", "steps": ["Do one", "Do two"]}


def hdr(make_token, role="viewer"):
    return {"Authorization": f"Bearer {make_token(role)}"}


def add_alert(c, **kw):
    body = {"type": "BruteForce", "src": "10.0.0.9", "dst": "10.0.0.5", "dport": "22",
            "detail": "8 SYNs in 10s"}
    body.update(kw)
    assert c.post("/ingest", json=body, headers=KEY).status_code == 201


def ids(c, make_token):
    rows = c.get("/", headers=hdr(make_token)).get_json()["alerts"]
    return [a["id"] for a in rows]


def explain(c, make_token, aid, role="viewer", refresh=False):
    url = f"/{aid}/explain" + ("?refresh=1" if refresh else "")
    return c.get(url, headers=hdr(make_token, role)).get_json()


@pytest.fixture()
def ai(alerts, monkeypatch):
    con = alerts.connect()
    con.cursor().execute("TRUNCATE ai_explanations, ai_usage")
    con.commit()
    con.close()
    monkeypatch.setattr(alerts, "AI_ON", False)
    monkeypatch.setattr(alerts, "AI_DAILY_LIMIT", 2)
    return alerts


def test_explain_needs_a_token_and_a_real_alert(ai, alert_client, make_token):
    assert alert_client.get("/1/explain").status_code == 401
    assert alert_client.get("/999/explain", headers=hdr(make_token)).status_code == 404


def test_builtin_guide_when_ai_is_off(ai, alert_client, make_token):
    add_alert(alert_client)
    r = explain(alert_client, make_token, ids(alert_client, make_token)[0])
    assert r["source"] == "builtin" and r["ai_enabled"] is False
    assert r["severity"] == "High"
    assert "10.0.0.9 -> 10.0.0.5" in r["context"]
    assert r["what"] and r["risk"] and len(r["steps"]) >= 3
    assert "no API key" in r["note"]


@pytest.mark.parametrize("atype, sev", [
    ("DoS/SYN Flood", "Critical"), ("PortScan", "Medium"), ("BruteForce", "High"),
    ("UDP Flood", "High"), ("ICMP Flood", "High"), ("ML-Detected", "Medium"), ("Weird", "Medium")])
def test_builtin_guide_for_every_attack_type(ai, alert_client, make_token, atype, sev):
    add_alert(alert_client, type=atype)
    r = explain(alert_client, make_token, ids(alert_client, make_token)[0])
    assert r["severity"] == sev
    assert r["what"] and r["risk"] and r["steps"]


def test_claude_answer_is_used_and_cached(ai, alert_client, make_token, monkeypatch):
    calls = []
    monkeypatch.setattr(ai, "AI_ON", True)
    monkeypatch.setattr(ai, "ask_claude", lambda a: calls.append(a["id"]) or dict(FAKE))
    add_alert(alert_client)
    aid = ids(alert_client, make_token)[0]
    first = explain(alert_client, make_token, aid)
    assert first["source"] == "claude" and first["cached"] is False
    assert first["what"] == FAKE["what"]
    second = explain(alert_client, make_token, aid)
    assert second["cached"] is True and calls == [aid]
    explain(alert_client, make_token, aid, role="viewer", refresh=True)   # viewers cannot refresh
    assert len(calls) == 1
    explain(alert_client, make_token, aid, role="analyst", refresh=True)
    assert len(calls) == 2


def test_daily_limit_falls_back_to_builtin(ai, alert_client, make_token, monkeypatch):
    monkeypatch.setattr(ai, "AI_ON", True)
    monkeypatch.setattr(ai, "ask_claude", lambda a: dict(FAKE))
    for i in range(3):
        add_alert(alert_client, src=f"10.0.0.{i}")
    sources = [explain(alert_client, make_token, i)["source"] for i in ids(alert_client, make_token)]
    assert sources.count("claude") == 2 and sources.count("builtin") == 1


def test_claude_failure_falls_back_to_builtin(ai, alert_client, make_token, monkeypatch):
    def boom(a):
        raise OSError("api down")
    monkeypatch.setattr(ai, "AI_ON", True)
    monkeypatch.setattr(ai, "ask_claude", boom)
    add_alert(alert_client)
    r = explain(alert_client, make_token, ids(alert_client, make_token)[0])
    assert r["source"] == "builtin" and "could not answer" in r["note"]


def test_parse_ai(alert_mod):
    ok = alert_mod.parse_ai('Sure!\n```json\n{"what": "w", "risk": "r", "steps": ["a", "b"]}\n```')
    assert ok == {"what": "w", "risk": "r", "steps": ["a", "b"]}
    assert alert_mod.parse_ai("no json here") is None
    assert alert_mod.parse_ai('{"what": "w"}') is None
    assert alert_mod.parse_ai('{"what": "w", "risk": "r", "steps": []}') is None