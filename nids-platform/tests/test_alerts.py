import pytest

KEY = {"X-Service-Key": "test-sensor-key"}


def ingest(c, **kw):
    body = {"type": "PortScan", "src": "10.0.0.1", "dst": "10.0.0.5", "dport": "-"}
    body.update(kw)
    return c.post("/ingest", json=body, headers=KEY)


def hdr(make_token, role="admin"):
    return {"Authorization": f"Bearer {make_token(role)}"}


# ---------- ingest ----------
def test_ingest_needs_the_sensor_key(alert_client):
    body = {"type": "DoS", "src": "1.1.1.1"}
    assert alert_client.post("/ingest", json=body).status_code == 401
    assert alert_client.post("/ingest", json=body, headers={"X-Service-Key": "wrong"}).status_code == 401


def test_ingest_requires_type_and_src(alert_client):
    assert alert_client.post("/ingest", json={"type": "DoS"}, headers=KEY).status_code == 400
    assert alert_client.post("/ingest", json={"src": "1.1.1.1"}, headers=KEY).status_code == 400


def test_ingested_alert_shows_in_list(alert_client, make_token):
    assert ingest(alert_client, type="BruteForce", src="10.0.0.9", dport="22").status_code == 201
    data = alert_client.get("/", headers=hdr(make_token, "viewer")).get_json()
    assert data["total"] == 1
    a = data["alerts"][0]
    assert (a["type"], a["src"], a["dport"], a["status"]) == ("BruteForce", "10.0.0.9", "22", "new")


# ---------- list, filters, pagination ----------
def test_list_needs_a_token(alert_client):
    assert alert_client.get("/").status_code == 401


def test_list_filters(alert_client, make_token):
    ingest(alert_client, type="DoS", src="10.0.0.1")
    ingest(alert_client, type="PortScan", src="10.0.0.2")
    ingest(alert_client, type="PortScan", src="10.0.0.3")
    h = hdr(make_token)
    assert alert_client.get("/?type=PortScan", headers=h).get_json()["total"] == 2
    assert alert_client.get("/?q=10.0.0.1", headers=h).get_json()["total"] == 1
    assert alert_client.get("/?status=resolved", headers=h).get_json()["total"] == 0


def test_pagination(alert_client, make_token):
    for i in range(5):
        ingest(alert_client, src=f"10.0.0.{i}")
    page = alert_client.get("/?limit=2&offset=2", headers=hdr(make_token)).get_json()
    assert page["total"] == 5 and len(page["alerts"]) == 2


# ---------- status and stats ----------
def test_status_change_permissions(alert_client, make_token):
    ingest(alert_client)
    aid = alert_client.get("/", headers=hdr(make_token)).get_json()["alerts"][0]["id"]
    url = f"/{aid}/status"
    assert alert_client.put(url, json={"status": "resolved"}, headers=hdr(make_token, "viewer")).status_code == 403
    assert alert_client.put(url, json={"status": "bogus"}, headers=hdr(make_token, "analyst")).status_code == 400
    assert alert_client.put("/999999/status", json={"status": "resolved"}, headers=hdr(make_token, "analyst")).status_code == 404
    assert alert_client.put(url, json={"status": "investigating"}, headers=hdr(make_token, "analyst")).status_code == 200
    assert alert_client.get("/?status=investigating", headers=hdr(make_token)).get_json()["total"] == 1


def test_stats(alert_client, make_token):
    ingest(alert_client, type="DoS", src="10.0.0.1")
    ingest(alert_client, type="DoS", src="10.0.0.1")
    ingest(alert_client, type="PortScan", src="10.0.0.2")
    s = alert_client.get("/stats", headers=hdr(make_token)).get_json()
    assert s["total"] == 3
    assert s["counts"] == {"DoS": 2, "PortScan": 1}
    assert s["sources"][0] == ["10.0.0.1", 2]


# ---------- sensor heartbeat ----------
def test_sensor_goes_online_then_offline(alerts, alert_client, make_token):
    h = hdr(make_token)
    assert alert_client.get("/sensor", headers=h).get_json() == {"seen": False, "online": False}
    r = alert_client.post("/heartbeat", json={"host": "pi5", "packets": 100, "uptime": 5}, headers=KEY)
    assert r.status_code == 200
    s = alert_client.get("/sensor", headers=h).get_json()
    assert s["online"] is True and s["host"] == "pi5"
    con = alerts.connect()
    con.cursor().execute("UPDATE sensor_status SET last_seen = last_seen - 120")
    con.commit()
    con.close()
    assert alert_client.get("/sensor", headers=h).get_json()["online"] is False


def test_heartbeat_validation(alert_client):
    assert alert_client.post("/heartbeat", json={"packets": "x"}, headers=KEY).status_code == 400
    assert alert_client.post("/heartbeat", json={"packets": 1, "uptime": 1}).status_code == 401


# ---------- email for Critical alerts ----------
@pytest.fixture()
def mails(alerts, monkeypatch):
    sent = []
    monkeypatch.setattr(alerts, "EMAIL_ON", True)
    monkeypatch.setattr(alerts, "notify_critical", lambda *a: sent.append(a))
    return sent


def test_is_critical_rule(alert_mod):
    assert alert_mod.is_critical("DoS") and alert_mod.is_critical("SYN Flood")
    assert not alert_mod.is_critical("PortScan") and not alert_mod.is_critical("BruteForce")


def test_critical_alert_sends_one_email_per_source(alert_client, mails):
    ingest(alert_client, type="DoS", src="10.0.0.1")
    ingest(alert_client, type="DoS", src="10.0.0.1")        # muted by the cooldown
    ingest(alert_client, type="DoS", src="10.0.0.2")        # different source
    ingest(alert_client, type="PortScan", src="10.0.0.3")   # not critical
    assert [m[1] for m in mails] == ["10.0.0.1", "10.0.0.2"]