import pytest


def hdr(make_token, role="viewer"):
    return {"Authorization": f"Bearer {make_token(role)}"}


def summary(c, make_token, hours):
    return c.get(f"/summary?hours={hours}", headers=hdr(make_token)).get_json()


def test_severity_rules(analytics_mod):
    sev = analytics_mod.sev
    assert sev("DoS") == "Critical" and sev("SYN Flood") == "Critical"
    assert sev("BruteForce") == sev("UDPFlood") == sev("ICMPFlood") == "High"
    assert sev("PortScan") == "Medium" and sev(None) == "Medium"


def test_summary_needs_a_token(analytics_client):
    assert analytics_client.get("/summary").status_code == 401


def test_empty_database(analytics_client, make_token):
    d = summary(analytics_client, make_token, 24)
    assert d["total"] == 0 and d["recent"] == []


def test_time_ranges_count_back_from_now(analytics_client, make_token, insert_alert):
    insert_alert("DoS", "10.0.0.1", minutes_ago=5)
    insert_alert("PortScan", "10.0.0.2", minutes_ago=120)             # 2 hours old
    insert_alert("BruteForce", "10.0.0.3", minutes_ago=50 * 60)       # 50 hours old
    insert_alert("UDPFlood", "10.0.0.4", minutes_ago=20 * 24 * 60)    # 20 days old
    totals = {h: summary(analytics_client, make_token, h)["total"] for h in (1, 6, 24, 168, 720)}
    assert totals == {1: 1, 6: 2, 24: 2, 168: 3, 720: 4}


@pytest.mark.parametrize("raw, expected", [("99999", 720), ("0", 1), ("abc", 24)])
def test_hours_argument_is_clamped(analytics_client, make_token, raw, expected):
    r = analytics_client.get(f"/summary?hours={raw}", headers=hdr(make_token))
    assert r.get_json()["hours"] == expected


def test_severity_and_top_sources(analytics_client, make_token, insert_alert):
    for _ in range(3):
        insert_alert("DoS", "10.0.0.1", minutes_ago=5)
    insert_alert("PortScan", "10.0.0.2", minutes_ago=5)
    d = summary(analytics_client, make_token, 24)
    assert d["by_severity"] == {"Critical": 3, "Medium": 1}
    assert d["sources"][0] == ["10.0.0.1", 3]
    assert d["unique_sources"] == 2


def test_report_pdf(analytics_client, make_token, insert_alert):
    h = hdr(make_token)
    empty = analytics_client.get("/report.pdf?hours=24", headers=h)
    assert empty.status_code == 200 and empty.data.startswith(b"%PDF")
    insert_alert("DoS", "10.0.0.1", minutes_ago=5)
    full = analytics_client.get("/report.pdf?hours=24", headers=h)
    assert full.mimetype == "application/pdf" and full.data.startswith(b"%PDF")
    assert analytics_client.get("/report.pdf").status_code == 401