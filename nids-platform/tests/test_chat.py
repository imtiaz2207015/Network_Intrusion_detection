from datetime import datetime, timedelta
import json
import time
from zoneinfo import ZoneInfo

import jwt
import pytest
import requests


def token_for(conftest_secret, sub="1", username="tester", role="viewer"):
    payload = {
        "sub": str(sub),
        "username": username,
        "role": role,
        "exp": datetime.now() + timedelta(hours=1),
    }
    return jwt.encode(payload, conftest_secret, algorithm="HS256")


def hdr_for(alert_mod, sub="1", username="tester", role="viewer"):
    return {"Authorization": f"Bearer {token_for(alert_mod.SECRET, sub=sub, username=username, role=role)}"}


class FakeGroqResponse:
    def __init__(self, status_code=200, content="A SYN flood sends many half-open TCP requests.", reasoning=None, finish_reason="stop"):
        self.status_code = status_code
        self._content = content
        self._reasoning = reasoning
        self._finish_reason = finish_reason

    def json(self):
        msg = {"role": "assistant", "content": self._content}
        if self._reasoning is not None:
            msg["reasoning"] = self._reasoning
        return {
            "choices": [
                {"message": msg, "finish_reason": self._finish_reason}
            ]
        }


def _seed_alert(alert_mod, owner_uid, atype, src, *, dst="10.0.0.5", dport="80",
                detail="test detail", explanation=None, minutes_ago=2):
    tz = ZoneInfo(alert_mod.SENSOR_TZ)
    when_local = (datetime.now(tz) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%d %H:%M:%S")
    ingested_at = time.time() - minutes_ago * 60
    exp_json = json.dumps(explanation) if explanation is not None else None
    con = alert_mod.connect()
    cur = con.cursor()
    cur.execute(
        """INSERT INTO alerts(time, type, src, dst, dport, detail, owner_user_id, explanation, ingested_at)
           VALUES(%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)""",
        (when_local, atype, src, dst, dport, detail, int(owner_uid), exp_json, ingested_at),
    )
    con.commit()
    con.close()


@pytest.fixture()
def chat(alerts, monkeypatch):
    con = alerts.connect()
    con.cursor().execute("TRUNCATE chat_messages, chat_usage RESTART IDENTITY")
    con.commit()
    con.close()
    monkeypatch.setattr(alerts, "GROQ_API_KEY", "test-groq-key")
    monkeypatch.setattr(alerts, "GROQ_MODEL", "openai/gpt-oss-20b")
    monkeypatch.setattr(alerts, "GROQ_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setattr(alerts, "CHAT_DAILY_LIMIT", 20)
    monkeypatch.setattr(alerts, "CHAT_MAX_TOKENS", 1500)
    return alerts


def test_chat_routes_require_auth(chat, alert_client):
    assert alert_client.post("/chat", json={"message": "What is a SYN flood?"}).status_code == 401
    assert alert_client.get("/chat/history").status_code == 401
    assert alert_client.get("/chat/usage").status_code == 401
    assert alert_client.delete("/chat/history").status_code == 401

    bad = {"Authorization": "Bearer not-a-real-jwt"}
    assert alert_client.post("/chat", json={"message": "Hi"}, headers=bad).status_code == 401


@pytest.mark.parametrize("payload", [
    {},
    {"message": ""},
    {"message": "    \n\t  "},
    {"message": None},
    {"message": 12345},
    {"message": "x" * 501},
])
def test_chat_rejects_empty_invalid_and_oversized_messages(chat, alert_client, monkeypatch, payload):
    called = []
    monkeypatch.setattr(
        chat.requests,
        "post",
        lambda *a, **kw: called.append(1) or FakeGroqResponse(),
    )
    r = alert_client.post("/chat", json=payload, headers=hdr_for(chat))
    assert r.status_code == 400
    assert r.get_json().get("error")
    assert called == []


def test_chat_sends_no_alert_sensor_or_ip_data_to_groq(chat, alert_client, monkeypatch):
    # Seed alerts (ML with SHAP + rule-based) and sensor_status for user 10
    shap_exp = {
        "method": "shap",
        "predicted_class": 1,
        "predicted_label": "ATTACK",
        "top_features": [
            {"feature": "Flow Packets/s", "value": 9500.0, "shap": 0.42, "direction": "toward attack"},
        ],
    }
    _seed_alert(
        chat, 10, "ML-Detected", "198.51.100.11",
        dst="10.0.0.5", dport="8080",
        detail="secret-alert-marker-ml", explanation=shap_exp, minutes_ago=1,
    )
    _seed_alert(
        chat, 10, "PortScan", "203.0.113.77",
        dst="10.0.0.9", dport="22",
        detail="secret-alert-marker-rule", minutes_ago=2,
    )
    con = chat.connect()
    con.cursor().execute(
        """INSERT INTO sensor_status(id, host, packets, uptime, last_seen, owner_user_id, sensor_ip, gateway_ip)
           VALUES(10, 'secret-pi5-host', 4200, 120, %s, 10, '192.168.55.10', '192.168.55.1')
           ON CONFLICT (owner_user_id) DO UPDATE SET host=EXCLUDED.host""",
        (time.time(),),
    )
    con.commit()
    con.close()

    # Track SQL queries during /chat to ensure alerts / sensor tables are never queried
    real_query = chat.query
    executed_sql = []

    def spy_query(sql, params=()):
        executed_sql.append(sql.lower())
        return real_query(sql, params)

    monkeypatch.setattr(chat, "query", spy_query)

    captured = []

    def fake_post(url, headers=None, json=None, timeout=None):
        captured.append({"url": url, "headers": headers, "json": json, "timeout": timeout})
        return FakeGroqResponse(content="Open the AI Assistant page and use Explain on that alert.")

    monkeypatch.setattr(chat.requests, "post", fake_post)

    h = hdr_for(chat, sub="10", username="alice")
    r = alert_client.post(
        "/chat",
        json={"message": "What happened in the last 10 minutes?"},
        headers=h,
    )
    assert r.status_code == 200
    assert len(captured) == 1

    req = captured[0]
    assert req["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert req["timeout"] == 20
    msgs = req["json"]["messages"]
    assert len(msgs) == 2
    assert msgs[0]["role"] == "system"
    assert msgs[0]["content"] == chat.CHAT_SYSTEM_PROMPT
    assert msgs[1] == {"role": "user", "content": "What happened in the last 10 minutes?"}

    # Verify strengthened system prompt rules
    sys_prompt = msgs[0]["content"]
    assert "You do not have access to the user's alerts or any private data." in sys_prompt
    assert "AI Assistant" in sys_prompt
    assert "Never invent alert IDs, scores, IPs or times." in sys_prompt

    # Verify ZERO alert, sensor, IP, or SHAP data leaked into the outgoing Groq payload
    serialized = json.dumps(req["json"])
    for forbidden in (
        "198.51.100.11",
        "203.0.113.77",
        "10.0.0.5",
        "10.0.0.9",
        "192.168.55.10",
        "192.168.55.1",
        "secret-alert-marker-ml",
        "secret-alert-marker-rule",
        "secret-pi5-host",
        "Flow Packets/s",
        "untrusted_alert_data",
    ):
        assert forbidden not in serialized

    # Verify /chat never queried the alerts or sensor tables
    assert not any("from alerts" in s for s in executed_sql)
    assert not any("sensor_status" in s for s in executed_sql)


def test_chat_sends_only_system_prompt_last_6_turns_and_current_message(chat, alert_client, monkeypatch):
    captured = []

    def fake_post(url, headers=None, json=None, timeout=None):
        captured.append(json)
        return FakeGroqResponse(content=f"Answer {len(captured)}")

    monkeypatch.setattr(chat.requests, "post", fake_post)
    h = hdr_for(chat, sub="15", username="turn_user")

    # Send 5 exchanges (10 stored messages: 5 user + 5 assistant)
    for i in range(1, 6):
        r = alert_client.post("/chat", json={"message": f"Question {i}"}, headers=h)
        assert r.status_code == 200

    # On the 5th request, there were 8 prior messages stored, so only the last 6 should be included
    fifth_msgs = captured[4]["messages"]
    assert len(fifth_msgs) == 1 + 6 + 1  # system + last 6 turns + current user message
    assert fifth_msgs[0] == {"role": "system", "content": chat.CHAT_SYSTEM_PROMPT}
    assert fifth_msgs[1:-1] == [
        {"role": "user", "content": "Question 2"},
        {"role": "assistant", "content": "Answer 2"},
        {"role": "user", "content": "Question 3"},
        {"role": "assistant", "content": "Answer 3"},
        {"role": "user", "content": "Question 4"},
        {"role": "assistant", "content": "Answer 4"},
    ]
    assert fifth_msgs[-1] == {"role": "user", "content": "Question 5"}


def test_chat_gpt_oss_empty_content_reasoning_fallback(chat, alert_client, monkeypatch):
    # Simulate openai/gpt-oss-20b consuming tokens in reasoning and returning empty content
    monkeypatch.setattr(
        chat.requests,
        "post",
        lambda *a, **kw: FakeGroqResponse(
            status_code=200,
            content="",
            reasoning="Let me think step by step about this...",
            finish_reason="length",
        ),
    )
    h = hdr_for(chat, sub="40", username="oss_user")
    r = alert_client.post("/chat", json={"message": "What is a SYN flood?"}, headers=h)
    assert r.status_code == 200
    reply = r.get_json()["reply"]
    assert reply == chat.CHAT_EMPTY_CONTENT_FALLBACK
    assert "step by step" not in reply


def test_chat_daily_cap_and_per_user_isolation(chat, alert_client, monkeypatch):
    monkeypatch.setattr(chat, "CHAT_DAILY_LIMIT", 3)
    calls = []
    monkeypatch.setattr(
        chat.requests,
        "post",
        lambda *a, **kw: calls.append(1) or FakeGroqResponse(content="Safe advice."),
    )

    h_a = hdr_for(chat, sub="10", username="user_a")
    h_b = hdr_for(chat, sub="20", username="user_b")

    assert alert_client.get("/chat/usage", headers=h_a).get_json() == {"used": 0, "limit": 3}

    for i in range(3):
        r = alert_client.post("/chat", json={"message": f"Help {i}"}, headers=h_a)
        assert r.status_code == 200
        assert r.get_json()["used"] == i + 1

    # 4th message hits per-user daily cap (429) without calling Groq
    r4 = alert_client.post("/chat", json={"message": "One more"}, headers=h_a)
    assert r4.status_code == 429
    assert "limit" in r4.get_json()["error"].lower()
    assert len(calls) == 3

    # Clearing history must NOT bypass the daily cap
    assert alert_client.delete("/chat/history", headers=h_a).status_code == 200
    assert alert_client.get("/chat/history", headers=h_a).get_json()["messages"] == []
    assert alert_client.get("/chat/usage", headers=h_a).get_json() == {"used": 3, "limit": 3}
    assert alert_client.post("/chat", json={"message": "Bypass?"}, headers=h_a).status_code == 429

    # User B has an independent quota and sees empty history
    assert alert_client.get("/chat/usage", headers=h_b).get_json() == {"used": 0, "limit": 3}
    rb = alert_client.post("/chat", json={"message": "What is PortScan?"}, headers=h_b)
    assert rb.status_code == 200
    assert len(alert_client.get("/chat/history", headers=h_b).get_json()["messages"]) == 2


def test_chat_history_returns_last_30_messages_chronologically(chat, alert_client, monkeypatch):
    monkeypatch.setattr(chat, "CHAT_DAILY_LIMIT", 25)
    monkeypatch.setattr(
        chat.requests,
        "post",
        lambda *a, **kw: FakeGroqResponse(content="Short answer."),
    )
    h = hdr_for(chat, sub="5", username="hist_user")
    for i in range(18):  # 36 total rows (18 user + 18 assistant)
        assert alert_client.post("/chat", json={"message": f"Msg {i}"}, headers=h).status_code == 200

    hist = alert_client.get("/chat/history", headers=h).get_json()["messages"]
    assert len(hist) == 30
    assert [m["id"] for m in hist] == sorted(m["id"] for m in hist)
    assert hist[-2]["role"] == "user" and hist[-2]["content"] == "Msg 17"
    assert hist[-1]["role"] == "assistant"


def test_chat_handles_groq_errors_and_missing_key_with_503(chat, alert_client, monkeypatch):
    h = hdr_for(chat, sub="7", username="err_user")

    # 1. Groq rate limit (429) -> friendly 503
    monkeypatch.setattr(chat.requests, "post", lambda *a, **kw: FakeGroqResponse(status_code=429))
    r = alert_client.post("/chat", json={"message": "What is SSH?"}, headers=h)
    assert r.status_code == 503
    assert "busy" in r.get_json()["error"].lower()

    # 2. Groq timeout -> friendly 503
    def raise_timeout(*a, **kw):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(chat.requests, "post", raise_timeout)
    r = alert_client.post("/chat", json={"message": "What is SSH?"}, headers=h)
    assert r.status_code == 503

    # 3. Groq 500 error -> friendly 503
    monkeypatch.setattr(chat.requests, "post", lambda *a, **kw: FakeGroqResponse(status_code=500))
    r = alert_client.post("/chat", json={"message": "What is SSH?"}, headers=h)
    assert r.status_code == 503

    # 4. Missing API key -> friendly 503
    monkeypatch.setattr(chat, "GROQ_API_KEY", "")
    monkeypatch.setattr(chat.requests, "post", lambda *a, **kw: FakeGroqResponse(status_code=200))
    r = alert_client.post("/chat", json={"message": "What is SSH?"}, headers=h)
    assert r.status_code == 503
