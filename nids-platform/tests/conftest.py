import importlib.util
import os
import pathlib
import sys
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import jwt
import psycopg2
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Test settings, set BEFORE the apps are imported. Real mail and Google login are off.
JWT_SECRET = "test-jwt-secret-for-pytest-only-0123456789"
SENSOR_KEY = "test-sensor-key"
os.environ.update(
    JWT_SECRET=JWT_SECRET, SENSOR_KEY=SENSOR_KEY, GOOGLE_CLIENT_ID="",
    SMTP_USER="", SMTP_APP_PASSWORD="", ALERT_EMAIL_TO="",
    FRONTEND_URL="http://localhost:8088", SENSOR_TZ="Asia/Dhaka",
)


def _env(name, default=""):
    if os.environ.get(name):
        return os.environ[name]
    f = ROOT / ".env"
    if f.exists():
        for line in f.read_text(encoding="utf-8-sig", errors="ignore").splitlines():
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return default


USER = _env("POSTGRES_USER", "nids")
PASSWORD = _env("POSTGRES_PASSWORD")
HOST = os.environ.get("TEST_DB_HOST", "127.0.0.1:5433")
AUTH_DSN = f"postgresql://{USER}:{PASSWORD}@{HOST}/auth_test"
ALERTS_DSN = f"postgresql://{USER}:{PASSWORD}@{HOST}/alerts_test"


def _ensure_db(name):
    con = psycopg2.connect(f"postgresql://{USER}:{PASSWORD}@{HOST}/postgres")
    con.autocommit = True
    cur = con.cursor()
    cur.execute("SELECT 1 FROM pg_database WHERE datname=%s", (name,))
    if not cur.fetchone():
        cur.execute(f'CREATE DATABASE "{name}"')
    con.close()


def _load(module_name, folder, dsn):
    os.environ["DATABASE_URL"] = dsn
    spec = importlib.util.spec_from_file_location(module_name, ROOT / folder / "app.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = mod
    spec.loader.exec_module(mod)
    mod.app.config["TESTING"] = True
    return mod


def _truncate(dsn, tables):
    con = psycopg2.connect(dsn)
    con.cursor().execute(f"TRUNCATE {tables} RESTART IDENTITY")
    con.commit()
    con.close()


# ---------- the three apps (imported once per test run) ----------
@pytest.fixture(scope="session")
def auth_mod():
    _ensure_db("auth_test")
    return _load("auth_app", "auth-service", AUTH_DSN)


@pytest.fixture(scope="session")
def alert_mod():
    _ensure_db("alerts_test")
    return _load("alert_app", "alert-service", ALERTS_DSN)


@pytest.fixture(scope="session")
def analytics_mod(alert_mod):          # alert_mod first: it creates the alerts table
    return _load("analytics_app", "analytics-service", ALERTS_DSN)


# ---------- clean tables before every test ----------
@pytest.fixture()
def auth(auth_mod):
    _truncate(AUTH_DSN, "users, login_log, password_resets")
    return auth_mod


@pytest.fixture()
def alerts(alert_mod):
    _truncate(ALERTS_DSN, "alerts, sensor_status, email_cooldown")
    return alert_mod


@pytest.fixture()
def analytics(analytics_mod, alert_mod):
    _truncate(ALERTS_DSN, "alerts")
    return analytics_mod


@pytest.fixture()
def auth_client(auth):
    return auth.app.test_client()


@pytest.fixture()
def alert_client(alerts):
    return alerts.app.test_client()


@pytest.fixture()
def analytics_client(analytics):
    return analytics.app.test_client()


# ---------- helpers ----------
@pytest.fixture()
def make_token():
    def _make(role="admin", username="tester"):
        payload = {"sub": "1", "username": username, "role": role,
                   "exp": datetime.now() + timedelta(hours=1)}
        return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return _make


@pytest.fixture()
def insert_alert():
    """Insert an alert straight into the test database, N minutes ago (sensor time)."""
    def _insert(atype, src, minutes_ago=0, dst="10.0.0.5", dport="80"):
        when = datetime.now(ZoneInfo("Asia/Dhaka")).replace(tzinfo=None) - timedelta(minutes=minutes_ago)
        con = psycopg2.connect(ALERTS_DSN)
        con.cursor().execute(
            "INSERT INTO alerts(time,type,src,dst,dport,detail) VALUES(%s,%s,%s,%s,%s,%s)",
            (when.strftime("%Y-%m-%d %H:%M:%S"), atype, src, dst, dport, "test"))
        con.commit()
        con.close()
    return _insert
