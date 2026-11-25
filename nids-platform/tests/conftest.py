import importlib.util
import os
import pathlib
import re
import sys
import types
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlparse
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
    TEST_AUTO_VERIFY="true",
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


def _ensure_reportlab_stub():
    """Stub reportlab when it is not installed so non-PDF analytics tests can load analytics_app."""
    try:
        import reportlab  # noqa: F401
        return
    except ModuleNotFoundError:
        pass
    for mod_name in (
        "reportlab",
        "reportlab.lib",
        "reportlab.lib.colors",
        "reportlab.lib.pagesizes",
        "reportlab.lib.styles",
        "reportlab.lib.units",
        "reportlab.platypus",
        "reportlab.graphics",
        "reportlab.graphics.shapes",
        "reportlab.graphics.charts",
        "reportlab.graphics.charts.barcharts",
    ):
        if mod_name not in sys.modules:
            m = types.ModuleType(mod_name)
            m.A4 = (595, 842)
            m.cm = 28.35
            m.HexColor = lambda x: x
            m.white = "#fff"
            m.grey = "#888"
            m.getSampleStyleSheet = lambda: {"Title": None, "Normal": None, "Heading2": None}
            m.SimpleDocTemplate = object
            m.Paragraph = object
            m.Spacer = object
            m.Table = object
            m.TableStyle = object
            m.Drawing = object
            m.VerticalBarChart = object
            sys.modules[mod_name] = m
    sys.modules["reportlab.lib"].colors = sys.modules["reportlab.lib.colors"]


@pytest.fixture(scope="session")
def analytics_mod(alert_mod):          # alert_mod first: it creates the alerts table
    _ensure_reportlab_stub()
    return _load("analytics_app", "analytics-service", ALERTS_DSN)


# ---------- clean tables before every test ----------
@pytest.fixture()
def auth(auth_mod):
    _truncate(AUTH_DSN, "users, login_log, password_resets, password_change_attempts")
    return auth_mod


@pytest.fixture()
def alerts(alert_mod):
    _truncate(ALERTS_DSN, "alerts, sensor_status, email_cooldown, email_throttle")
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
    def _insert(atype, src, minutes_ago=0, dst="10.0.0.5", dport="80", owner_user_id=1):
        when = datetime.now(ZoneInfo("Asia/Dhaka")).replace(tzinfo=None) - timedelta(minutes=minutes_ago)
        con = psycopg2.connect(ALERTS_DSN)
        con.cursor().execute(
            "INSERT INTO alerts(time,type,src,dst,dport,detail,owner_user_id) VALUES(%s,%s,%s,%s,%s,%s,%s)",
            (when.strftime("%Y-%m-%d %H:%M:%S"), atype, src, dst, dport, "test", owner_user_id))
        con.commit()
        con.close()
    return _insert


# ---------- shared Flask stub for isolated unit tests ----------
class _FakeRequest:
    def __init__(self):
        self.headers = {}
        self.args = {}
        self.method = "GET"
        self.remote_addr = "127.0.0.1"
        self._json = None

    def get_json(self, silent=True):
        return self._json


class _FakeG(dict):
    __getattr__ = dict.get
    __setattr__ = dict.__setitem__


class _FakeResponse:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code

    def get_json(self):
        return self._data


def _fake_jsonify(*args, **kwargs):
    if args and isinstance(args[0], (dict, list)):
        return args[0]
    return dict(kwargs)


class _FakeFlaskApp:
    """Shared lightweight Flask stub for unit tests that mock the DB."""

    def __init__(self, name, *, req=None, log_lines=None):
        self.name = name
        self.config = {}
        self.routes = []
        self.before_request_funcs = []
        self.after_request_funcs = []
        self.error_handlers = {}
        self.teardowns = []
        self._req = req if req is not None else _FakeRequest()
        if log_lines is not None:
            self.logger = types.SimpleNamespace(
                info=lambda fmt, *a: log_lines.append(fmt % a if a else str(fmt)),
                warning=lambda fmt, *a: log_lines.append(fmt % a if a else str(fmt)),
                error=lambda fmt, *a: log_lines.append("ERROR: " + (fmt % a if a else str(fmt))),
            )
        else:
            self.logger = types.SimpleNamespace(
                info=lambda fmt, *a: None,
                warning=lambda fmt, *a: None,
                error=lambda fmt, *a: None,
            )

    def _add(self, rule, methods, fn):
        pat = re.sub(r"<int:(\w+)>", r"(?P<\1>\\d+)", rule)
        pat = re.sub(r"<(?:string:)?(\w+)>", r"(?P<\1>[^/]+)", pat)
        self.routes.append((rule, set(methods), re.compile("^" + pat + "$"), fn))

    def route(self, rule, methods=("GET",), **kwargs):
        def deco(fn):
            self._add(rule, methods, fn)
            return fn
        return deco

    def get(self, rule, **kwargs):
        return self.route(rule, methods=("GET",), **kwargs)

    def post(self, rule, **kwargs):
        return self.route(rule, methods=("POST",), **kwargs)

    def put(self, rule, **kwargs):
        return self.route(rule, methods=("PUT",), **kwargs)

    def patch(self, rule, **kwargs):
        return self.route(rule, methods=("PATCH",), **kwargs)

    def delete(self, rule, **kwargs):
        return self.route(rule, methods=("DELETE",), **kwargs)

    def before_request(self, fn):
        self.before_request_funcs.append(fn)
        return fn

    def after_request(self, fn):
        self.after_request_funcs.append(fn)
        return fn

    def errorhandler(self, code_or_exception):
        def deco(fn):
            self.error_handlers[code_or_exception] = fn
            return fn
        return deco

    def teardown_appcontext(self, fn):
        self.teardowns.append(fn)
        return fn

    def test_client(self):
        app = self
        req = self._req

        class Client:
            def _call(self, method, path, headers=None, json_body=None):
                u = urlparse(path)
                req.headers = {k: v for k, v in (headers or {}).items()}
                req.args = {k: v[0] for k, v in parse_qs(u.query).items()}
                req.method = method
                req._json = json_body
                for _rule, methods, regex, fn in app.routes:
                    if method in methods:
                        m = regex.match(u.path)
                        if m:
                            kw = {
                                k: (int(v) if v.isdigit() else v)
                                for k, v in m.groupdict().items()
                            }
                            res = fn(**kw)
                            if isinstance(res, tuple):
                                data, code = res
                                return _FakeResponse(data, code)
                            return _FakeResponse(res, 200)
                return _FakeResponse({"error": "Not found"}, 404)

            def get(self, path, headers=None):
                return self._call("GET", path, headers=headers)

            def post(self, path, headers=None, json=None):
                return self._call("POST", path, headers=headers, json_body=json)

            def put(self, path, headers=None, json=None):
                return self._call("PUT", path, headers=headers, json_body=json)

            def patch(self, path, headers=None, json=None):
                return self._call("PATCH", path, headers=headers, json_body=json)

            def delete(self, path, headers=None, json=None):
                return self._call("DELETE", path, headers=headers, json_body=json)

        return Client()


def make_fake_flask(log_lines=None):
    """Build an isolated fake `flask` module backed by `_FakeFlaskApp`."""
    fake_flask = types.ModuleType("flask")
    req = _FakeRequest()
    g = _FakeG()

    class _BoundFakeFlaskApp(_FakeFlaskApp):
        def __init__(self, name):
            super().__init__(name, req=req, log_lines=log_lines)

    fake_flask.Flask = _BoundFakeFlaskApp
    fake_flask.request = req
    fake_flask.jsonify = _fake_jsonify
    fake_flask.g = g
    fake_flask.send_file = lambda *a, **kw: ("pdf", 200)
    return fake_flask


@pytest.fixture()
def fake_flask(monkeypatch):
    """Install the shared fake `flask` module for the duration of a test."""
    mod = make_fake_flask()
    monkeypatch.setitem(sys.modules, "flask", mod)
    return mod
