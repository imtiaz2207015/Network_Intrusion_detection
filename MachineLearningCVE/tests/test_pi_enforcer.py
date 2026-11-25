"""Unit tests for MachineLearningCVE/pi_enforcer.py with mocked subprocess and HTTP."""

import importlib.util
import logging
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load_pi_enforcer():
    spec = importlib.util.spec_from_file_location("pi_enforcer_mod", ROOT / "pi_enforcer.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pi_enforcer_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


pe = _load_pi_enforcer()


class FakeIptablesRunner:
    """In-memory fake subprocess.run for iptables commands."""

    def __init__(self):
        self.calls = []
        self.chain_created = False
        self.input_jump = False
        self.rules = []  # list of blocked IPv4 strings

    def __call__(self, cmd, **kwargs):
        assert isinstance(cmd, list), "subprocess must be called with a list, never a string"
        assert kwargs.get("shell") in (None, False), "shell=True is forbidden"
        self.calls.append(list(cmd))

        # Strip binary name
        args = cmd[1:]
        if args[:2] == ["-L", pe.CHAIN_NAME]:
            if not self.chain_created:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="No chain/target/match by that name.")
            body = "\n".join(f"DROP all -- {ip} 0.0.0.0/0" for ip in self.rules)
            return subprocess.CompletedProcess(cmd, 0, stdout=f"Chain {pe.CHAIN_NAME}\n{body}\n", stderr="")

        if args == ["-N", pe.CHAIN_NAME]:
            if self.chain_created:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Chain already exists.")
            self.chain_created = True
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if args == ["-C", "INPUT", "-j", pe.CHAIN_NAME]:
            return subprocess.CompletedProcess(cmd, 0 if self.input_jump else 1, stdout="", stderr="")

        if args == ["-I", "INPUT", "1", "-j", pe.CHAIN_NAME]:
            self.input_jump = True
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if args == ["-D", "INPUT", "-j", pe.CHAIN_NAME]:
            if not self.input_jump:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Bad rule")
            self.input_jump = False
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if args == ["-S", pe.CHAIN_NAME]:
            if not self.chain_created:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="No chain")
            lines = [f"-N {pe.CHAIN_NAME}"] + [
                f"-A {pe.CHAIN_NAME} -s {ip}/32 -j DROP" for ip in self.rules
            ]
            return subprocess.CompletedProcess(cmd, 0, stdout="\n".join(lines) + "\n", stderr="")

        if len(args) == 6 and args[:3] == ["-A", pe.CHAIN_NAME, "-s"] and args[4:] == ["-j", "DROP"]:
            self.rules.append(args[3])
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if len(args) == 6 and args[:3] == ["-D", pe.CHAIN_NAME, "-s"] and args[4:] == ["-j", "DROP"]:
            if args[3] not in self.rules:
                return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="Rule not found")
            self.rules.remove(args[3])
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if args == ["-F", pe.CHAIN_NAME]:
            self.rules.clear()
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        if args == ["-X", pe.CHAIN_NAME]:
            self.chain_created = False
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        raise AssertionError(f"Unexpected iptables command: {cmd}")


def test_add_and_remove_blocked_ips():
    runner = FakeIptablesRunner()
    backend = pe.IptablesBackend(dry_run=False, runner=runner)
    responses = [
        {"ips": ["203.0.113.10", "203.0.113.20"], "allowlist": []},
        {"ips": ["203.0.113.20"], "allowlist": []},
    ]
    enforcer = pe.PiEnforcer(
        platform_url="http://127.0.0.1:8088",
        sensor_key="test-key",
        dry_run=False,
        local_ips={"192.168.1.50"},
        backend=backend,
        fetcher=lambda: responses.pop(0),
    )

    r1 = enforcer.sync_once()
    assert r1["ok"] is True
    assert r1["added"] == ["203.0.113.10", "203.0.113.20"]
    assert runner.chain_created is True
    assert runner.input_jump is True
    assert set(runner.rules) == {"203.0.113.10", "203.0.113.20"}

    # Second poll: 203.0.113.10 unblocked/expired -> removed, jump not duplicated
    r2 = enforcer.sync_once()
    assert r2["ok"] is True
    assert r2["added"] == []
    assert r2["removed"] == ["203.0.113.10"]
    assert runner.rules == ["203.0.113.20"]
    jump_inserts = [c for c in runner.calls if c == ["iptables", "-I", "INPUT", "1", "-j", "NIDS_BLOCK"]]
    assert len(jump_inserts) == 1


def test_protected_ips_are_skipped_with_warning(caplog):
    runner = FakeIptablesRunner()
    backend = pe.IptablesBackend(dry_run=False, runner=runner)
    enforcer = pe.PiEnforcer(
        platform_url="http://127.0.0.1:8088",
        sensor_key="test-key",
        dry_run=False,
        local_ips={"192.168.1.50"},
        protected_ips={"192.168.1.1", "192.168.1.100"},
        backend=backend,
        fetcher=lambda: {
            "ips": ["127.0.0.1", "192.168.1.50", "192.168.1.1", "192.168.1.100", "198.51.100.7"],
            "allowlist": ["198.51.100.7"],
        },
    )

    with caplog.at_level(logging.WARNING, logger="pi_enforcer"):
        res = enforcer.sync_once()

    assert res["ok"] is True
    assert res["added"] == []
    assert runner.rules == []
    assert "Skipping protected IP 127.0.0.1" in caplog.text
    assert "Skipping protected IP 192.168.1.50" in caplog.text
    assert "Skipping protected IP 192.168.1.1" in caplog.text
    assert "Skipping protected IP 192.168.1.100" in caplog.text
    assert "Skipping protected IP 198.51.100.7" in caplog.text


def test_invalid_ips_are_rejected_before_iptables(caplog):
    runner = FakeIptablesRunner()
    backend = pe.IptablesBackend(dry_run=False, runner=runner)
    enforcer = pe.PiEnforcer(
        platform_url="http://127.0.0.1:8088",
        sensor_key="test-key",
        dry_run=False,
        local_ips={"192.168.1.50"},
        backend=backend,
        fetcher=lambda: {
            "ips": [
                "not-an-ip",
                "1.2.3.4; rm -rf /",
                "203.0.113.0/24",
                "999.999.999.999",
                "203.0.113.55",
            ]
        },
    )

    with caplog.at_level(logging.WARNING, logger="pi_enforcer"):
        res = enforcer.sync_once()

    assert res["ok"] is True
    assert res["added"] == ["203.0.113.55"]
    assert runner.rules == ["203.0.113.55"]
    assert "Rejected invalid IP" in caplog.text
    # Ensure no invalid string ever reached subprocess
    for call in runner.calls:
        assert all("rm -rf" not in arg and "not-an-ip" not in arg for arg in call)


def test_dry_run_runs_no_iptables_commands(caplog):
    runner = FakeIptablesRunner()
    backend = pe.IptablesBackend(dry_run=True, runner=runner)
    enforcer = pe.PiEnforcer(
        platform_url="http://127.0.0.1:8088",
        sensor_key="test-key",
        dry_run=True,
        local_ips={"192.168.1.50"},
        backend=backend,
        fetcher=lambda: {"ips": ["203.0.113.77"]},
    )

    with caplog.at_level(logging.INFO, logger="pi_enforcer"):
        res = enforcer.sync_once()

    assert res["ok"] is True
    assert res["added"] == ["203.0.113.77"]
    assert runner.calls == []  # zero subprocess executions in dry-run mode
    assert "[DRY_RUN] would run: iptables -A NIDS_BLOCK -s 203.0.113.77 -j DROP" in caplog.text


def test_api_failure_keeps_existing_rules_and_backs_off():
    runner = FakeIptablesRunner()
    backend = pe.IptablesBackend(dry_run=False, runner=runner)
    should_fail = {"flag": False}

    def fetch():
        if should_fail["flag"]:
            raise OSError("connection refused")
        return {"ips": ["203.0.113.99"]}

    enforcer = pe.PiEnforcer(
        platform_url="http://127.0.0.1:8088",
        sensor_key="test-key",
        poll_interval=10.0,
        dry_run=False,
        local_ips={"192.168.1.50"},
        backend=backend,
        fetcher=fetch,
    )

    assert enforcer.sync_once()["ok"] is True
    assert runner.rules == ["203.0.113.99"]

    should_fail["flag"] = True
    calls_before = len(runner.calls)
    r_fail = enforcer.sync_once()
    assert r_fail["ok"] is False
    assert runner.rules == ["203.0.113.99"]  # existing block preserved
    assert len(runner.calls) == calls_before  # no iptables changes attempted
    assert enforcer._backoff_sec == 20.0


def test_null_expiry_stays_blocked_while_past_expiry_is_ignored():
    runner = FakeIptablesRunner()
    backend = pe.IptablesBackend(dry_run=False, runner=runner)
    now = 1_700_000_000.0
    enforcer = pe.PiEnforcer(
        platform_url="http://127.0.0.1:8088",
        sensor_key="test-key",
        dry_run=False,
        local_ips={"192.168.1.50"},
        backend=backend,
        fetcher=lambda: {
            "blocked": [
                {"ip": "203.0.113.31", "expires_at": None},          # until unblocked
                {"ip": "203.0.113.32", "expires_at": now + 3600},    # future expiry
                {"ip": "203.0.113.33", "expires_at": now - 10},      # already expired
            ]
        },
    )

    res = enforcer.sync_once(now_ts=now)
    assert res["ok"] is True
    assert set(runner.rules) == {"203.0.113.31", "203.0.113.32"}


def test_cleanup_removes_jump_flushes_and_deletes_chain():
    runner = FakeIptablesRunner()
    backend = pe.IptablesBackend(dry_run=False, runner=runner)
    backend.ensure_chain_and_jump()
    backend.add_ip("203.0.113.44")
    assert runner.chain_created is True
    assert runner.input_jump is True
    assert runner.rules == ["203.0.113.44"]

    backend.cleanup()
    assert runner.input_jump is False
    assert runner.chain_created is False
    assert runner.rules == []
