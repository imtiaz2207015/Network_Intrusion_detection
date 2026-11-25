import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from scapy.all import IP, TCP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import live_feature_extractor as lfe


class TestBruteForceDetection(unittest.TestCase):

    def setUp(self):
        """Clear all trackers before each test."""
        lfe.brute_force_tracker.clear()
        lfe.brute_already_flagged.clear()
        lfe.port_scan_tracker.clear()
        lfe.already_flagged.clear()
        lfe.dos_syn_tracker.clear()
        lfe.dos_already_flagged.clear()
        lfe.flows.clear()
        lfe.seen_flows.clear()
        lfe.last_alert.clear()
        self._orig_ignore_src = lfe.IGNORE_SRC
        lfe.IGNORE_SRC = set()

    def tearDown(self):
        lfe.IGNORE_SRC = self._orig_ignore_src

    # ── TCP flag filtering via process_packet ────────────────────────────────
    def test_pure_syn_counts_as_attempt(self):
        """Pure SYN (0x02) to a login service port is tracked as a brute-force attempt."""
        pkt = IP(src="10.0.0.10", dst="192.168.0.106") / TCP(sport=40001, dport=22, flags="S")
        with patch.object(lfe, "log_alert"):
            lfe.process_packet(pkt)
        self.assertEqual(len(lfe.brute_force_tracker[("10.0.0.10", "192.168.0.106", 22)]), 1)

    def test_syn_ack_is_not_attempt(self):
        """SYN+ACK (0x12) is the server reply, NOT a client brute-force attempt."""
        pkt = IP(src="10.0.0.11", dst="192.168.0.106") / TCP(sport=40002, dport=22, flags="SA")
        with patch.object(lfe, "log_alert"):
            for _ in range(12):
                lfe.process_packet(pkt)
        self.assertEqual(len(lfe.brute_force_tracker[("10.0.0.11", "192.168.0.106", 22)]), 0)

    def test_plain_ack_is_not_attempt(self):
        """Plain ACK (0x10) must NOT be counted as a brute-force attempt."""
        pkt = IP(src="10.0.0.12", dst="192.168.0.106") / TCP(sport=40003, dport=22, flags="A")
        with patch.object(lfe, "log_alert"):
            for _ in range(12):
                lfe.process_packet(pkt)
        self.assertEqual(len(lfe.brute_force_tracker[("10.0.0.12", "192.168.0.106", 22)]), 0)

    def test_rst_and_rst_ack_are_not_counted_as_syn_attempts(self):
        """RST (0x04) and RST+ACK (0x14) are not pure SYNs and must not trigger BruteForce."""
        with patch.object(lfe, "log_alert") as mock_log:
            for flags in ("R", "RA"):
                pkt = IP(src="10.0.0.13", dst="192.168.0.106") / TCP(sport=40004, dport=22, flags=flags)
                for _ in range(10):
                    lfe.process_packet(pkt)
        brute_calls = [c for c in mock_log.call_args_list if c.args and c.args[0] == "BruteForce"]
        self.assertEqual(brute_calls, [])

    # ── check_brute_force ────────────────────────────────────────────────────
    def test_detects_syn_burst_at_threshold(self):
        """8 pure SYNs to SSH (port 22) within BRUTE_WINDOW triggers detection at attempt 8."""
        with patch.object(lfe, "log_alert") as mock_log:
            for i in range(1, lfe.BRUTE_SYN_THRESHOLD):
                self.assertFalse(
                    lfe.check_brute_force("10.0.0.2", "192.168.0.106", 22),
                    f"Should not trigger on attempt {i}",
                )
            self.assertTrue(lfe.check_brute_force("10.0.0.2", "192.168.0.106", 22))
        self.assertEqual(mock_log.call_count, 1)
        self.assertEqual(mock_log.call_args.args[:4], ("BruteForce", "10.0.0.2", "192.168.0.106", 22))

    def test_no_alert_below_threshold(self):
        """7 attempts (< 8 threshold) must NOT trigger detection."""
        with patch.object(lfe, "log_alert") as mock_log:
            results = [
                lfe.check_brute_force("10.0.0.4", "192.168.0.106", 22)
                for _ in range(lfe.BRUTE_SYN_THRESHOLD - 1)
            ]
        self.assertFalse(any(results))
        self.assertEqual(mock_log.call_count, 0)

    def test_ignores_non_service_ports(self):
        """High SYN bursts to non-login ports (e.g. 80, 443, 4444) must NOT trigger BruteForce."""
        with patch.object(lfe, "log_alert") as mock_log:
            for port in (80, 443, 4444):
                for _ in range(20):
                    self.assertFalse(lfe.check_brute_force("10.0.0.6", "192.168.0.106", port))
        self.assertEqual(mock_log.call_count, 0)

    def test_detects_all_configured_login_ports(self):
        """Every port in BRUTE_FORCE_PORTS triggers BruteForce at BRUTE_SYN_THRESHOLD."""
        with patch.object(lfe, "log_alert") as mock_log:
            for port in sorted(lfe.BRUTE_FORCE_PORTS):
                detected = False
                for _ in range(lfe.BRUTE_SYN_THRESHOLD):
                    if lfe.check_brute_force("10.0.0.7", "192.168.0.106", port):
                        detected = True
                        break
                self.assertTrue(detected, f"Expected BruteForce detection on port {port}")
        self.assertEqual(mock_log.call_count, len(lfe.BRUTE_FORCE_PORTS))

    def test_rearms_after_window_expires(self):
        """Once attempts fall outside BRUTE_WINDOW, a new burst triggers a fresh alert."""
        now = [1_000_000.0]
        with patch.object(lfe.time, "time", side_effect=lambda: now[0]), \
             patch.object(lfe, "log_alert") as mock_log:
            for _ in range(lfe.BRUTE_SYN_THRESHOLD):
                lfe.check_brute_force("10.0.0.5", "192.168.0.106", 22)
            self.assertEqual(mock_log.call_count, 1)

            # Advance past BRUTE_WINDOW: first packet clears the flagged state
            now[0] += lfe.BRUTE_WINDOW + 1
            self.assertFalse(lfe.check_brute_force("10.0.0.5", "192.168.0.106", 22))
            for _ in range(lfe.BRUTE_SYN_THRESHOLD - 1):
                lfe.check_brute_force("10.0.0.5", "192.168.0.106", 22)
            self.assertEqual(mock_log.call_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
