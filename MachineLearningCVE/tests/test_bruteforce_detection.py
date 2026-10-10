import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import live_feature_extractor as lfe


class TestBruteForceDetection(unittest.TestCase):

    def setUp(self):
        """Clear all trackers before each test."""
        lfe.brute_force_tracker.clear()
        lfe.brute_already_flagged.clear()
        lfe.highfreq_tracker.clear()
        lfe.highfreq_already_flagged.clear()

    # ── is_connection_attempt ────────────────────────────────────────────────
    def test_pure_syn_is_attempt(self):
        self.assertTrue(lfe.is_connection_attempt(0x02))   # SYN

    def test_pure_rst_is_attempt(self):
        self.assertTrue(lfe.is_connection_attempt(0x04))   # RST

    def test_rst_ack_is_attempt(self):
        """RST+ACK (0x14) — server actively refusing. Must be counted."""
        self.assertTrue(lfe.is_connection_attempt(0x14))   # RST+ACK  ← new

    def test_syn_ack_is_not_attempt(self):
        """SYN+ACK is the server reply, NOT a client attempt."""
        self.assertFalse(lfe.is_connection_attempt(0x12))  # SYN+ACK

    def test_plain_ack_is_not_attempt(self):
        self.assertFalse(lfe.is_connection_attempt(0x10))  # ACK

    # ── check_brute_force ────────────────────────────────────────────────────
    def test_detects_mixed_syn_reset_burst(self):
        """5 SYNs + 3 RSTs = 8 attempts → detection triggers at attempt 8."""
        detected = False
        for flags in [0x02] * 5 + [0x04] * 3:
            if lfe.check_brute_force("10.0.0.2", "192.168.0.106", 22, flags):
                detected = True
                break
        self.assertTrue(detected)

    def test_detects_rst_ack_burst(self):
        """Server replies with RST+ACK (0x14). Must still count as attempts."""
        # 5 SYNs from attacker  +  5 RST+ACK from server (both same direction key)
        # Actually attacker sends SYN, we see SYNs here:
        detected = False
        for flags in [0x02] * 5 + [0x14] * 5:  # 10 packets total
            if lfe.check_brute_force("10.0.0.3", "192.168.0.106", 22, flags):
                detected = True
                break
        self.assertTrue(detected)

    def test_no_alert_below_threshold(self):
        """7 attempts (< 8 threshold) must NOT trigger detection."""
        results = [
            lfe.check_brute_force("10.0.0.4", "192.168.0.106", 22, 0x02)
            for _ in range(7)
        ]
        self.assertFalse(any(results))

    # ── check_highfreq_syn ───────────────────────────────────────────────────
    def test_highfreq_detects_rapid_syns(self):
        """8 SYNs to same port within window → high-freq detection fires."""
        detected = False
        for _ in range(8):
            if lfe.check_highfreq_syn("10.0.0.5", "192.168.0.106", 22):
                detected = True
                break
        self.assertTrue(detected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
