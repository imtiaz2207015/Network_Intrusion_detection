"""
simulate_bruteforce.py
======================
Simulates rapid repeated TCP connection attempts to trigger brute-force detection.

DEPLOYMENT:
  - Copy this file to Raspberry Pi.
  - Set target_ip = Windows laptop's LAN IP (e.g. 192.168.0.106).
  - Run live_feature_extractor.py on Windows FIRST, then run this on Pi.

WHY Pi works (no loopback issue):
  Pi has its own IP → Windows is a different machine → real network traffic
  → Scapy on Windows captures it perfectly.
"""

import socket
import time

# ─── CONFIG ──────────────────────────────────────────────────────────────────
# Set this to the Windows laptop's LAN IP (the machine running live_feature_extractor.py)
target_ip   = "192.168.0.100"  # ← Windows laptop IP
target_port = 9999              # Any port works. Use 9999 (dummy_server) for CONNECTED,
                                # or any closed port for RST+ACK (both are detected).
num_attempts   = 30             # 30 >> threshold of 8 → alert will fire
delay_between  = 0.05           # 50ms between attempts → all 30 done in ~1.5s
# ─────────────────────────────────────────────────────────────────────────────

print(f"[*] Simulating brute-force: {num_attempts} connection attempts")
print(f"    Attacker : This Pi")
print(f"    Target   : {target_ip}:{target_port}")
print(f"    Delay    : {delay_between}s  |  Window: 10s")
print(f"    Threshold to trigger alert: 8 attempts")
print()

for i in range(num_attempts):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect((target_ip, target_port))
        s.close()
        status = "CONNECTED"
    except ConnectionRefusedError:
        status = "REFUSED (RST+ACK)"   # closed port → still detected!
    except socket.timeout:
        status = "TIMEOUT"
    except OSError as e:
        status = f"ERR:{e.errno}"

    print(f"  Attempt {i+1:02d}/{num_attempts}: {status}")
    time.sleep(delay_between)

print()
print("[*] Done. Check Windows Terminal (live_feature_extractor.py) for:")
print("    [ATTACK - BruteForce detected] ...")