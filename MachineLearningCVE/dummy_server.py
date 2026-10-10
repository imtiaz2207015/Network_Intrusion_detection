"""
dummy_server.py
===============
Opens a TCP server on port 9999 on ALL interfaces (0.0.0.0).
This lets simulate_bruteforce.py connect to 192.168.0.106:9999
which IS visible to Scapy (real network interface, not loopback).

Run this in Terminal 3 (keep running):
    python dummy_server.py
"""

import socket
import threading

HOST = "0.0.0.0"
PORT = 9999

def handle(conn, addr):
    try:
        conn.close()  # immediately close — simulates "refused" behavior
    except:
        pass

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(100)
print(f"[*] Dummy TCP server listening on {HOST}:{PORT}")
print(f"[*] Scapy will see connections to this port on your LAN IP")
print(f"    (e.g. 192.168.0.106:9999)")
print(f"[*] Keep this running. Ctrl+C to stop.")

while True:
    try:
        conn, addr = server.accept()
        t = threading.Thread(target=handle, args=(conn, addr), daemon=True)
        t.start()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        break
