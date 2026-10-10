from scapy.all import sniff, IP

def show_packet(pkt):
    if IP in pkt:
        print(f"{pkt[IP].src} -> {pkt[IP].dst}")

print("Capturing for 10 seconds targeting self-scan...")
sniff(prn=show_packet, timeout=10, filter="host 192.168.0.106")