
from scapy.all import sniff, IP, TCP, UDP, ICMP

count = 0

def analyze_packet(packet):
    global count
    count += 1

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        print(f"\nPacket #{count}")
        print("[+] Packet Captured")
        print(f"Source: {src}")
        print(f"Destination: {dst}")

        # Save to log file (auto create + save)
        with open("log.txt", "a") as log_file:
            log_file.write(f"Packet #{count}: {src} -> {dst}\n")

    if packet.haslayer(TCP):
        print("Protocol: TCP")
    elif packet.haslayer(UDP):
        print("Protocol: UDP")
    elif packet.haslayer(ICMP):
        print("Protocol: ICMP")


print("Starting Packet Capture... Press CTRL+C to stop.")
sniff(prn=analyze_packet, store=0)
