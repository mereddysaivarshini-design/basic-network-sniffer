from scapy.all import sniff, IP, TCP, UDP, Raw


def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            protocol = str(packet[IP].proto)
            src_port = "-"
            dst_port = "-"

        print("\n--------------------------------")
        print(f"Source IP       : {src_ip}")
        print(f"Destination IP  : {dst_ip}")
        print(f"Protocol        : {protocol}")
        print(f"Source Port     : {src_port}")
        print(f"Destination Port: {dst_port}")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload         : {payload[:50]!r}")
        else:
            print("Payload         : No payload")

        print("--------------------------------")


print("Starting Network Sniffer...")
print("Press Ctrl+C to stop.")

sniff(prn=packet_callback, store=False)