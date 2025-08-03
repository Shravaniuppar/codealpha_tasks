from scapy.all import sniff, IP, TCP, UDP, ICMP

# Function to process each packet
def process_packet(packet):
    print("="*60)
    
    # Check for IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for transport layer protocols
        if packet.haslayer(TCP):
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
            print(f"Payload: {bytes(packet[TCP].payload)}")

        elif packet.haslayer(UDP):
            print("Protocol: UDP")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
            print(f"Payload: {bytes(packet[UDP].payload)}")

        elif packet.haslayer(ICMP):
            print("Protocol: ICMP")
            print(f"Type: {packet[ICMP].type}")
            print(f"Code: {packet[ICMP].code}")
    
    else:
        print("Non-IP packet received")

# Start sniffing packets
print("Starting packet sniffing... Press Ctrl+C to stop.\n")
sniff(prn=process_packet, count=10, iface="Wi-Fi", store=False)

print("\nPacket sniffing stopped.")