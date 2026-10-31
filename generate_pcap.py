from scapy.all import Ether, IP, TCP, UDP, ICMP, wrpcap
from datetime import datetime
import random

random.seed(42)

packets = []
base_time = datetime.now().timestamp()

# Normal TCP traffic
for i in range(20):
    packet = (
        Ether() /
        IP(src="192.168.1.10", dst="192.168.1.20") /
        TCP(sport=50000 + i, dport=80, flags="S")
    )
    packet.time = base_time + i
    packets.append(packet)

# Normal UDP traffic
for i in range(10):
    packet = (
        Ether() /
        IP(src="192.168.1.15", dst="192.168.1.20") /
        UDP(sport=40000 + i, dport=53)
    )
    packet.time = base_time + 30 + i
    packets.append(packet)

# ICMP traffic
for i in range(5):
    packet = (
        Ether() /
        IP(src="192.168.1.30", dst="192.168.1.20") /
        ICMP()
    )
    packet.time = base_time + 45 + i
    packets.append(packet)

# Simulated repeated connection attempts
for i in range(30):
    packet = (
        Ether() /
        IP(src="192.168.1.99", dst="192.168.1.20") /
        TCP(sport=55000 + i, dport=22, flags="S")
    )
    packet.time = base_time + 50 + i * 0.1
    packets.append(packet)

# Simulated port-scan-like traffic
for i in range(25):
    packet = (
        Ether() /
        IP(src="192.168.1.77", dst="192.168.1.20") /
        TCP(sport=56000 + i, dport=1000 + i, flags="S")
    )
    packet.time = base_time + 55 + i * 0.1
    packets.append(packet)

# Shuffle packets
random.shuffle(packets)

# Save synthetic PCAP
output_file = "pcaps/sample/synthetic_traffic.pcap"
wrpcap(output_file, packets)

print("Synthetic PCAP created successfully!")
print("Total packets:", len(packets))
print("Saved to:", output_file)