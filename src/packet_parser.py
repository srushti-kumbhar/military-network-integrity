import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, ICMP


def parse_pcap(file_path):
    packets = rdpcap(file_path)
    records = []

    for packet in packets:
        if IP not in packet:
            continue

        ip_layer = packet[IP]

        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        tcp_flags = ""

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        records.append({
            "timestamp": float(packet.time),
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": len(packet),
            "tcp_flags": tcp_flags
        })

    return pd.DataFrame(records)


if __name__ == "__main__":
    file_path = "pcaps/sample/synthetic_traffic.pcap"

    df = parse_pcap(file_path)

    print("\nPACKET PARSER RESULTS")
    print("---------------------")
    print("Total IP packets:", len(df))
    print("\nProtocol distribution:")
    print(df["protocol"].value_counts())
    print("\nFirst 10 packets:")
    print(df.head(10).to_string(index=False))

    output_file = "data/processed/packet_data.csv"
    df.to_csv(output_file, index=False)

    print("\nCSV saved successfully:", output_file)