import pandas as pd


def extract_features(file_path):
    df = pd.read_csv(file_path)

    features = df.groupby("src_ip").agg(
        total_packets=("src_ip", "count"),
        unique_destinations=("dst_ip", "nunique"),
        unique_ports=("dst_port", "nunique"),
        avg_packet_size=("packet_size", "mean"),
        total_bytes=("packet_size", "sum"),
        tcp_packets=("protocol", lambda x: (x == "TCP").sum()),
        udp_packets=("protocol", lambda x: (x == "UDP").sum()),
        icmp_packets=("protocol", lambda x: (x == "ICMP").sum()),
        unique_protocols=("protocol", "nunique")
    ).reset_index()

    features["duration"] = df.groupby("src_ip")["timestamp"].agg(
        lambda x: x.max() - x.min()
    ).values

    features["packets_per_second"] = (
        features["total_packets"] /
        features["duration"].replace(0, 1)
    )

    return features


if __name__ == "__main__":
    input_file = "data/processed/packet_data.csv"

    features = extract_features(input_file)

    print("\nNETWORK FEATURE EXTRACTION RESULTS")
    print("---------------------------------")
    print(features.to_string(index=False))

    output_file = "data/processed/network_features.csv"
    features.to_csv(output_file, index=False)

    print("\nFeatures saved successfully:", output_file)