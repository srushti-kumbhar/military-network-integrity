import pandas as pd


def detect_threats(file_path):
    df = pd.read_csv(file_path)
    alerts = []

    for _, row in df.iterrows():
        src_ip = row["src_ip"]

        # Port scan-like detection
        if row["unique_ports"] >= 15:
            alerts.append({
                "src_ip": src_ip,
                "threat": "Port Scan-like Activity",
                "severity": "HIGH",
                "details": f'{int(row["unique_ports"])} unique destination ports detected'
            })

        # Repeated connection attempts
        if row["total_packets"] >= 25 and row["tcp_packets"] >= 20:
            alerts.append({
                "src_ip": src_ip,
                "threat": "Repeated TCP Connection Attempts",
                "severity": "HIGH",
                "details": f'{int(row["tcp_packets"])} TCP packets detected'
            })

        # High traffic rate
        if row["packets_per_second"] >= 8:
            alerts.append({
                "src_ip": src_ip,
                "threat": "Unusually High Packet Rate",
                "severity": "MEDIUM",
                "details": f'{row["packets_per_second"]:.2f} packets per second'
            })

        # Unusually high traffic volume
        if row["total_bytes"] >= 5000:
            alerts.append({
                "src_ip": src_ip,
                "threat": "High Traffic Volume",
                "severity": "MEDIUM",
                "details": f'{int(row["total_bytes"])} bytes transmitted'
            })

    return pd.DataFrame(alerts)


if __name__ == "__main__":
    input_file = "data/processed/network_features.csv"

    results = detect_threats(input_file)

    print("\nRULE-BASED INTRUSION DETECTION")
    print("-----------------------------")

    if results.empty:
        print("No suspicious activity detected.")
    else:
        print(results.to_string(index=False))

    output_file = "data/processed/rule_alerts.csv"
    results.to_csv(output_file, index=False)

    print("\nAlerts saved successfully:", output_file)
    print("Total alerts:", len(results))