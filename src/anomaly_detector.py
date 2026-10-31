import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def detect_anomalies(file_path):
    df = pd.read_csv(file_path)

    features = [
        "total_packets",
        "unique_destinations",
        "unique_ports",
        "avg_packet_size",
        "total_bytes",
        "tcp_packets",
        "udp_packets",
        "icmp_packets",
        "unique_protocols",
        "duration",
        "packets_per_second"
    ]

    X = df[features].fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=100,
        contamination=0.4,
        random_state=42
    )

    predictions = model.fit_predict(X_scaled)
    scores = model.decision_function(X_scaled)

    df["anomaly_prediction"] = predictions
    df["anomaly_score"] = scores
    df["anomaly_status"] = df["anomaly_prediction"].map({
        1: "NORMAL",
        -1: "ANOMALY"
    })

    return df


if __name__ == "__main__":
    input_file = "data/processed/network_features.csv"

    results = detect_anomalies(input_file)

    print("\nISOLATION FOREST RESULTS")
    print("-----------------------")
    print(results[
        ["src_ip", "anomaly_status", "anomaly_score"]
    ].to_string(index=False))

    output_file = "data/processed/anomaly_results.csv"
    results.to_csv(output_file, index=False)

    print("\nResults saved successfully:", output_file)
    print("\nTotal anomalies:",
          (results["anomaly_status"] == "ANOMALY").sum())