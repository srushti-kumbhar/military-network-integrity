import pandas as pd


def evaluate_detections():
    rule_file = "data/processed/rule_alerts.csv"
    ml_file = "data/processed/anomaly_results.csv"

    rules = pd.read_csv(rule_file)
    ml_results = pd.read_csv(ml_file)

    # Summarize rule-based alerts by source IP
    if not rules.empty:
        rule_summary = rules.groupby("src_ip").agg(
            rule_alert_count=("threat", "count"),
            detected_threats=("threat", lambda x: "; ".join(x)),
            highest_rule_severity=("severity", lambda x:
                "HIGH" if "HIGH" in x.values else "MEDIUM")
        ).reset_index()
    else:
        rule_summary = pd.DataFrame(columns=[
            "src_ip", "rule_alert_count",
            "detected_threats", "highest_rule_severity"
        ])

    # Combine rule-based and machine-learning results
    report = ml_results.merge(rule_summary, on="src_ip", how="left")

    report["rule_alert_count"] = report["rule_alert_count"].fillna(0).astype(int)
    report["detected_threats"] = report["detected_threats"].fillna("None")
    report["highest_rule_severity"] = report["highest_rule_severity"].fillna("NONE")

    def classify(row):
        if row["highest_rule_severity"] == "HIGH":
            return "HIGH"
        if (
            row["highest_rule_severity"] == "MEDIUM"
            or row["anomaly_status"] == "ANOMALY"
        ):
            return "MEDIUM"
        return "NORMAL"

    report["overall_status"] = report.apply(classify, axis=1)

    output_file = "data/processed/final_detection_report.csv"
    report.to_csv(output_file, index=False)

    print("\nFINAL NETWORK INTEGRITY REPORT")
    print("--------------------------------")
    print(report[[
        "src_ip",
        "anomaly_status",
        "rule_alert_count",
        "overall_status"
    ]].to_string(index=False))

    print("\nReport saved successfully:", output_file)


if __name__ == "__main__":
    evaluate_detections()