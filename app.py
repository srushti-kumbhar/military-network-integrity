import streamlit as st
import pandas as pd
from pathlib import Path

st.set_page_config(
    page_title="Military Network Integrity",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Military Network Integrity")
st.subheader("Automated Packet Sniffer and Intrusion Detection System")

st.caption("Defensive cybersecurity prototype | Offline synthetic PCAP analysis")

DATA = Path("data/processed")


def load_csv(filename):
    path = DATA / filename
    if path.exists():
        return pd.read_csv(path)
    return pd.DataFrame()


packets = load_csv("packet_data.csv")
features = load_csv("network_features.csv")
alerts = load_csv("rule_alerts.csv")
ml_results = load_csv("anomaly_results.csv")
report = load_csv("final_detection_report.csv")

st.divider()

if report.empty:
    st.warning("Final report not found. Run the analysis scripts first.")
else:
    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Source IPs", len(report))
    col2.metric(
        "ML Anomalies",
        (report["anomaly_status"] == "ANOMALY").sum()
    )
    col3.metric("Rule-Based Alerts", len(alerts))
    col4.metric(
        "High-Risk Sources",
        (report["overall_status"] == "HIGH").sum()
    )

st.divider()

overview_tab, packets_tab, alerts_tab, ml_tab, report_tab = st.tabs([
    "Overview",
    "Packet Analysis",
    "Rule-Based Alerts",
    "ML Detection",
    "Final Report"
])

with overview_tab:
    st.header("Network Overview")

    if not packets.empty:
        st.write("Protocol distribution")
        protocol_counts = packets["protocol"].value_counts()
        st.bar_chart(protocol_counts)

        st.write("Traffic by source IP")
        traffic = packets["src_ip"].value_counts()
        st.bar_chart(traffic)
    else:
        st.info("Packet data is not available.")

with packets_tab:
    st.header("Packet Analysis")

    if not packets.empty:
        st.write(f"Total packets analysed: {len(packets)}")
        st.dataframe(packets, use_container_width=True)
    else:
        st.info("Packet data is not available.")

    if not features.empty:
        st.subheader("Extracted Network Features")
        st.dataframe(features, use_container_width=True)

with alerts_tab:
    st.header("Rule-Based Intrusion Detection")

    if not alerts.empty:
        st.dataframe(alerts, use_container_width=True)

        st.subheader("Alert Severity Distribution")
        st.bar_chart(alerts["severity"].value_counts())
    else:
        st.success("No rule-based alerts found.")

with ml_tab:
    st.header("Isolation Forest Anomaly Detection")

    if not ml_results.empty:
        st.dataframe(
            ml_results[[
                "src_ip",
                "anomaly_status",
                "anomaly_score"
            ]],
            use_container_width=True
        )

        st.subheader("ML Detection Distribution")
        st.bar_chart(ml_results["anomaly_status"].value_counts())
    else:
        st.info("ML results are not available.")

with report_tab:
    st.header("Combined Detection Report")

    if not report.empty:
        st.dataframe(report, use_container_width=True)

        st.subheader("Overall Risk Distribution")
        st.bar_chart(report["overall_status"].value_counts())

        csv_data = report.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="Download Final Report (CSV)",
            data=csv_data,
            file_name="final_detection_report.csv",
            mime="text/csv"
        )
    else:
        st.warning("Final report is not available.")

st.divider()
st.caption(
    "This prototype analyses offline synthetic network traffic. "
    "It does not perform live network monitoring."
)