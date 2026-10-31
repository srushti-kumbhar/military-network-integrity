\# Military Network Integrity

\## Automated Packet Sniffer and Intrusion Detection System



A defensive cybersecurity college project that analyses authorized network traffic using packet analysis, rule-based intrusion detection, and machine-learning anomaly detection.



\## 1. Project Overview



Military Network Integrity is an educational prototype designed to demonstrate how network traffic can be analysed to identify suspicious activities.



The system uses offline synthetic network traffic to demonstrate intrusion detection techniques.



\## 2. Key Features



\- Offline packet capture (PCAP) analysis using Scapy.

\- Packet metadata extraction.

\- Network traffic feature extraction.

\- Rule-based intrusion detection.

\- Isolation Forest machine-learning anomaly detection.

\- Combined threat analysis.

\- Interactive Streamlit dashboard.

\- CSV report generation and downloading.



\## 3. Technologies Used



\- Python

\- Scapy

\- Pandas

\- NumPy

\- Scikit-learn

\- Matplotlib

\- Streamlit



\## 4. Project Structure



military-network-integrity/

│

├── data/

│   └── processed/

├── pcaps/

│   └── sample/

├── models/

├── notebooks/

├── src/

│   ├── packet\_parser.py

│   ├── feature\_extractor.py

│   ├── anomaly\_detector.py

│   ├── rule\_detector.py

│   └── evaluation.py

│

├── app.py

├── generate\_pcap.py

├── requirements.txt

└── README.md



\## 5. Detection Techniques



\### Rule-Based Detection



Identifies suspicious patterns using predefined conditions:



\- Port scan-like activity.

\- Repeated TCP connection attempts.

\- Unusually high packet rates.

\- High traffic volume.



\### Machine Learning Detection



Uses the Isolation Forest algorithm to identify unusual network traffic patterns.



The model produces:

\- Normal traffic classification.

\- Anomaly classification.

\- Anomaly scores.



\### Combined Detection



Combines rule-based alerts and machine-learning results to produce an overall risk classification.



\## 6. Installation



Clone the repository:



git clone YOUR\_GITHUB\_REPOSITORY\_URL



Navigate into the project:



cd military-network-integrity



Create a virtual environment:



python -m venv venv



Activate it on Windows:



venv\\Scripts\\activate



Install dependencies:



python -m pip install -r requirements.txt



\## 7. Running the Project



Generate synthetic network traffic:



python generate\_pcap.py



Parse packets:



python src/packet\_parser.py



Extract network features:



python src/feature\_extractor.py



Run rule-based detection:



python src/rule\_detector.py



Run machine-learning detection:



python src/anomaly\_detector.py



Generate the combined report:



python src/evaluation.py



Launch the dashboard:



python -m streamlit run app.py



\## 8. Dashboard



The dashboard contains five sections:



1\. Overview

2\. Packet Analysis

3\. Rule-Based Alerts

4\. ML Detection

5\. Final Report



Users can view traffic statistics, inspect detection results, and download the final CSV report.



\## 9. Safety and Limitations



\- Uses synthetic network traffic for testing.

\- Analyses offline PCAP files.

\- Does not perform unauthorized network access.

\- Does not capture passwords or credentials.

\- Does not currently provide live network monitoring.

\- Machine-learning results are educational demonstrations, not validated real-world detection performance.



\## 10. Future Enhancements



\- Authorized live network monitoring.

\- Larger and more diverse training datasets.

\- Improved anomaly detection.

\- Real-time alert notifications.

\- Advanced traffic visualization.

\- Improved model evaluation.



\## 11. Disclaimer



This project is developed strictly for educational and defensive cybersecurity purposes. Any future live monitoring functionality must be used only on networks for which explicit authorization has been granted.

