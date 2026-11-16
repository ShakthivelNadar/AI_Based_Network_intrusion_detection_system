# 🛡️ AI-Based Network Intrusion Detection & Security Monitoring System (NIDS)

A real-time, modular **Network Intrusion Detection System (NIDS)** built with Python. It captures live network traffic at the packet level, classifies potential threats using machine learning and heuristic analysis, and visualizes security telemetry on a Security Operations Center (SOC) dashboard.

---

## 🏗️ System Architecture

The application decouples packet ingestion from dashboard visualization using a non-blocking JSON logging bridge (`logs/alerts.json`), ensuring high-throughput packet capture without UI lag:

```text
[ Network Interface ] ──► [ Live Packet Sniffer ] ──► [ Threat Classifier ] ──► [ SOC Dashboard ]
  (eth0 / wlan0)            (gui/main_gui.py &         (core/threat_classifier.py)   (app.py - Streamlit)
                             core/live_sniffer.py)      └─► logs/alerts.json

For Linux
1. Clone the Repository
git clone [https://github.com/](https://github.com/)<your-username>/<your-repo-name>.git
cd <your-repo-name>

2. Create & Activate a Virtual Environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

3. Install All Required Dependencies
pip install scapy scikit-learn pandas numpy streamlit plotly reportlab psutil

Usage
Terminal 1: Launch the SOC Web Dashboard
source venv/bin/activate
streamlit run app.py
Access the dashboard in your browser at http://localhost:8501

Terminal 2: Launch the Packet Capture GUI
Root/Administrator privileges are required for raw socket sniffing
# Linux / Kali
sudo PYTHONPATH=. venv/bin/python3 gui/main_gui.py

⚠️ Disclaimer
This tool is developed for educational, academic, and authorized network security monitoring purposes only. Ensure you have explicit permission before capturing traffic on any network.
