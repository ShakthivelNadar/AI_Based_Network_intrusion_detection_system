# 🛡️ AI-Based Network Intrusion Detection & Security Monitoring System (NIDS)

A real-time, modular **Network Intrusion Detection System (NIDS)** built with Python. It captures live network traffic at the packet level, classifies potential threats using machine learning and heuristic analysis, and visualizes security telemetry on a Security Operations Center (SOC) dashboard.

---

## 🏗️ System Architecture

The application decouples packet ingestion from dashboard visualization using a non-blocking JSON logging bridge (`logs/alerts.json`), ensuring high-throughput packet capture without UI lag:

```text
[ Network Interface ] ──► [ Live Packet Sniffer ] ──► [ Threat Classifier ] ──► [ SOC Dashboard ]
  (eth0 / wlan0)            (gui/main_gui.py &         (core/threat_classifier.py)   (app.py - Streamlit)
                             core/live_sniffer.py)      └─► logs/alerts.json
