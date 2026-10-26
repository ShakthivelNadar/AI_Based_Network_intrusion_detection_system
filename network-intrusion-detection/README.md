# AI-Based Network Intrusion Detection & Security Monitoring System

A student-friendly, offline-first SOC-style GUI for analyzing network-flow CSV datasets with machine learning and tracking generated incidents locally.

## Features

- Streamlit dark SOC dashboard
- CSV upload and preview
- Label-aware supervised classification: Random Forest, Decision Tree, Logistic Regression
- Unsupervised Isolation Forest anomaly mode
- Basic metrics: accuracy, weighted precision/recall/F1, class list
- Prediction sample and tree-based feature importance
- Alert generation with ID, timestamp, severity, confidence score, source/destination IP when present
- Incident status and analyst notes
- Local SQLite persistence and CSV export
- Runs locally at `127.0.0.1`; no cloud upload required by this application

## Kali Linux installation

```bash
sudo apt update
sudo apt install -y git
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd network-intrusion-detection
chmod +x install.sh
./install.sh
```

After installation:

```bash
network-intrusion-detection
```

Open `http://127.0.0.1:8501` if the browser does not open automatically. Stop the app with `Ctrl+C` in its terminal.

### If the command is not found

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
network-intrusion-detection
```

## Dataset setup

Download datasets only from their official project pages or the dataset provider. Extract the CSV files, then use **Analyze Dataset → Network traffic CSV** to upload one.

- CIC-IDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
- CSE-CIC-IDS2018: https://www.unb.ca/cic/datasets/ids-2018.html
- UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset

Datasets can be large. In a Kali VM, begin with a smaller CSV sample and allocate sufficient RAM. The app caps analysis at 150,000 sampled rows for responsiveness.

## What the models mean

- **Random Forest / Decision Tree / Logistic Regression**: supervised models trained from the label column selected by the analyst. Their metrics are measured on an internal holdout split.
- **Isolation Forest**: unsupervised anomaly detection. It does not know attack names and cannot produce supervised accuracy without labeled test data.
- A prediction confidence score is the model's probability for its predicted class when available. It is not a calibrated probability that a real-world intrusion occurred.

## Security and research limitations

- This project analyzes offline CSV records; it does not capture live packets or block traffic.
- CSV schemas differ among CIC-IDS2017, CSE-CIC-IDS2018 and UNSW-NB15. Inspect column names and select the appropriate label column.
- This is a teaching prototype, not a production SIEM/IDS. Validate models on a separate capture, monitor false positives, and do not report high accuracy as a guarantee of security.
- Only analyze traffic that you own or are explicitly authorized to inspect.
- Never expose the Streamlit port publicly. The launcher binds to localhost (`127.0.0.1`).

## Project structure

```text
network-intrusion-detection/
├── app.py
├── nid/
│   ├── engine.py
│   └── storage.py
├── requirements.txt
├── install.sh
├── uninstall.sh
└── README.md
```

## Suggested report chapters

1. Problem statement and objectives
2. Dataset description and license
3. Data cleaning and exploratory analysis
4. Model design and split strategy
5. Evaluation metrics and false-positive analysis
6. Alert generation and incident workflow
7. Dashboard screenshots
8. Limitations, ethical scope, and future improvements
