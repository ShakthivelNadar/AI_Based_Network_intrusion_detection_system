from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from nid.engine import load_csv, normalize_columns, train_and_predict, make_alerts, evaluate_model, export_alerts
from nid.storage import init_db, save_alerts, update_alert, read_alerts, add_audit

st.set_page_config(page_title="NID | SOC Console", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
.stApp {background:#0b1018;color:#e6edf3}
[data-testid="stSidebar"] {background:#101722}
div[data-testid="stMetric"] {background:#151e2b;border:1px solid #29384a;padding:14px;border-radius:10px}
div[data-testid="stMetricValue"] {color:#dbeafe}
h1,h2,h3 {letter-spacing:.2px}
.small-muted {color:#9aa9bb}
</style>
""", unsafe_allow_html=True)
init_db()

st.sidebar.markdown("## 🛡️ NID SOC Console")
st.sidebar.caption("AI-Based Network Intrusion Detection")
page = st.sidebar.radio("Workspace", ["Overview", "Analyze Dataset", "Alerts & Incidents", "Model Evaluation", "About & Safety"])
st.sidebar.markdown("---")
st.sidebar.caption("Offline-first • Analyst-controlled • CSV-based")

def get_upload():
    return st.session_state.get("uploaded_df")

if page == "Overview":
    st.title("Network Security Operations Center")
    st.caption("Network traffic analytics, machine-learning triage, and incident review.")
    alerts = read_alerts()
    total = len(alerts)
    high = int(alerts["severity"].isin(["High","Critical"]).sum()) if total else 0
    critical = int((alerts["severity"] == "Critical").sum()) if total else 0
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Alerts", f"{total:,}")
    c2.metric("High / Critical", f"{high:,}")
    c3.metric("Critical", f"{critical:,}")
    c4.metric("Datasets analyzed", st.session_state.get("analysis_count",0))
    left,right = st.columns([1.15,1])
    with left:
        st.subheader("Recent alerts")
        if total:
            st.dataframe(alerts.sort_values("created_at", ascending=False).head(10), use_container_width=True, hide_index=True)
        else:
            st.info("No alerts yet. Open **Analyze Dataset** and upload a labeled network-flow CSV.")
    with right:
        st.subheader("Alert severity")
        if total:
            counts = alerts["severity"].value_counts().rename_axis("Severity").reset_index(name="Count")
            st.plotly_chart(px.pie(counts, names="Severity", values="Count", hole=.58, template="plotly_dark"), use_container_width=True)
        else:
            st.write("Severity distribution will appear after a dataset is analyzed.")
    st.subheader("Workflow")
    st.markdown("**1.** Upload a CSV → **2.** Map the label column → **3.** Train/evaluate a model → **4.** Review generated alerts → **5.** Export an incident report.")
    st.warning("This is a decision-support prototype. Predictions are not proof of compromise; validate alerts before taking action.")

elif page == "Analyze Dataset":
    st.title("Analyze Network Traffic")
    st.write("Upload a CSV exported from CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, or a compatible flow exporter.")
    uploaded = st.file_uploader("Network traffic CSV", type=["csv"])
    if uploaded:
        try:
            df = load_csv(uploaded)
            st.session_state["uploaded_df"] = df
            st.session_state["uploaded_name"] = uploaded.name
        except Exception as e:
            st.error(f"Could not read CSV: {e}")
    df = get_upload()
    if df is not None:
        st.success(f"Loaded {len(df):,} rows × {len(df.columns)} columns from {st.session_state.get('uploaded_name','CSV')}")
        st.dataframe(df.head(12), use_container_width=True)
        norm = normalize_columns(df)
        label_guess = norm.attrs.get("label_column")
        choices = ["(Unlabeled / anomaly mode)"] + list(df.columns)
        default_idx = choices.index(label_guess) if label_guess in choices else (choices.index(label_guess) if label_guess in df.columns else 0)
        label_col = st.selectbox("Label column (normal/attack category)", choices, index=default_idx)
        model_name = st.selectbox("Detection model", ["Random Forest", "Decision Tree", "Logistic Regression", "Isolation Forest (anomaly detection)"])
        threshold = st.slider("Alert sensitivity (score threshold)", 0.30, 0.95, 0.70, 0.05)
        if st.button("Run analysis", type="primary", use_container_width=True):
            with st.spinner("Preparing data and running detection..."):
                try:
                    result = train_and_predict(df, None if label_col.startswith("(") else label_col, model_name, threshold)
                    st.session_state["last_result"] = result
                    st.session_state["analysis_count"] = st.session_state.get("analysis_count",0)+1
                    alerts = make_alerts(result, source=st.session_state.get("uploaded_name","uploaded.csv"))
                    save_alerts(alerts)
                    add_audit("analysis", f"{st.session_state.get('uploaded_name','CSV')} | model={model_name} | rows={len(df)}")
                    st.session_state["last_alerts"] = alerts
                    st.success("Analysis completed.")
                except Exception as e:
                    st.error(f"Analysis could not complete: {e}")
                    st.exception(e)
        result = st.session_state.get("last_result")
        if result is not None:
            st.subheader("Detection summary")
            a,b,c,d = st.columns(4)
            a.metric("Rows analyzed", f"{result['rows']:,}")
            b.metric("Flagged", f"{result['flagged']:,}")
            c.metric("Flag rate", f"{result['flag_rate']:.1%}")
            d.metric("Mode", result["mode"])
            if result.get("metrics"):
                st.json(result["metrics"])
            st.subheader("Predictions (sample)")
            st.dataframe(result["preview"], use_container_width=True, hide_index=True)
            if result.get("feature_importance") is not None and len(result["feature_importance"]):
                st.subheader("Most influential features")
                st.plotly_chart(px.bar(result["feature_importance"].head(15), x="importance", y="feature", orientation="h", template="plotly_dark"), use_container_width=True)
            if st.session_state.get("last_alerts") is not None:
                st.download_button("Download this run's alerts (CSV)", export_alerts(st.session_state["last_alerts"]), "nid_alerts.csv", "text/csv")

elif page == "Alerts & Incidents":
    st.title("Alerts & Incident Queue")
    alerts = read_alerts()
    if alerts.empty:
        st.info("No saved alerts yet. Analyze a dataset first.")
    else:
        f1,f2,f3 = st.columns(3)
        sev = f1.multiselect("Severity", ["Critical","High","Medium","Low"], default=["Critical","High","Medium","Low"])
        status = f2.multiselect("Status", ["New","Investigating","Resolved"], default=["New","Investigating","Resolved"])
        search = f3.text_input("Search category / source")
        view = alerts[alerts["severity"].isin(sev) & alerts["status"].isin(status)]
        if search:
            view = view[view.astype(str).apply(lambda col: col.str.contains(search, case=False, na=False)).any(axis=1)]
        st.dataframe(view, use_container_width=True, hide_index=True)
        st.download_button("Export filtered alerts", export_alerts(view), "nid_incidents.csv", "text/csv")
        st.subheader("Update incident")
        selected = st.selectbox("Alert ID", view["alert_id"].tolist() if len(view) else alerts["alert_id"].tolist())
        current = alerts[alerts["alert_id"] == selected].iloc[0]
        new_status = st.selectbox("Status", ["New","Investigating","Resolved"], index=["New","Investigating","Resolved"].index(current["status"]))
        notes = st.text_area("Analyst notes", value=str(current.get("analyst_notes","")))
        if st.button("Save incident update"):
            update_alert(selected, new_status, notes)
            add_audit("incident_update", f"{selected} -> {new_status}")
            st.success("Incident updated. Refresh the page to see the latest table.")
    st.caption("Alerts are stored locally in SQLite at ~/.local/share/network-intrusion-detection/nid.db.")

elif page == "Model Evaluation":
    st.title("Model Evaluation & Validation")
    result = st.session_state.get("last_result")
    if not result:
        st.info("Run an analysis first to populate evaluation metrics.")
    else:
        if result.get("metrics"):
            st.json(result["metrics"])
            st.markdown("Use **precision**, **recall**, **F1-score**, and the **confusion matrix** together. Accuracy alone can be misleading when attack classes are rare.")
        else:
            st.info("Unlabeled anomaly mode does not calculate supervised accuracy. Use a labeled holdout set to measure false positives and recall.")
        st.markdown("""
**Validation checklist**
- Split train/test data before fitting preprocessing or feature selection.
- Keep near-duplicate flows and repeated captures from leaking across splits.
- Report per-class precision/recall/F1 and confusion matrix.
- Measure false-positive rate on normal traffic.
- Test on a separate capture or dataset before drawing conclusions.
""")
elif page == "About & Safety":
    st.title("About this project")
    st.markdown("""
**AI-Based Network Intrusion Detection & Security Monitoring System**

- **Language:** Python
- **GUI:** Streamlit
- **Analysis:** Pandas, NumPy, scikit-learn, Plotly
- **Persistence:** local SQLite incident store
- **Inputs:** offline CSV flow records
- **Models:** Logistic Regression, Decision Tree, Random Forest, Isolation Forest

### Scope and limitations
This project analyzes records supplied by the analyst. It does not silently sniff traffic, block hosts, alter firewall rules, or guarantee that a prediction is a real attack. CIC/UNSW datasets use different feature schemas; performance must be measured on the chosen dataset and must not be presented as universal.

### Safe deployment
Only analyze traffic you own or are authorized to inspect. For live collection, configure Zeek or Suricata explicitly and review privacy, retention, and authorization requirements before importing logs.
""")
