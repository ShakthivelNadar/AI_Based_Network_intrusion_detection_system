import io, re, uuid
from datetime import datetime, timezone
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix, classification_report
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression

LABEL_NAMES = {"label","class","attack","attack_cat","category","target","is_attack"," Label"}
def load_csv(file):
    # Low-memory off to avoid mixed-type inference warnings on common security datasets.
    return pd.read_csv(file, low_memory=False)

def normalize_columns(df):
    out = df.copy()
    out.columns = [re.sub(r"\s+", "_", str(c).strip().lower().replace("/", "_")) for c in out.columns]
    label = next((c for c in out.columns if c.strip().lower() in LABEL_NAMES or c.strip().lower().replace("_","") in {"attackcat","isattack"}), None)
    out.attrs["label_column"] = label
    return out

def _clean(df):
    x = normalize_columns(df)
    x = x.replace([np.inf, -np.inf], np.nan)
    x = x.loc[:, ~x.columns.duplicated()]
    return x

def _severity(label, score):
    s = str(label).lower()
    if any(k in s for k in ["dos","ddos","botnet","infiltration","ransom","exploit","critical"]): return "Critical"
    if any(k in s for k in ["brute","scan","port","web attack","sql","xss","malware","attack"]): return "High"
    if score >= .9: return "High"
    if score >= .7: return "Medium"
    return "Low"

def train_and_predict(raw_df, label_col, model_name, threshold=0.70):
    df = _clean(raw_df)
    if label_col is not None:
        # map user-selected original label name to normalized column
        label_norm = re.sub(r"\s+", "_", str(label_col).strip().lower().replace("/", "_"))
        if label_norm not in df.columns:
            label_norm = next((c for c in df.columns if c.lower() == str(label_col).strip().lower()), None)
        if label_norm is None:
            raise ValueError("Selected label column was not found after column normalization.")
        y_raw = df[label_norm].astype(str).str.strip().replace({"nan":"Unknown","":"Unknown"})
        X = df.drop(columns=[label_norm])
    else:
        y_raw = None
        X = df.copy()
    # Avoid obvious identifiers and high-cardinality address-like columns that can dominate a toy model.
    drop_cols = [c for c in X.columns if c.lower() in {"flow_id","id","row_id","unnamed:_0"}]
    X = X.drop(columns=drop_cols, errors="ignore")
    if X.empty:
        raise ValueError("No usable feature columns remain.")
    # Drop completely empty columns and columns with only one value.
    X = X.dropna(axis=1, how="all")
    X = X.loc[:, X.nunique(dropna=False) > 1]
    if X.empty:
        raise ValueError("No varying feature columns remain after cleaning.")
    # Keep model bounded for very large datasets on a student VM.
    cap = 150000
    if len(X) > cap:
        idx = np.random.default_rng(42).choice(len(X), cap, replace=False)
        X = X.iloc[idx].reset_index(drop=True)
        if y_raw is not None: y_raw = y_raw.iloc[idx].reset_index(drop=True)
    categorical = X.select_dtypes(include=["object","category","bool"]).columns.tolist()
    numeric = [c for c in X.columns if c not in categorical]
    transformers = []
    if numeric:
        transformers.append(("num", Pipeline([("imputer", SimpleImputer(strategy="median")), ("scale", StandardScaler())]), numeric))
    if categorical:
        transformers.append(("cat", Pipeline([("imputer", SimpleImputer(strategy="most_frequent")), ("onehot", OneHotEncoder(handle_unknown="ignore", max_categories=30))]), categorical))
    prep = ColumnTransformer(transformers, remainder="drop")
    if y_raw is None or "Isolation Forest" in model_name:
        model = IsolationForest(n_estimators=150, contamination="auto", random_state=42, n_jobs=-1)
        pipe = Pipeline([("prep", prep), ("model", model)])
        pipe.fit(X)
        pred = pipe.predict(X)
        anomaly = pred == -1
        scores = -pipe.named_steps["model"].score_samples(pipe.named_steps["prep"].transform(X))
        score_norm = (scores - scores.min()) / (scores.max() - scores.min() + 1e-9)
        flagged = anomaly | (score_norm >= threshold)
        labels = np.where(flagged, "Anomaly", "Normal")
        preview = X.head(100).copy()
        preview["prediction"] = labels[:len(preview)]
        preview["anomaly_score"] = score_norm[:len(preview)].round(4)
        return {"rows":len(X), "flagged":int(flagged.sum()), "flag_rate":float(flagged.mean()), "mode":"Unsupervised anomaly detection", "metrics":None, "preview":preview, "predictions":labels, "scores":score_norm, "features":X, "feature_importance":None}
    # Supervised classification with stratified holdout where feasible.
    y = y_raw.fillna("Unknown").astype(str)
    # Convert labels with two categories to Normal/Attack for clear binary workflow.
    unique = y.unique()
    if len(unique) < 2:
        raise ValueError("The selected label column contains only one class; select a labeled dataset.")
    if len(unique) > 60:
        raise ValueError(f"Found {len(unique)} distinct labels. Select a suitable attack-label column or clean labels first.")
    model_map = {
        "Random Forest": RandomForestClassifier(n_estimators=160, class_weight="balanced", random_state=42, n_jobs=-1, min_samples_leaf=2),
        "Decision Tree": DecisionTreeClassifier(class_weight="balanced", random_state=42, max_depth=18),
        "Logistic Regression": LogisticRegression(max_iter=700, class_weight="balanced", solver="lbfgs")
    }
    model = model_map[model_name]
    # Avoid stratify when any class has fewer than 2 records.
    strat = y if y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=strat)
    pipe = Pipeline([("prep", prep), ("model", model)])
    pipe.fit(X_train, y_train)
    pred_test = pipe.predict(X_test)
    pred_all = pipe.predict(X)
    try:
        prob = pipe.predict_proba(X)
        classes = list(pipe.named_steps["model"].classes_)
        # confidence of predicted class, not calibrated probability
        scores = np.array([prob[i, classes.index(pred_all[i])] for i in range(len(pred_all))])
    except Exception:
        scores = np.ones(len(pred_all)) * 0.75
    normal_words = {"benign","normal","0","false","no","normal traffic"}
    flagged = np.array([str(v).strip().lower() not in normal_words for v in pred_all])
    metrics = {
        "accuracy": round(float(accuracy_score(y_test, pred_test)), 4),
        "weighted_precision": round(float(precision_recall_fscore_support(y_test, pred_test, average="weighted", zero_division=0)[0]), 4),
        "weighted_recall": round(float(precision_recall_fscore_support(y_test, pred_test, average="weighted", zero_division=0)[1]), 4),
        "weighted_f1": round(float(precision_recall_fscore_support(y_test, pred_test, average="weighted", zero_division=0)[2]), 4),
        "test_rows": int(len(X_test)),
        "classes": [str(c) for c in np.unique(y)]
    }
    preview = X.head(100).copy()
    preview["actual_label"] = y.head(len(preview)).values
    preview["prediction"] = pred_all[:len(preview)]
    preview["confidence"] = scores[:len(preview)].round(4)
    importance = None
    fitted = pipe.named_steps["model"]
    if hasattr(fitted, "feature_importances_"):
        try:
            names = pipe.named_steps["prep"].get_feature_names_out()
            importance = pd.DataFrame({"feature":names, "importance":fitted.feature_importances_}).sort_values("importance", ascending=False)
        except Exception:
            pass
    return {"rows":len(X), "flagged":int(flagged.sum()), "flag_rate":float(flagged.mean()), "mode":"Supervised classification", "metrics":metrics, "preview":preview, "predictions":pred_all, "scores":scores, "features":X, "feature_importance":importance}

def make_alerts(result, source="uploaded.csv"):
    features = result["features"]
    preds = result["predictions"]
    scores = result["scores"]
    alerts = []
    # Generate alert for each predicted non-normal row, cap to prevent oversized alert DB.
    normal_words = {"benign","normal","0","false","no","normal traffic"}
    idxs = [i for i,p in enumerate(preds) if str(p).strip().lower() not in normal_words]
    idxs = idxs[:5000]
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for i in idxs:
        label = str(preds[i])
        score = float(scores[i]) if i < len(scores) else 0.75
        row = features.iloc[i]
        def first(keys):
            for k in keys:
                for c in row.index:
                    if k in c.lower() and pd.notna(row[c]): return str(row[c])[:100]
            return ""
        alerts.append({
            "alert_id":"ALT-"+uuid.uuid4().hex[:8].upper(),
            "created_at":now,
            "timestamp":first(["timestamp","flow_start","time"]) or now,
            "category":label,
            "severity":_severity(label,score),
            "confidence":round(score,4),
            "source_ip":first(["src_ip","source_ip","srcaddr","source"]),
            "destination_ip":first(["dst_ip","destination_ip","dstaddr","destination"]),
            "source_file":source,
            "status":"New",
            "analyst_notes":""
        })
    return pd.DataFrame(alerts, columns=["alert_id","created_at","timestamp","category","severity","confidence","source_ip","destination_ip","source_file","status","analyst_notes"])

def export_alerts(df):
    return df.to_csv(index=False).encode("utf-8")
