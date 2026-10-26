from pathlib import Path
import sqlite3
import pandas as pd
from datetime import datetime, timezone

DB_DIR = Path.home()/".local"/"share"/"network-intrusion-detection"
DB_PATH = DB_DIR/"nid.db"

def conn():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS alerts (
          alert_id TEXT PRIMARY KEY, created_at TEXT, timestamp TEXT, category TEXT,
          severity TEXT, confidence REAL, source_ip TEXT, destination_ip TEXT,
          source_file TEXT, status TEXT, analyst_notes TEXT)""")
        c.execute("""CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, action TEXT, details TEXT)""")

def save_alerts(df):
    if df is None or df.empty: return
    with conn() as c:
        c.executemany("""INSERT OR IGNORE INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            [tuple(row) for row in df[["alert_id","created_at","timestamp","category","severity","confidence","source_ip","destination_ip","source_file","status","analyst_notes"]].itertuples(index=False, name=None)])

def update_alert(alert_id, status, notes):
    with conn() as c:
        c.execute("UPDATE alerts SET status=?, analyst_notes=? WHERE alert_id=?", (status, notes, alert_id))

def read_alerts():
    with conn() as c:
        rows = c.execute("SELECT * FROM alerts ORDER BY created_at DESC").fetchall()
    return pd.DataFrame([dict(r) for r in rows])

def add_audit(action, details):
    with conn() as c:
        c.execute("INSERT INTO audit(created_at, action, details) VALUES (?,?,?)",
                  (datetime.now(timezone.utc).isoformat(timespec="seconds"), action, details))
