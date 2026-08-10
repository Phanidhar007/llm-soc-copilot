"""SQLite alert store + synthetic SOC alert generator.

The store persists every alert, its AI triage result and the human-in-the-loop
action log. Because real SOC alert corpora are not bundled (and downloading one
would violate the offline compute budget), the pipeline synthesizes a realistic
alert stream: each alert is templated from one of the 20 MITRE ATT&CK
techniques in ``knowledge.TECHNIQUES`` so retrieval and classification can be
measured against a known ground truth.

Schema notes
------------
* ``alerts``      - one row per alert: evidence, ground-truth technique,
                    analyst verdict, AI triage result, simulated times.
* ``human_actions`` - one row per analyst decision (approve / edit / reject).
"""

from __future__ import annotations

import datetime as _dt
import sqlite3
from typing import Dict, List, Optional, Sequence

import numpy as np
import pandas as pd

from .knowledge import TECHNIQUES, get_technique, severity_name

TECHNIQUE_IDS = [t["id"] for t in TECHNIQUES]

# Weights bias the synthetic stream toward the most frequently-seen techniques.
_TECH_WEIGHTS = {
    "T1059": 6, "T1566": 5, "T1071": 4, "T1027": 4, "T1136": 2, "T1548": 3,
    "T1041": 2, "T1210": 2, "T1486": 3, "T1005": 3, "T1567": 2, "T1083": 3,
    "T1021": 4, "T1572": 2, "T1003": 3, "T1110": 4, "T1098": 2, "T1557": 1,
    "T1622": 1, "T1614": 1,
}

_DECOYS = [  # benign wrappers used to synthesize false-positive alerts
    "approved change window", "scheduled maintenance job", "legitimate admin task",
    "compliance scan", "vendor patching window", "signed enterprise tool",
]

SEVERITY_NAMES = ["low", "medium", "high", "critical"]


def _random_ips(rng: np.random.Generator) -> "tuple[str, str]":
    def _oct() -> str:
        return str(rng.integers(1, 255))
    src = f"{_oct()}.{_oct()}.{_oct()}.{_oct()}"
    dst = f"{_oct()}.{_oct()}.{_oct()}.{_oct()}"
    return src, dst


def generate_alerts(n: int = 300, seed: int = 7, decoy_rate: float = 0.15) -> pd.DataFrame:
    """Generate ``n`` synthetic alerts with known ground truth.

    Fields: id, ts, src_ip, dst_ip, sig_id, severity (0-3), raw_log,
    technique_ground_truth, is_decoy, true_label, analyst_verdict, baseline_time.

    The analyst verdict is a simulated human label: it replicates the true label
    with a small error probability so "triage accuracy vs human labels" is a
    meaningful (imperfect) target.
    """
    rng = np.random.default_rng(seed)
    tech_ids = [t for t in TECHNIQUE_IDS]
    tech_weights = [_TECH_WEIGHTS.get(t, 1) for t in TECHNIQUE_IDS]
    rows: List[dict] = []
    base_time = _dt.datetime(2026, 1, 1, 0, 0, 0)

    for i in range(n):
        tech_id = rng.choice(tech_ids, p=np.asarray(tech_weights) / sum(tech_weights))
        tech = get_technique(tech_id)
        kws = [k for k in tech.keywords]
        kw_a = kws[int(rng.integers(0, len(kws)))]
        kw_b = kws[int(rng.integers(0, len(kws)))]
        sig = tech.signature

        is_decoy = bool(rng.random() < decoy_rate)
        if is_decoy:
            wrapper = _DECOYS[int(rng.integers(0, len(_DECOYS)))]
            raw_log = (f"{sig}: benign {kw_a} / {kw_b} activity during "
                       f"{wrapper}; src user 'svc-corp-monitor' matched allowlist; "
                       f"no IOC overlap")
            true_label = "benign"
        else:
            raw_log = (f"{sig}: {kw_a} / {kw_b} evidence observed on endpoint; "
                       f"indicator overlap with intel feed; unusual process ancestry; "
                       f"no allowlist match")
            true_label = tech.label

        # alert severity: base severity of the technique +/- one notch; decoys stay low
        sev = int(np.clip(tech.base_severity + rng.choice([-1, 0, 0, 1]), 0, 3))
        if is_decoy:
            sev = int(min(sev, 1))

        analyst = true_label
        if rng.random() < 0.05:
            analyst = rng.choice(["benign", "suspicious", "malicious"])

        src_ip, dst_ip = _random_ips(rng)
        ts = base_time + _dt.timedelta(minutes=int(rng.integers(0, 60 * 24 * 14)))

        rows.append({
            "id": f"A{i:04d}",
            "ts": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "sig_id": sig,
            "severity": int(sev),
            "raw_log": raw_log,
            "technique_ground_truth": tech_id,
            "is_decoy": int(is_decoy),
            "true_label": true_label,
            "analyst_verdict": analyst,
            # simulated baseline triage time in minutes (no copilot)
            "baseline_time": round(float(np.clip(rng.normal(12.0, 4.0), 4, 30)), 2),
        })

    return pd.DataFrame(rows)


class AlertStore:
    """Thin SQLite-backed store for alerts and human-in-the-loop actions."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                ts TEXT, src_ip TEXT, dst_ip TEXT, sig_id TEXT,
                severity INTEGER, raw_log TEXT,
                technique_ground_truth TEXT,
                is_decoy INTEGER, true_label TEXT, analyst_verdict TEXT,
                baseline_time REAL,
                ai_label TEXT, ai_conf REAL, ai_technique TEXT,
                ai_technique_conf REAL, summary TEXT,
                severity_justification TEXT, recommended_steps TEXT,
                action TEXT, assisted_time REAL, is_test INTEGER
            );
            CREATE TABLE IF NOT EXISTS human_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                action TEXT NOT NULL,
                analyst_time_min REAL,
                edited_summary TEXT,
                logged_at TEXT
            );
            """
        )
        self._conn.commit()

    def save_alerts(self, alerts: pd.DataFrame) -> None:
        alerts.to_sql("alerts", self._conn, if_exists="replace", index=False)

    def reset(self) -> None:
        """Drop and recreate all tables (fresh run — clears stale actions)."""
        self._conn.executescript(
            "DROP TABLE IF EXISTS alerts; DROP TABLE IF EXISTS human_actions;"
        )
        self._create_tables()

    def upsert_alert(self, alert: pd.Series) -> None:
        cols = alert.index.tolist()
        placeholders = ",".join(["?"] * len(cols))
        cols_sql = ",".join(cols)
        self._conn.execute(
            f"INSERT OR REPLACE INTO alerts ({cols_sql}) VALUES ({placeholders})",
            [None if pd.isna(alert[c]) else alert[c] for c in cols],
        )
        self._conn.commit()

    def get_alerts(self) -> pd.DataFrame:
        return pd.read_sql_query("SELECT * FROM alerts", self._conn)

    def get_alert(self, alert_id: str) -> Optional[pd.Series]:
        row = self._conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return None if row is None else pd.Series(dict(row))

    def log_action(self, alert_id: str, action: str, analyst_time_min: float,
                   edited_summary: Optional[str] = None) -> None:
        self._conn.execute(
            "INSERT INTO human_actions (alert_id, action, analyst_time_min,"
            " edited_summary, logged_at) VALUES (?, ?, ?, ?, ?)",
            (alert_id, action, analyst_time_min, edited_summary,
             _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
        self._conn.commit()

    def get_actions(self) -> pd.DataFrame:
        return pd.read_sql_query(
            "SELECT * FROM human_actions ORDER BY id", self._conn
        )

    def past_alert_logs(self, exclude_id: Optional[str] = None) -> pd.DataFrame:
        """Raw-log corpus of already-ingested alerts (for similarity retrieval)."""
        if exclude_id is None:
            return pd.read_sql_query(
                "SELECT id, raw_log, analyst_verdict FROM alerts", self._conn
            )
        return pd.read_sql_query(
            "SELECT id, raw_log, analyst_verdict FROM alerts WHERE id != ?",
            self._conn,
            params=(exclude_id,),
        )

    def close(self) -> None:
        self._conn.close()


def severity_bucket(level: int) -> str:
    return severity_name(int(level))
