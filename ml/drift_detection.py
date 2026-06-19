#!/usr/bin/env python3
"""
Thor ML Model Drift Detection
==============================
Monitors the statistical distribution of ML inference scores over time
to detect when the model has become stale and retraining is needed.

WHAT IS MODEL DRIFT?
  The IsolationForest was trained on a snapshot of normal traffic.
  As the network evolves (new services, changing patterns), normal
  traffic shifts and the model starts producing skewed scores:
  - Score mean shifts away from 0.5 (the expected center)
  - Score variance changes (model becomes overconfident or underconfident)
  - Alert rate changes significantly without a corresponding security event

DETECTION METHOD:
  1. Collect a rolling window of inference scores (default: 7 days)
  2. Compare current week vs. baseline (training week or last stable week)
  3. If mean drift > DRIFT_THRESHOLD or distribution diverges significantly → alert
  4. Use Jensen-Shannon Divergence (JSD) for distribution comparison (symmetric KL-divergence)

USAGE:
  # Run weekly (add to cron or CI):
  python3 ml/drift_detection.py --scores-db /var/lib/thor/ml_scores.db

  # Check drift right now:
  python3 ml/drift_detection.py --mode check --scores-db /var/lib/thor/ml_scores.db

  # Record a score (called by Thor Rust agent via Python subprocess or API):
  python3 ml/drift_detection.py --mode record --score 0.52

ENVIRONMENT:
  THOR_DRIFT_THRESHOLD     — Mean drift threshold (default: 0.05)
  THOR_DRIFT_JSD_MAX       — Max Jensen-Shannon Divergence (default: 0.10)
  THOR_DRIFT_ALERT_WEBHOOK — Webhook URL for drift alerts (optional)
  THOR_SCORES_DB           — SQLite path (default: /var/lib/thor/ml_scores.db)
"""

import os
import sys
import json
import math
import sqlite3
import argparse
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [drift-detection] %(message)s"
)
log = logging.getLogger("thor.drift_detection")

# ── Configuration ─────────────────────────────────────────────────────────────

DRIFT_THRESHOLD     = float(os.getenv("THOR_DRIFT_THRESHOLD", "0.05"))
JSD_MAX             = float(os.getenv("THOR_DRIFT_JSD_MAX", "0.10"))
SCORES_DB           = os.getenv("THOR_SCORES_DB", "/var/lib/thor/ml_scores.db")
ALERT_WEBHOOK       = os.getenv("THOR_DRIFT_ALERT_WEBHOOK", "")
WINDOW_DAYS         = 7           # Rolling window in days
BASELINE_DAYS       = 30          # Baseline window in days


# ── Database ──────────────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ml_scores (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            score      REAL NOT NULL,           -- IsolationForest anomaly score
            is_anomaly INTEGER NOT NULL,        -- 1 if score exceeded threshold
            timestamp  TEXT DEFAULT (datetime('now'))
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS drift_reports (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            report_at       TEXT DEFAULT (datetime('now')),
            current_mean    REAL,
            baseline_mean   REAL,
            mean_drift      REAL,
            current_std     REAL,
            baseline_std    REAL,
            jsd             REAL,
            n_current       INTEGER,
            n_baseline      INTEGER,
            alert_rate      REAL,
            drift_detected  INTEGER,
            action          TEXT
        )
    """)
    conn.commit()
    return conn


def record_score(conn: sqlite3.Connection, score: float, is_anomaly: bool):
    """Record a single ML inference score."""
    conn.execute(
        "INSERT INTO ml_scores (score, is_anomaly) VALUES (?,?)",
        (score, int(is_anomaly))
    )
    conn.commit()


def get_scores_window(conn: sqlite3.Connection, days: int) -> np.ndarray:
    """Get scores from the last N days."""
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    rows = conn.execute(
        "SELECT score FROM ml_scores WHERE timestamp >= ? ORDER BY timestamp",
        (cutoff,)
    ).fetchall()
    return np.array([r[0] for r in rows], dtype=np.float32)


def get_alert_rate(conn: sqlite3.Connection, days: int) -> float:
    """Get the fraction of scores that triggered anomaly alerts in the last N days."""
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    rows = conn.execute(
        "SELECT COUNT(*), SUM(is_anomaly) FROM ml_scores WHERE timestamp >= ?",
        (cutoff,)
    ).fetchone()
    total, alerts = rows
    if not total:
        return 0.0
    return float(alerts or 0) / float(total)


# ── Drift Metrics ─────────────────────────────────────────────────────────────

def jensen_shannon_divergence(p: np.ndarray, q: np.ndarray,
                               n_bins: int = 50) -> float:
    """
    Compute Jensen-Shannon Divergence between two score distributions.

    JSD ∈ [0, 1]:
      0.00 = identical distributions
      0.05 = slight drift (monitor)
      0.10 = significant drift → retrain recommended
      0.30 = major drift → urgent retrain
      1.00 = completely different distributions
    """
    # Bin both into the same histogram
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    p_hist, _ = np.histogram(p, bins=bins, density=True)
    q_hist, _ = np.histogram(q, bins=bins, density=True)

    # Normalize to probability distributions
    p_hist = p_hist + 1e-10   # Laplace smoothing
    q_hist = q_hist + 1e-10
    p_hist /= p_hist.sum()
    q_hist /= q_hist.sum()

    # JSD = 0.5 * KL(P || M) + 0.5 * KL(Q || M)  where M = 0.5*(P+Q)
    m = 0.5 * (p_hist + q_hist)
    kl_pm = np.sum(p_hist * np.log(p_hist / m))
    kl_qm = np.sum(q_hist * np.log(q_hist / m))
    return float(0.5 * kl_pm + 0.5 * kl_qm)


def check_drift(conn: sqlite3.Connection) -> dict:
    """
    Check for model drift by comparing current week vs baseline.

    Returns a drift report dictionary.
    """
    current_scores  = get_scores_window(conn, WINDOW_DAYS)
    baseline_scores = get_scores_window(conn, BASELINE_DAYS)

    if len(current_scores) < 100:
        log.warning(f"Insufficient current data: {len(current_scores)} scores (need 100+)")
        return {"drift_detected": False, "reason": "insufficient_data",
                "n_current": len(current_scores)}

    if len(baseline_scores) < 500:
        log.warning(f"Insufficient baseline data: {len(baseline_scores)} scores (need 500+)")
        return {"drift_detected": False, "reason": "insufficient_baseline",
                "n_baseline": len(baseline_scores)}

    current_mean  = float(np.mean(current_scores))
    baseline_mean = float(np.mean(baseline_scores))
    current_std   = float(np.std(current_scores))
    baseline_std  = float(np.std(baseline_scores))
    mean_drift    = abs(current_mean - baseline_mean)
    jsd           = jensen_shannon_divergence(baseline_scores, current_scores)
    alert_rate    = get_alert_rate(conn, WINDOW_DAYS)

    drift_detected = (mean_drift > DRIFT_THRESHOLD) or (jsd > JSD_MAX)

    action = "none"
    if jsd > 0.30 or mean_drift > 0.15:
        action = "urgent_retrain"
    elif drift_detected:
        action = "retrain_recommended"
    elif jsd > 0.05:
        action = "monitor_closely"

    report = {
        "timestamp":       datetime.now().isoformat(),
        "drift_detected":  drift_detected,
        "action":          action,
        "current_mean":    round(current_mean, 4),
        "baseline_mean":   round(baseline_mean, 4),
        "mean_drift":      round(mean_drift, 4),
        "current_std":     round(current_std, 4),
        "baseline_std":    round(baseline_std, 4),
        "jsd":             round(jsd, 4),
        "n_current":       len(current_scores),
        "n_baseline":      len(baseline_scores),
        "alert_rate":      round(alert_rate, 4),
        "thresholds": {
            "mean_drift_max": DRIFT_THRESHOLD,
            "jsd_max":        JSD_MAX,
        },
        "interpretation": _interpret(jsd, mean_drift, alert_rate),
    }

    # Persist
    conn.execute("""
        INSERT INTO drift_reports
        (current_mean, baseline_mean, mean_drift, current_std, baseline_std,
         jsd, n_current, n_baseline, alert_rate, drift_detected, action)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, (current_mean, baseline_mean, mean_drift, current_std, baseline_std,
          jsd, len(current_scores), len(baseline_scores), alert_rate,
          int(drift_detected), action))
    conn.commit()

    return report


def _interpret(jsd: float, mean_drift: float, alert_rate: float) -> str:
    """Human-readable interpretation of drift metrics."""
    msgs = []
    if jsd < 0.05 and mean_drift < 0.03:
        msgs.append("✅ Model is stable — score distribution matches baseline.")
    else:
        if jsd >= 0.30:
            msgs.append(f"🔴 CRITICAL: JSD={jsd:.3f} — major distribution shift, urgent retrain needed.")
        elif jsd >= 0.10:
            msgs.append(f"🟡 WARNING: JSD={jsd:.3f} — significant distribution shift detected.")
        elif jsd >= 0.05:
            msgs.append(f"🟡 NOTICE: JSD={jsd:.3f} — mild distribution shift, monitor closely.")

        if mean_drift >= 0.15:
            msgs.append(f"🔴 Mean drift={mean_drift:.3f} (>{DRIFT_THRESHOLD}) — major score bias shift.")
        elif mean_drift >= DRIFT_THRESHOLD:
            msgs.append(f"🟡 Mean drift={mean_drift:.3f} exceeds threshold {DRIFT_THRESHOLD}.")

    if alert_rate > 0.10:
        msgs.append(f"⚠️  Alert rate={alert_rate:.1%} — unusually high, check for attack campaign or FP spike.")
    elif alert_rate < 0.001:
        msgs.append(f"ℹ️  Alert rate={alert_rate:.1%} — very low, model may be underdetecting.")

    return " ".join(msgs) or "No interpretation available."


def send_drift_alert(report: dict):
    """Send drift alert to configured webhook."""
    if not ALERT_WEBHOOK:
        return
    try:
        import httpx
        payload = {
            "text": f"⚠️ Thor ML Drift Alert — {report['action'].replace('_',' ').title()}",
            "attachments": [{
                "color": "danger" if "urgent" in report["action"] else "warning",
                "fields": [
                    {"title": "JSD",        "value": str(report["jsd"]),        "short": True},
                    {"title": "Mean Drift", "value": str(report["mean_drift"]), "short": True},
                    {"title": "Action",     "value": report["action"],           "short": True},
                    {"title": "Details",    "value": report["interpretation"],   "short": False},
                ]
            }]
        }
        httpx.post(ALERT_WEBHOOK, json=payload, timeout=10)
        log.info("Drift alert sent to webhook")
    except Exception as e:
        log.warning(f"Drift alert webhook failed: {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Thor ML Drift Detection")
    parser.add_argument("--mode", choices=["check", "record", "report"], default="check")
    parser.add_argument("--scores-db", default=SCORES_DB)
    parser.add_argument("--score", type=float, help="Score to record (--mode record)")
    parser.add_argument("--is-anomaly", action="store_true")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    conn = init_db(args.scores_db)

    if args.mode == "record":
        if args.score is None:
            print("Error: --score required for record mode", file=sys.stderr)
            sys.exit(1)
        record_score(conn, args.score, args.is_anomaly)
        print(f"Recorded score={args.score:.4f} anomaly={args.is_anomaly}")

    elif args.mode == "check":
        report = check_drift(conn)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"\n{'='*60}")
            print(f"Thor ML Drift Report — {report.get('timestamp', 'N/A')[:19]}")
            print(f"{'='*60}")
            print(f"  Drift detected:  {report.get('drift_detected', 'N/A')}")
            print(f"  Action:          {report.get('action', 'N/A')}")
            print(f"  JSD:             {report.get('jsd', 'N/A')}")
            print(f"  Mean drift:      {report.get('mean_drift', 'N/A')}")
            print(f"  Alert rate:      {report.get('alert_rate', 'N/A')}")
            print(f"  Interpretation:  {report.get('interpretation', '')}")
            print(f"{'='*60}\n")

        if report.get("drift_detected"):
            send_drift_alert(report)
            sys.exit(2)  # Exit code 2 = drift detected (CI/cron can check this)

    elif args.mode == "report":
        # Print last 10 drift reports
        rows = conn.execute(
            "SELECT report_at, jsd, mean_drift, drift_detected, action FROM drift_reports ORDER BY id DESC LIMIT 10"
        ).fetchall()
        print("\nLast 10 drift reports:")
        print(f"{'Timestamp':<22} {'JSD':>6} {'Drift':>7} {'Alert':>6} {'Action'}")
        print("-" * 65)
        for row in rows:
            print(f"  {row[0]:<20} {row[1]:>6.4f} {row[2]:>7.4f} {str(bool(row[3])):>6}  {row[4]}")


if __name__ == "__main__":
    main()
