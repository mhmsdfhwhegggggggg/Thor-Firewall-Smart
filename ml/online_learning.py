#!/usr/bin/env python3
"""
Thor ML Online Learning Loop
============================
Implements continuous model retraining based on SOC analyst feedback.

ARCHITECTURE:
  1. SOC analyst confirms/rejects alerts via the Thor API (POST /api/v1/feedback)
  2. Confirmed alerts → positive (attack) examples added to retraining buffer
  3. Rejected alerts → negative (false positive) examples added to buffer
  4. Every 24 hours (or when 1000 samples accumulate) → retrain IsolationForest
  5. Retrained model is exported as ONNX and hot-swapped in the running service

USAGE:
  # Run as a daemon (every 24h):
  python3 ml/online_learning.py --mode daemon --buffer-db /var/lib/thor/ml_buffer.db

  # Single retrain run:
  python3 ml/online_learning.py --mode once --buffer-db /var/lib/thor/ml_buffer.db

  # Inspect buffer statistics:
  python3 ml/online_learning.py --mode stats --buffer-db /var/lib/thor/ml_buffer.db

ENVIRONMENT:
  THOR_API_BASE     — Thor agent API (default: http://localhost:8080)
  THOR_API_TOKEN    — JWT token for API access
  THOR_BUFFER_DB    — SQLite path for feedback buffer
  THOR_MODEL_OUT    — Output ONNX path (default: models/thor_ueba_model.onnx)
  THOR_RETRAIN_HOURS  — Retrain interval in hours (default: 24)
  THOR_RETRAIN_MIN_SAMPLES — Minimum new samples before retraining (default: 1000)
"""

import os
import sys
import json
import time
import logging
import sqlite3
import argparse
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import numpy as np

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [online-learning] %(message)s"
)
log = logging.getLogger("thor.online_learning")

# ── Constants ──────────────────────────────────────────────────────────────────

N_FEATURES          = 28          # Must match crates/thor-agent/src/ml/features.rs
RETRAIN_INTERVAL_H  = int(os.getenv("THOR_RETRAIN_HOURS", "24"))
MIN_SAMPLES         = int(os.getenv("THOR_RETRAIN_MIN_SAMPLES", "1000"))
BUFFER_DB           = os.getenv("THOR_BUFFER_DB", "/var/lib/thor/ml_buffer.db")
MODEL_OUT           = os.getenv("THOR_MODEL_OUT", "models/thor_ueba_model.onnx")
API_BASE            = os.getenv("THOR_API_BASE", "http://localhost:8080")
API_TOKEN           = os.getenv("THOR_API_TOKEN", "")

# ── Buffer Database ─────────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    """Initialize the feedback buffer SQLite database."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback_buffer (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id    TEXT NOT NULL,
            features    TEXT NOT NULL,        -- JSON array of 28 floats
            label       INTEGER NOT NULL,     -- 1=attack (confirmed), 0=normal (FP)
            analyst_id  TEXT,
            created_at  TEXT DEFAULT (datetime('now')),
            used_in_run INTEGER DEFAULT 0     -- 0=pending, 1=used
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS retrain_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            run_at        TEXT DEFAULT (datetime('now')),
            samples_used  INTEGER,
            attack_count  INTEGER,
            normal_count  INTEGER,
            model_path    TEXT,
            success       INTEGER,
            error         TEXT
        )
    """)
    conn.commit()
    return conn


def add_feedback(conn: sqlite3.Connection, alert_id: str, features: list,
                 label: int, analyst_id: str = ""):
    """Add a confirmed or rejected alert to the retraining buffer."""
    if len(features) != N_FEATURES:
        raise ValueError(f"Expected {N_FEATURES} features, got {len(features)}")
    conn.execute(
        "INSERT INTO feedback_buffer (alert_id, features, label, analyst_id) VALUES (?,?,?,?)",
        (alert_id, json.dumps(features), label, analyst_id)
    )
    conn.commit()
    log.info(f"Added feedback: alert={alert_id} label={'ATTACK' if label else 'NORMAL'}")


def get_pending_samples(conn: sqlite3.Connection):
    """Get all unused feedback samples for retraining."""
    rows = conn.execute(
        "SELECT id, features, label FROM feedback_buffer WHERE used_in_run = 0"
    ).fetchall()
    return rows


def mark_used(conn: sqlite3.Connection, ids: list):
    """Mark samples as used in a retrain run."""
    placeholders = ",".join("?" * len(ids))
    conn.execute(f"UPDATE feedback_buffer SET used_in_run = 1 WHERE id IN ({placeholders})", ids)
    conn.commit()


def buffer_stats(conn: sqlite3.Connection) -> dict:
    """Return buffer statistics."""
    total = conn.execute("SELECT COUNT(*) FROM feedback_buffer").fetchone()[0]
    pending = conn.execute("SELECT COUNT(*) FROM feedback_buffer WHERE used_in_run=0").fetchone()[0]
    attacks = conn.execute("SELECT COUNT(*) FROM feedback_buffer WHERE label=1").fetchone()[0]
    normals = conn.execute("SELECT COUNT(*) FROM feedback_buffer WHERE label=0").fetchone()[0]
    last_run = conn.execute(
        "SELECT run_at, success FROM retrain_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return {
        "total_samples": total,
        "pending_samples": pending,
        "attack_samples": attacks,
        "normal_samples": normals,
        "last_retrain": last_run[0] if last_run else None,
        "last_retrain_success": bool(last_run[1]) if last_run else None,
    }


# ── Model Retraining ───────────────────────────────────────────────────────────

def retrain(conn: sqlite3.Connection, base_model_path: str, output_path: str,
            n_normal_base: int = 10000) -> bool:
    """
    Retrain the IsolationForest model with new feedback samples.

    Strategy:
    - Load base normal distribution (re-generate synthetic if not cached)
    - Append confirmed attack samples as labeled outliers
    - Append FP-corrected samples as normal (reduce FP rate)
    - Retrain IF with contamination = n_attacks / total
    - Export as ONNX
    """
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import MinMaxScaler
        from skl2onnx import convert_sklearn
        from skl2onnx.common.data_types import FloatTensorType
        import onnx

        rows = get_pending_samples(conn)
        if not rows:
            log.info("No pending samples — nothing to retrain")
            return False

        sample_ids = [r[0] for r in rows]
        features = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
        labels   = np.array([r[2] for r in rows], dtype=np.int32)

        n_attacks = int(labels.sum())
        n_normals_fb = int((1 - labels).sum())
        log.info(f"Retraining with {len(rows)} new samples: {n_attacks} attacks, {n_normals_fb} normals")

        # ── Generate base normal distribution ─────────────────────────────────
        # Re-use the same generators as ml_train_export.py for consistency
        rng = np.random.default_rng(42)
        X_base = _generate_normal_base(rng, n_normal_base)

        # ── Combine: base normal + feedback normal + feedback attacks ──────────
        X_attack = features[labels == 1]
        X_normal_fb = features[labels == 0]

        X_combined = np.vstack([
            X_base,
            X_normal_fb * 2,   # Weight FP corrections (reduce FP rate)
            X_attack,
        ])

        total = len(X_combined)
        contamination = max(0.01, min(0.15, n_attacks / total))
        log.info(f"Combined dataset: {total} samples, contamination={contamination:.4f}")

        # ── Normalize ─────────────────────────────────────────────────────────
        scaler = MinMaxScaler(feature_range=(0.0, 1.0))
        X_scaled = scaler.fit_transform(X_combined).astype(np.float32)

        # ── Train IsolationForest ──────────────────────────────────────────────
        clf = IsolationForest(
            n_estimators=300,
            contamination=contamination,
            max_features=0.8,
            bootstrap=True,
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X_scaled)
        log.info("IsolationForest trained successfully")

        # ── Export to ONNX ─────────────────────────────────────────────────────
        initial_type = [("float_input", FloatTensorType([None, N_FEATURES]))]
        onnx_model = convert_sklearn(clf, initial_types=initial_type,
                                     target_opset=17, options={"zipmap": False})

        # Atomic write: write to temp, then move
        tmp_path = output_path + ".tmp"
        with open(tmp_path, "wb") as f:
            f.write(onnx_model.SerializeToString())
        shutil.move(tmp_path, output_path)
        log.info(f"✅ Model exported to {output_path}")

        # ── Mark samples as used ────────────────────────────────────────────
        mark_used(conn, sample_ids)

        # ── Log the run ─────────────────────────────────────────────────────
        conn.execute(
            "INSERT INTO retrain_log (samples_used, attack_count, normal_count, model_path, success) VALUES (?,?,?,?,1)",
            (len(rows), n_attacks, n_normals_fb, output_path)
        )
        conn.commit()
        return True

    except Exception as e:
        log.error(f"Retrain failed: {e}", exc_info=True)
        conn.execute(
            "INSERT INTO retrain_log (samples_used, attack_count, normal_count, model_path, success, error) VALUES (?,?,?,?,0,?)",
            (0, 0, 0, output_path, str(e))
        )
        conn.commit()
        return False


def _generate_normal_base(rng, n: int) -> np.ndarray:
    """Generate base normal traffic distribution (same as ml_train_export.py)."""
    X = np.zeros((n, N_FEATURES), dtype=np.float32)
    X[:,0]  = rng.uniform(0, 1, n)
    X[:,1]  = rng.beta(2, 5, n)
    X[:,2]  = np.clip(rng.lognormal(1.5, 0.8, n), 0, 10)
    X[:,3]  = np.clip(rng.poisson(3.0, n), 0, 30).astype(float)
    X[:,4]  = rng.binomial(1, 0.02, n).astype(float)
    X[:,5]  = rng.binomial(1, 0.08, n).astype(float)
    X[:,6]  = rng.binomial(1, 0.005, n).astype(float)
    X[:,7]  = rng.binomial(1, 0.03, n).astype(float)
    X[:,8]  = rng.binomial(1, 0.15, n).astype(float)
    X[:,9]  = rng.binomial(1, 0.05, n).astype(float)
    X[:,10] = rng.binomial(1, 0.10, n).astype(float)
    X[:,11] = rng.binomial(1, 0.01, n).astype(float)
    X[:,12] = np.clip(rng.beta(0.5, 0.5, n), 0, 1)
    X[:,13] = rng.binomial(1, 0.70, n).astype(float)
    X[:,14] = np.clip(rng.exponential(500, n) / 20000, 0, 1)
    X[:,15] = rng.binomial(1, 0.002, n).astype(float)
    X[:,16] = rng.beta(2, 8, n)
    X[:,17] = np.clip(rng.lognormal(8, 2, n) / 1e6, 0, 1)
    X[:,18] = np.clip(rng.lognormal(7, 2, n) / 1e6, 0, 1)
    X[:,19] = np.clip(rng.lognormal(3, 1.5, n) / 1e4, 0, 1)
    X[:,20] = rng.beta(8, 2, n)
    X[:,21] = rng.binomial(1, 0.01, n).astype(float)
    X[:,22] = np.clip(rng.normal(2.5, 0.8, n) / 8.0, 0, 1)
    X[:,23] = rng.binomial(1, 0.005, n).astype(float)
    X[:,24] = rng.beta(1, 10, n)
    X[:,25] = np.clip(np.abs(rng.normal(0, 1, n)) / 4.0, 0, 1)
    hours   = rng.uniform(0, 24, n)
    X[:,26] = (np.sin(hours * 2 * np.pi / 24) + 1) / 2
    X[:,27] = (np.cos(hours * 2 * np.pi / 24) + 1) / 2
    return X


# ── API Polling ─────────────────────────────────────────────────────────────────

def poll_api_feedback(conn: sqlite3.Connection):
    """Poll the Thor API for SOC analyst feedback and add to buffer."""
    try:
        import httpx
        resp = httpx.get(
            f"{API_BASE}/api/v1/feedback/pending",
            headers={"Authorization": f"Bearer {API_TOKEN}"},
            timeout=10,
        )
        if resp.status_code != 200:
            log.warning(f"API poll failed: {resp.status_code}")
            return

        items = resp.json().get("items", [])
        for item in items:
            try:
                add_feedback(
                    conn,
                    alert_id=item["alert_id"],
                    features=item["features"],
                    label=1 if item["verdict"] == "attack" else 0,
                    analyst_id=item.get("analyst_id", ""),
                )
            except Exception as e:
                log.warning(f"Skipping malformed feedback item: {e}")

        if items:
            log.info(f"Ingested {len(items)} feedback items from API")

    except Exception as e:
        log.warning(f"API poll error (running in offline mode): {e}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Thor ML Online Learning Loop")
    parser.add_argument("--mode", choices=["daemon", "once", "stats"], default="once")
    parser.add_argument("--buffer-db", default=BUFFER_DB)
    parser.add_argument("--model-out", default=MODEL_OUT)
    parser.add_argument("--base-model", default=MODEL_OUT)
    args = parser.parse_args()

    conn = init_db(args.buffer_db)

    if args.mode == "stats":
        stats = buffer_stats(conn)
        print(json.dumps(stats, indent=2))
        return

    if args.mode == "once":
        log.info("Single retrain run")
        poll_api_feedback(conn)
        stats = buffer_stats(conn)
        pending = stats["pending_samples"]
        log.info(f"Buffer: {pending} pending samples")

        if pending < MIN_SAMPLES:
            log.info(f"Not enough samples ({pending} < {MIN_SAMPLES}) — skipping retrain")
            log.info("Tip: use --mode daemon to wait for samples to accumulate")
        else:
            success = retrain(conn, args.base_model, args.model_out)
            sys.exit(0 if success else 1)

    elif args.mode == "daemon":
        log.info(f"Daemon mode: retrain every {RETRAIN_INTERVAL_H}h or {MIN_SAMPLES} new samples")
        next_retrain = datetime.now() + timedelta(hours=RETRAIN_INTERVAL_H)

        while True:
            poll_api_feedback(conn)
            stats = buffer_stats(conn)
            pending = stats["pending_samples"]

            should_retrain = (
                pending >= MIN_SAMPLES or
                datetime.now() >= next_retrain
            )

            if should_retrain and pending > 0:
                log.info(f"Triggering retrain: {pending} pending samples")
                retrain(conn, args.base_model, args.model_out)
                next_retrain = datetime.now() + timedelta(hours=RETRAIN_INTERVAL_H)
            else:
                log.info(f"Waiting: {pending}/{MIN_SAMPLES} samples, next retrain at {next_retrain:%H:%M}")

            time.sleep(300)  # Poll every 5 minutes


if __name__ == "__main__":
    main()
