import time
import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from config.mlflow_env import *


from training_framework import TrainingFramework
from evaluation import evaluate_classification
from mlflow_config import (
    setup_mlflow,
    start_run,
    log_params,
    log_metrics,
    log_model
)

# ======================
# PATH SETUP (ROBUST)
# ======================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

POSSIBLE_FILES = [
    "week6_test_events_balanced.csv",
    "week6_test_events.csv"
]

CSV_PATH = None
for fname in POSSIBLE_FILES:
    path = os.path.join(DATA_DIR, fname)
    if os.path.exists(path):
        CSV_PATH = path
        break

if CSV_PATH is None:
    raise FileNotFoundError(
        f"No valid Week 6 CSV found in {DATA_DIR}"
    )

# ======================
# CONFIG
# ======================

FEATURE_COLUMNS = ["payload_length"]
LABEL_COLUMN = "is_attack"

ATTACK_EVENTS = {
    "login_failed",
    "sqli_attempt",
    "command",
    "connect",
    "mail_from",
    "rcpt_to",
    "data"
}

# ======================
# MAIN
# ======================

def main():
    print("[ML] Loading dataset...")
    print(f"[ML] Dataset path: {CSV_PATH}")
    df = pd.read_csv(CSV_PATH)

    # ----------------------
    # FEATURE ENGINEERING
    # ----------------------
    if "payload_length" not in df.columns:
        print("[ML] Computing payload_length feature...")
        df["payload_length"] = df["data"].astype(str).apply(len)

    print("[ML] Creating binary attack label...")
    df["is_attack"] = df["event"].apply(
        lambda x: 1 if str(x).lower() in ATTACK_EVENTS else 0
    )

    print("[ML] Setting up MLflow...")
    setup_mlflow()

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42
    )

    trainer = TrainingFramework(
        model=model,
        feature_columns=FEATURE_COLUMNS,
        label_column=LABEL_COLUMN
    )

    with start_run(run_name="binary_attack_random_forest"):
        result = trainer.train(df)

        metrics = evaluate_classification(
            result["y_test"],
            result["y_pred"]
        )

        log_params({
            "model": "RandomForest",
            "n_estimators": 200,
            "features": FEATURE_COLUMNS,
            "label": "binary_attack"
        })

        log_metrics(metrics)
        log_model(result["model"])

        print("[ML] Training complete")
        print("[ML] Metrics:", metrics)

        # ----------------------
        # Inference Latency
        # ----------------------
        start = time.time()
        _ = result["model"].predict(result["X_test"])
        end = time.time()

        latency_ms = (end - start) * 1000
        print(f"[ML] Inference latency: {latency_ms:.2f} ms")


if __name__ == "__main__":
    main()
