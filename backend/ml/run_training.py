import time
import os
import traceback
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from config.mlflow_env import TRACKING_URI, MODEL_NAME, DEFAULT_STAGE
import mlflow
mlflow.set_tracking_uri(TRACKING_URI)
mlflow.set_registry_uri(TRACKING_URI)

from training_framework import TrainingFramework
from evaluation import evaluate_classification
from mlflow_config import setup_mlflow, start_run, log_params, log_metrics, log_model

# --------------------------------------------------
# PATH SETUP
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

POSSIBLE_FILES = [
    "week6_test_events_balanced.csv",
    "week6_test_events.csv"
]

CSV_PATH = next(
    (os.path.join(DATA_DIR, f) for f in POSSIBLE_FILES if os.path.exists(os.path.join(DATA_DIR, f))),
    None
)

if CSV_PATH is None:
    raise FileNotFoundError(f"No valid Week 6 CSV found in {DATA_DIR}")

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
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

# --------------------------------------------------
# MAIN
# --------------------------------------------------
def main():
    try:
        print("[ML] Loading dataset:", CSV_PATH)
        df = pd.read_csv(CSV_PATH)

        if "payload_length" not in df.columns:
            df["payload_length"] = df["data"].astype(str).apply(len)

        df["is_attack"] = df["event"].apply(
            lambda x: 1 if str(x).lower() in ATTACK_EVENTS else 0
        )

        print("[ML] Label distribution:")
        print(df["is_attack"].value_counts())

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
            })

            log_metrics(metrics)
            log_model(result["model"])

            print("[ML] Training complete:", metrics)

    except Exception as e:
        print("[ML] ERROR:", e)
        traceback.print_exc()
        raise

if __name__ == "__main__":
    main()
