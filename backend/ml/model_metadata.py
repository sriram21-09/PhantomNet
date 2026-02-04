import os
import json
import mlflow
from config.mlflow_env import *


from mlflow.tracking import MlflowClient

MODEL_NAME = "PhantomNet_Attack_Detector"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
MLFLOW_DIR = os.path.join(PROJECT_ROOT, "mlruns")

mlflow.set_tracking_uri(f"file:///{MLFLOW_DIR}")


def main():
    print("[METADATA] Connecting to MLflow...")
    client = MlflowClient()

    versions = client.search_model_versions(f"name='{MODEL_NAME}'")
    if not versions:
        raise RuntimeError("No model versions found")

    latest_version = max(int(v.version) for v in versions)
    model_version = next(v for v in versions if int(v.version) == latest_version)

    run_id = model_version.run_id

    print(f"[METADATA] Tracking metadata for model v{latest_version}")
    print(f"[METADATA] Linked run_id: {run_id}")

    # ----------------------
    # Lineage Metadata
    # ----------------------
    metadata = {
        "dataset": "week6_test_events.csv",
        "features": [
            "payload_length",
            "honeypot_type",
            "event_type"
        ],
        "label": "is_attack",
        "training_week": "Week 7",
        "training_day": "Day 1",
        "framework": "scikit-learn",
        "model_type": "RandomForestClassifier"
    }

    # ----------------------
    # Store as model tags
    # ----------------------
    for key, value in metadata.items():
        client.set_model_version_tag(
            name=MODEL_NAME,
            version=latest_version,
            key=key,
            value=json.dumps(value) if isinstance(value, list) else str(value)
        )

    print("\n--- Metadata & Lineage Recorded ---")
    for k, v in metadata.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
