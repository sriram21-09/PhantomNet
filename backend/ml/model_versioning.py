import os
import mlflow
from mlflow.tracking import MlflowClient
from config.mlflow_env import *


# ======================
# CONFIG
# ======================

MODEL_NAME = "PhantomNet_Attack_Detector"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
MLFLOW_DIR = os.path.join(PROJECT_ROOT, "mlruns")

mlflow.set_tracking_uri(f"file:///{MLFLOW_DIR}")


def main():
    print("[VERSIONING] Connecting to MLflow Registry...")
    client = MlflowClient()

    versions = client.search_model_versions(f"name='{MODEL_NAME}'")
    if not versions:
        raise RuntimeError("No model versions found")

    latest_version = max(int(v.version) for v in versions)
    print(f"[VERSIONING] Latest model version: {latest_version}")

    # ----------------------
    # Move directly to STAGING
    # ----------------------
    client.transition_model_version_stage(
        name=MODEL_NAME,
        version=latest_version,
        stage="Staging",
        archive_existing_versions=False
    )

    # ----------------------
    # Add metadata tags (modern replacement for Dev stage)
    # ----------------------
    client.set_model_version_tag(
        name=MODEL_NAME,
        version=latest_version,
        key="lifecycle",
        value="pre-production"
    )

    client.set_model_version_tag(
        name=MODEL_NAME,
        version=latest_version,
        key="validated",
        value="true"
    )

    print("\n--- Versioning Complete ---")
    print(f"Model Name : {MODEL_NAME}")
    print(f"Version    : {latest_version}")
    print("Stage      : Staging")
    print("Tags       : lifecycle=pre-production, validated=true")


if __name__ == "__main__":
    main()
