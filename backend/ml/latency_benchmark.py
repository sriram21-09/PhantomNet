import os
import time
import numpy as np
import pandas as pd
import mlflow
import mlflow.sklearn
from config.mlflow_env import *



# ======================
# PATH & MLFLOW SETUP
# ======================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MLFLOW_DIR = os.path.join(PROJECT_ROOT, "mlruns")

# Force same MLflow tracking DB as training
mlflow.set_tracking_uri(f"file:///{MLFLOW_DIR}")

CSV_PATH = os.path.join(DATA_DIR, "week6_test_events.csv")
FEATURE_COLUMNS = ["payload_length"]

# ======================
# MAIN
# ======================

def main():
    print("[LATENCY] Loading dataset...")
    df = pd.read_csv(CSV_PATH)

    if "payload_length" not in df.columns:
        df["payload_length"] = df["data"].astype(str).apply(len)

    X = df[FEATURE_COLUMNS]

    print("[LATENCY] Connecting to MLflow...")
    client = mlflow.tracking.MlflowClient()

    # Get all experiment IDs
    experiments = client.search_experiments()
    if not experiments:
        raise RuntimeError("No MLflow experiments found. Run training first.")

    experiment_ids = [exp.experiment_id for exp in experiments]

    runs = client.search_runs(
        experiment_ids=experiment_ids,
        order_by=["attributes.start_time DESC"],
        max_results=1
    )

    if not runs:
        raise RuntimeError("No MLflow runs found. Run training first.")

    run_id = runs[0].info.run_id
    model_uri = f"runs:/{run_id}/model"

    print(f"[LATENCY] Loading model from MLflow (run_id={run_id})")
    model = mlflow.sklearn.load_model(model_uri)

    latencies = []

    print("[LATENCY] Running inference benchmark...")

    for _ in range(100):
        start = time.time()
        _ = model.predict(X)
        end = time.time()
        latencies.append((end - start) * 1000)

    print("\n--- Inference Latency Benchmark (ms) ---")
    print(f"Average latency : {np.mean(latencies):.2f}")
    print(f"Minimum latency : {np.min(latencies):.2f}")
    print(f"Maximum latency : {np.max(latencies):.2f}")

    if np.mean(latencies) < 100:
        print("\n[LATENCY] PASSED ✅ (<100 ms)")
    else:
        print("\n[LATENCY] FAILED ❌ (>100 ms)")


if __name__ == "__main__":
    main()
