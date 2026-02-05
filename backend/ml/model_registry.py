import mlflow
from mlflow.tracking import MlflowClient
from pathlib import Path
from config.mlflow_env import *



PROJECT_ROOT = Path(__file__).resolve().parents[2]
MLRUNS_PATH = PROJECT_ROOT / "mlruns"

MODEL_NAME = "PhantomNet_Attack_Detector"
EXPERIMENT_NAME = "PhantomNet-ML"

def main():
    print("[REGISTRY] Connecting to MLflow...")
    mlflow.set_tracking_uri(f"file:///{MLRUNS_PATH}")
    mlflow.set_experiment(EXPERIMENT_NAME)

    client = MlflowClient()

    # 🔍 Find experiment
    exp = client.get_experiment_by_name(EXPERIMENT_NAME)
    if not exp:
        raise RuntimeError("Experiment not found. Train model first.")

    # 🔍 Get latest successful run
    runs = client.search_runs(
        experiment_ids=[exp.experiment_id],
        order_by=["attributes.start_time DESC"],
        max_results=1
    )

    if not runs:
        raise RuntimeError("No MLflow runs found. Train model first.")

    run_id = runs[0].info.run_id
    print(f"[REGISTRY] Using run_id={run_id}")

    model_uri = f"runs:/{run_id}/model"

    print("[REGISTRY] Registering model from MLflow artifacts...")
    mlflow.register_model(
        model_uri=model_uri,
        name=MODEL_NAME
    )

    print("\n--- Model Registered Successfully ---")
    print(f"Model Name : {MODEL_NAME}")
    print(f"Source Run : {run_id}")
    print("Artifact   : model/")
    print("Status     : READY FOR VERSIONING")

if __name__ == "__main__":
    main()
