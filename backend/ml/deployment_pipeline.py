import mlflow
import pandas as pd
from pathlib import Path
from config.mlflow_env import *



# 🔒 Force consistent tracking store
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MLRUNS_PATH = PROJECT_ROOT / "mlruns"
mlflow.set_tracking_uri(f"file:///{MLRUNS_PATH}")

MODEL_NAME = "PhantomNet_Attack_Detector"
MODEL_STAGE = "Staging"   # or "Production" later


class DeploymentPipeline:
    def __init__(self):
        print("[DEPLOY] Loading model from MLflow Registry (SAFE MODE)...")
        print(f"[DEPLOY] Model : {MODEL_NAME}")
        print(f"[DEPLOY] Stage : {MODEL_STAGE}")

        # ✅ THIS NEVER DEPENDS ON run_id
        self.model = mlflow.pyfunc.load_model(
            model_uri=f"models:/{MODEL_NAME}/{MODEL_STAGE}"
        )

        print("[DEPLOY] Model loaded successfully from registry ✅")

    def predict(self, df: pd.DataFrame):
        return self.model.predict(df)


def main():
    pipeline = DeploymentPipeline()

    # 🔎 Minimal inference test
    sample = pd.DataFrame([
        {"payload_length": 120}
    ])

    prediction = pipeline.predict(sample)

    print("\n--- Deployment Test ---")
    print("Input :", sample.to_dict(orient="records"))
    print("Output:", prediction.tolist())


if __name__ == "__main__":
    main()
