import os
import mlflow

# --------------------------------------------------
# Project root (CI-safe)
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", "..", ".."))

MLRUNS_DIR = os.path.join(PROJECT_ROOT, "mlruns")
os.makedirs(MLRUNS_DIR, exist_ok=True)

TRACKING_URI = f"file://{MLRUNS_DIR}"

MODEL_NAME = "PhantomNet_Attack_Detector"
DEFAULT_STAGE = "Staging"

# --------------------------------------------------
# FORCE MLflow configuration
# --------------------------------------------------
mlflow.set_tracking_uri(TRACKING_URI)
mlflow.set_registry_uri(TRACKING_URI)
