import os
import mlflow
import pathlib

# --------------------------------------------------
# Project root (CI-safe)
# --------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", "..", ".."))

MLRUNS_DIR = os.path.join(PROJECT_ROOT, "mlruns")
os.makedirs(MLRUNS_DIR, exist_ok=True)

# Use pathlib to generate a valid file URI on all platforms (handles backslashes on Windows)
TRACKING_URI = pathlib.Path(MLRUNS_DIR).as_uri()

MODEL_NAME = "PhantomNet_Attack_Detector"
DEFAULT_STAGE = "Staging"

# --------------------------------------------------
# FORCE MLflow configuration
# --------------------------------------------------
mlflow.set_tracking_uri(TRACKING_URI)
mlflow.set_registry_uri(TRACKING_URI)
