import os
import mlflow

# Resolve project root
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

# Repo-local mlruns directory
MLRUNS_DIR = os.path.join(PROJECT_ROOT, "mlruns")
os.makedirs(MLRUNS_DIR, exist_ok=True)

# Use file:// URI (OS-agnostic, CI-safe)
TRACKING_URI = f"file://{MLRUNS_DIR}"

mlflow.set_tracking_uri(TRACKING_URI)
mlflow.set_registry_uri(TRACKING_URI)

MODEL_NAME = "PhantomNet_Attack_Detector"
