import os
import mlflow
import mlflow.sklearn
from contextlib import contextmanager

# ==================================================
# MLFLOW CONFIG (CI + LOCAL SAFE)
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))

MLRUNS_DIR = os.path.join(PROJECT_ROOT, "mlruns")
os.makedirs(MLRUNS_DIR, exist_ok=True)

TRACKING_URI = f"file://{MLRUNS_DIR}"

mlflow.set_tracking_uri(TRACKING_URI)
mlflow.set_registry_uri(TRACKING_URI)

EXPERIMENT_NAME = "PhantomNet-ML"

def setup_mlflow():
    """
    Idempotent MLflow setup.
    Safe to call multiple times.
    """
    mlflow.set_tracking_uri(TRACKING_URI)
    mlflow.set_registry_uri(TRACKING_URI)
    mlflow.set_experiment(EXPERIMENT_NAME)

# ==================================================
# RUN CONTEXT
# ==================================================

@contextmanager
def start_run(run_name: str | None = None):
    with mlflow.start_run(run_name=run_name):
        yield

# ==================================================
# LOGGING HELPERS
# ==================================================

def log_params(params: dict):
    for key, value in params.items():
        mlflow.log_param(key, value)

def log_metrics(metrics: dict):
    for key, value in metrics.items():
        mlflow.log_metric(key, value)

def log_model(model):
    """
    Logs model AND makes it registrable.
    """
    mlflow.sklearn.log_model(
        sk_model=model,
        artifact_path="model",
        registered_model_name="PhantomNet_Attack_Detector"
    )

