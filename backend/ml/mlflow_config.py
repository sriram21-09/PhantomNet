import os
import mlflow
import mlflow.sklearn
from contextlib import contextmanager

# ======================
# MLFLOW SETUP
# ======================

def setup_mlflow():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
    MLFLOW_DIR = os.path.join(PROJECT_ROOT, "mlruns")

    mlflow.set_tracking_uri(f"file:///{MLFLOW_DIR}")
    mlflow.set_experiment("PhantomNet-ML")

# ======================
# RUN CONTEXT
# ======================

@contextmanager
def start_run(run_name=None):
    with mlflow.start_run(run_name=run_name):
        yield

# ======================
# LOGGING HELPERS
# ======================

def log_params(params: dict):
    for k, v in params.items():
        mlflow.log_param(k, v)

def log_metrics(metrics: dict):
    for k, v in metrics.items():
        mlflow.log_metric(k, v)

def log_model(model):
    mlflow.sklearn.log_model(model, artifact_path="model")
