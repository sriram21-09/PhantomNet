import os
import mlflow
import pytest


@pytest.fixture(scope="session", autouse=True)
def set_mlflow_tracking_uri():
    """
    Ensure ALL tests use the same MLflow tracking store
    regardless of execution path.
    """
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))

    from backend.ml.config.mlflow_env import TRACKING_URI
    mlflow.set_tracking_uri(TRACKING_URI)
