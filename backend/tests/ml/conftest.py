import os
import mlflow
import pytest


@pytest.fixture(scope="session", autouse=True)
def set_mlflow_tracking_uri():
    """
    Ensure ALL tests use the same MLflow tracking store
    regardless of execution path.
    """
    project_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../..")
    )

    mlruns_path = os.path.join(project_root, "mlruns")

    mlflow.set_tracking_uri(f"file:///{mlruns_path.replace(os.sep, '/')}")
