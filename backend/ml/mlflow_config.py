# backend/ml/mlflow_config.py

import mlflow
import mlflow.sklearn


def setup_mlflow(
    experiment_name="PhantomNet-ML",
    tracking_uri="http://127.0.0.1:5000"
):
    """
    Configure MLflow tracking.
    """
    mlflow.set_tracking_uri(tracking_uri)
    mlflow.set_experiment(experiment_name)


def start_run(run_name=None):
    """
    Start an MLflow run.
    """
    return mlflow.start_run(run_name=run_name)


def log_params(params: dict):
    """
    Log model parameters.
    """
    for key, value in params.items():
        mlflow.log_param(key, value)


def log_metrics(metrics: dict):
    """
    Log evaluation metrics.
    """
    for key, value in metrics.items():
        mlflow.log_metric(key, value)


def log_model(model, artifact_path="model"):
    """
    Log trained model.
    """
    mlflow.sklearn.log_model(model, artifact_path)
