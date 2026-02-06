import mlflow
import mlflow.sklearn
from contextlib import contextmanager
from config.mlflow_env import TRACKING_URI, MODEL_NAME, DEFAULT_STAGE

# --------------------------------------------------
# DO NOT compute paths here
# --------------------------------------------------

def setup_mlflow():
    mlflow.set_tracking_uri(TRACKING_URI)
    mlflow.set_experiment("PhantomNet-ML")

@contextmanager
def start_run(run_name=None):
    with mlflow.start_run(run_name=run_name):
        yield

def log_params(params: dict):
    for k, v in params.items():
        mlflow.log_param(k, v)

def log_metrics(metrics: dict):
    for k, v in metrics.items():
        mlflow.log_metric(k, v)

def log_model(model, model_name=MODEL_NAME, stage=DEFAULT_STAGE):
    mlflow.sklearn.log_model(model, artifact_path="model")

    result = mlflow.register_model(
        model_uri="runs:/{}/model".format(mlflow.active_run().info.run_id),
        name=model_name
    )

    client = mlflow.tracking.MlflowClient()
    client.transition_model_version_stage(
        name=model_name,
        version=result.version,
        stage=stage
    )
