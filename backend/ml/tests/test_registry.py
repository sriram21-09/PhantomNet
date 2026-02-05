import mlflow
from mlflow.tracking import MlflowClient
from config.mlflow_env import *


MODEL_NAME = "PhantomNet_Attack_Detector"

def test_model_registered():
    client = MlflowClient()
    models = [m.name for m in client.search_registered_models()]
    assert MODEL_NAME in models
