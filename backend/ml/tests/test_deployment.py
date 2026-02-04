import mlflow
import pandas as pd
from config.mlflow_env import *


MODEL_NAME = "PhantomNet_Attack_Detector"
STAGE = "Staging"

def test_model_deployment_inference():
    model = mlflow.pyfunc.load_model(
        model_uri=f"models:/{MODEL_NAME}/{STAGE}"
    )

    df = pd.DataFrame([{"payload_length": 120}])
    preds = model.predict(df)

    assert len(preds) == 1
