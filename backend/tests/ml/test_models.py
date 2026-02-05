import mlflow
import pandas as pd
from mlflow.tracking import MlflowClient

MODEL_NAME = "PhantomNet_Attack_Detector"
STAGE = "Staging"


def test_model_registered():
    """
    Ensure model is registered in MLflow Registry
    """
    client = MlflowClient()
    models = [m.name for m in client.search_registered_models()]

    assert MODEL_NAME in models, "Model not found in MLflow Registry"


def test_model_load_and_inference():
    """
    Ensure model loads from registry and can run inference
    """
    model = mlflow.pyfunc.load_model(
        model_uri=f"models:/{MODEL_NAME}/{STAGE}"
    )

    # Minimal valid input (same as deployment test)
    sample_input = pd.DataFrame([
        {"payload_length": 120}
    ])

    preds = model.predict(sample_input)

    assert preds is not None
    assert len(preds) == 1
