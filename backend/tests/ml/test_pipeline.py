import time
import pandas as pd
import mlflow
from mlflow.tracking import MlflowClient

MODEL_NAME = "PhantomNet_Attack_Detector"
STAGE = "Staging"


def test_pipeline_quality_and_latency():
    """
    Integration test:
    - Load model from registry
    - Run inference
    - Validate latency
    - Validate inference sanity
    """

    model = mlflow.pyfunc.load_model(
        model_uri=f"models:/{MODEL_NAME}/{STAGE}"
    )

    # Synthetic batch (deployment sanity only)
    X = pd.DataFrame([
        {"payload_length": 50},
        {"payload_length": 120},
        {"payload_length": 300}
    ])

    start = time.time()
    y_pred = model.predict(X)
    latency_ms = (time.time() - start) * 1000

    # Latency requirement
    assert latency_ms < 100, f"Latency too high: {latency_ms} ms"

    # Deployment-level sanity checks
    assert len(y_pred) == len(X)
    assert set(y_pred).issubset({0, 1})
