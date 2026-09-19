import os
import pytest
import mlflow
import mlflow.sklearn
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from backend.ml.config.mlflow_env import MODEL_NAME, TRACKING_URI, DEFAULT_STAGE


@pytest.fixture(scope="session", autouse=True)
def setup_mlflow_model():
    """
    Ensures a model is registered and staged for tests.
    Guarantees that test_models.py and test_pipeline.py pass
    even on a fresh CI environment or after clearing mlruns.
    """
    mlflow.set_tracking_uri(TRACKING_URI)
    mlflow.set_registry_uri(TRACKING_URI)

    experiment = mlflow.get_experiment_by_name("PhantomNet-ML")
    if experiment is None:
        try:
            mlflow.create_experiment("PhantomNet-ML")
        except:
            pass
    mlflow.set_experiment("PhantomNet-ML")

    client = mlflow.tracking.MlflowClient()

    model_exists = False
    try:
        registered_models = client.search_registered_models(
            filter_string=f"name='{MODEL_NAME}'"
        )
        if registered_models:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", category=FutureWarning)
                latest_versions = client.get_latest_versions(
                    MODEL_NAME, stages=[DEFAULT_STAGE]
                )
            if latest_versions:
                model_exists = True
    except Exception:
        pass

    if model_exists:
        return

    model = RandomForestClassifier(n_estimators=10)
    df = pd.DataFrame({"payload_length": [10, 20, 30], "is_attack": [0, 0, 1]})
    X = df[["payload_length"]]
    y = df["is_attack"]
    model.fit(X, y)

    with mlflow.start_run(run_name="test_fixture_run"):
        mlflow.sklearn.log_model(model, "model")
        run_id = mlflow.active_run().info.run_id

    model_uri = f"runs:/{run_id}/model"
    mv = mlflow.register_model(model_uri, MODEL_NAME)

    client.transition_model_version_stage(
        name=MODEL_NAME, version=mv.version, stage=DEFAULT_STAGE
    )
