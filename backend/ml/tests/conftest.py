import pytest
import mlflow
import mlflow.sklearn
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
# Adjust import based on sys.path set by backend/ml/conftest.py
try:
    from config.mlflow_env import MODEL_NAME, TRACKING_URI, DEFAULT_STAGE
except ImportError:
    # If running from root, python path might behave differently
    from backend.ml.config.mlflow_env import MODEL_NAME, TRACKING_URI, DEFAULT_STAGE

@pytest.fixture(scope="session", autouse=True)
def setup_mlflow_model():
    """
    Ensures a model is registered and staged for tests.
    This guarantees that test_deployment.py and test_registry.py pass
    even on a fresh CI environment or after clearing mlruns.
    """
    mlflow.set_tracking_uri(TRACKING_URI)
    mlflow.set_registry_uri(TRACKING_URI)
    
    # Ensure default experiment exists
    experiment = mlflow.get_experiment_by_name("PhantomNet-ML")
    if experiment is None:
        try:
             mlflow.create_experiment("PhantomNet-ML")
        except:
             # If exact name collision or race condition, ignore
             pass
    mlflow.set_experiment("PhantomNet-ML")


    client = mlflow.tracking.MlflowClient()
    
    # Check if a usable version exists
    model_exists = False
    try:
        # Search for registered model
        registered_models = client.search_registered_models(filter_string=f"name='{MODEL_NAME}'")
        if registered_models:
            latest_versions = client.get_latest_versions(MODEL_NAME, stages=[DEFAULT_STAGE])
            if latest_versions:
                model_exists = True
    except Exception:
        # If registry doesn't exist or error, assume we need to create
        pass

    if model_exists:
        return

    # Create dummy model
    print("Fixture: Training dummy model for tests...")
    model = RandomForestClassifier(n_estimators=10)
    # Dummy data
    df = pd.DataFrame({"payload_length": [10, 20, 30], "is_attack": [0, 0, 1]})
    X = df[["payload_length"]]
    y = df["is_attack"]
    model.fit(X, y)

    with mlflow.start_run(run_name="test_fixture_run"):
        mlflow.sklearn.log_model(model, "model")
        run_id = mlflow.active_run().info.run_id
    
    # Register
    model_uri = f"runs:/{run_id}/model"
    mv = mlflow.register_model(model_uri, MODEL_NAME)
    
    # Transition to Staging
    client.transition_model_version_stage(
        name=MODEL_NAME,
        version=mv.version,
        stage=DEFAULT_STAGE
    )
    print(f"Fixture: Model {MODEL_NAME} version {mv.version} registered and staged to {DEFAULT_STAGE}.")
