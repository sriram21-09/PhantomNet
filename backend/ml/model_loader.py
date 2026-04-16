import mlflow
import os
import joblib
from pathlib import Path
from ml.config.mlflow_env import TRACKING_URI, MODEL_NAME

# Singleton instance
_MODEL = None
_LOAD_ATTEMPTED = False


def load_model():
    """
    Loads the production model from MLflow or local artifacts.
    Implements caching to avoid reloading on every request.
    """
    global _MODEL, _LOAD_ATTEMPTED

    if _MODEL is not None:
        return _MODEL

    if not _LOAD_ATTEMPTED:
        print("[MODEL_LOADER] Initializing ML scoring engine...")
        _LOAD_ATTEMPTED = True

    # 1. Try MLflow
    try:
        mlflow.set_tracking_uri(TRACKING_URI)
        client = mlflow.tracking.MlflowClient()

        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=FutureWarning)
            # Get latest production version
            versions = client.get_latest_versions(MODEL_NAME, stages=["Production"])
            if not versions:
                # Fallback to None/Staging or just latest
                versions = client.get_latest_versions(
                    MODEL_NAME, stages=["None", "Staging"]
                )

        if versions:
            latest_version = versions[0]
            model_uri = f"models:/{MODEL_NAME}/{latest_version.version}"
            print(f"[MODEL_LOADER] Loading from MLflow: {model_uri}")
            _MODEL = mlflow.sklearn.load_model(model_uri)
            return _MODEL

    except Exception:
        # Silencing MLflow connection errors if they repeat
        pass

    # 2. Fallback to Local File (if MLflow fails)
    # Correct path to the model registry (project root)
    local_path = Path(__file__).parent.parent.parent / "ml_models" / "registry" / "AttackClassifier_Enhanced_v1.0.0.pkl"
    if local_path.exists():
        _MODEL = joblib.load(local_path)
        print(f"[MODEL_LOADER] Successfully loaded production model: {local_path}")
        return _MODEL

    return None


def get_model():
    """
    Public accessor for the model.
    """
    return load_model()
