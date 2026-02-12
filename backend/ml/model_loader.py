import mlflow
import os
import joblib
from pathlib import Path
from ml.config.mlflow_env import TRACKING_URI, MODEL_NAME

# Singleton instance
_MODEL = None

def load_model():
    """
    Loads the production model from MLflow or local artifacts.
    Implements caching to avoid reloading on every request.
    """
    global _MODEL
    
    if _MODEL is not None:
        return _MODEL

    print("[MODEL_LOADER] Loading model...")
    
    # 1. Try MLflow
    try:
        mlflow.set_tracking_uri(TRACKING_URI)
        client = mlflow.tracking.MlflowClient()
        
        # Get latest production version
        versions = client.get_latest_versions(MODEL_NAME, stages=["Production"])
        if not versions:
            # Fallback to None/Staging or just latest
            versions = client.get_latest_versions(MODEL_NAME, stages=["None", "Staging"])
            
        if versions:
            latest_version = versions[0]
            model_uri = f"models:/{MODEL_NAME}/{latest_version.version}"
            print(f"[MODEL_LOADER] Loading from MLflow: {model_uri}")
            _MODEL = mlflow.sklearn.load_model(model_uri)
            return _MODEL
            
    except Exception as e:
        print(f"[MODEL_LOADER] MLflow load failed: {e}")

    # 2. Fallback to Local File (if MLflow fails)
    local_path = Path(__file__).parent / "model.pkl"
    if local_path.exists():
        print(f"[MODEL_LOADER] Loading from local file: {local_path}")
        _MODEL = joblib.load(local_path)
        return _MODEL

    print("[MODEL_LOADER] CRITICAL: No model found.")
    return None

def get_model():
    """
    Public accessor for the model.
    """
    return load_model()
