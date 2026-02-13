from fastapi import APIRouter, HTTPException
import os
import json

router = APIRouter(prefix="/api/v1/model", tags=["Model Metrics"])

# Path to the models directory relative to backend/api/model_metrics.py
# backend/api/model_metrics.py -> ../../models
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.abspath(os.path.join(BASE_DIR, "..", "..", "models"))
RESULTS_FILE = os.path.join(MODELS_DIR, "hyperparameter_results.json")
CONFIG_FILE = os.path.join(MODELS_DIR, "training_config.json")

@router.get("/metrics")
def get_model_metrics():
    """
    Retrieve the latest model performance metrics.
    """
    if not os.path.exists(RESULTS_FILE):
        raise HTTPException(status_code=404, detail="Metrics file not found. Model might not be trained yet.")
    
    try:
        with open(RESULTS_FILE, "r") as f:
            data = json.load(f)
            
        # Extract relevant info
        response = {
            "timestamp": data.get("timestamp"),
            "best_f1_score": data.get("best_f1_score"),
            "best_params": data.get("best_params"),
            "details": "For full history, check models/hyperparameter_results.json"
        }
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading metrics: {str(e)}")

@router.get("/config")
def get_training_config():
    """
    Retrieve the training configuration.
    """
    if not os.path.exists(CONFIG_FILE):
         raise HTTPException(status_code=404, detail="Config file not found.")

    try:
        with open(CONFIG_FILE, "r") as f:
            config = json.load(f)
        return config
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading config: {str(e)}")
