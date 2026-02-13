"""
Script to tune Isolation Forest hyperparameters using grid search.
"""

import os
import sys
import json
import joblib
import itertools
from datetime import datetime
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

# Import data loading and preprocessing from train_isolation_forest
# Assuming train_isolation_forest.py is in the same directory
try:
    from train_isolation_forest import load_data, preprocess_data, PROJECT_ROOT, DATA_DIR, MODELS_DIR
except ImportError:
    # If running from root or elsewhere, adjust path
    sys.path.append(os.path.dirname(__file__))
    from train_isolation_forest import load_data, preprocess_data, PROJECT_ROOT, DATA_DIR, MODELS_DIR

def tune_hyperparameters():
    print("🚀 Starting Hyperparameter Tuning for Isolation Forest...")
    
    # Load and preprocess data
    dataset_path = os.path.join(DATA_DIR, "training_dataset.csv")
    df = load_data(dataset_path)
    X_scaled, y, scaler, feature_cols = preprocess_data(df)
    
    if y is None:
        print("❌ Error: Labels are required for hyperparameter tuning.")
        sys.exit(1)

    # Define parameter grid
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_samples': ['auto', 0.5, 0.8],
        'contamination': ['auto', 0.01, 0.05, 0.1, 0.2]
    }
    
    # Generate all combinations
    keys, values = zip(*param_grid.items())
    param_combinations = [dict(zip(keys, v)) for v in itertools.product(*values)]
    
    print(f"🔍 Testing {len(param_combinations)} parameter combinations...")
    
    results = []
    best_f1 = -1
    best_model = None
    best_params = None
    
    for i, params in enumerate(param_combinations):
        print(f"   Testing combo {i+1}/{len(param_combinations)}: {params}...", end="\r")
        
        try:
            model = IsolationForest(
                n_estimators=params['n_estimators'],
                max_samples=params['max_samples'],
                contamination=params['contamination'],
                random_state=42,
                n_jobs=-1
            )
            model.fit(X_scaled)
            
            # Predict
            y_pred_raw = model.predict(X_scaled)
            y_pred = np.where(y_pred_raw == -1, 1, 0)
            
            # Evaluate
            f1 = f1_score(y, y_pred, zero_division=0)
            precision = precision_score(y, y_pred, zero_division=0)
            recall = recall_score(y, y_pred, zero_division=0)
            
            result_entry = {
                "params": params,
                "metrics": {
                    "f1_score": float(f1),
                    "precision": float(precision),
                    "recall": float(recall)
                }
            }
            results.append(result_entry)
            
            if f1 > best_f1:
                best_f1 = f1
                best_model = model
                best_params = params
                
        except Exception as e:
            print(f"\n❌ Error with params {params}: {e}")
            
    print(f"\n✅ Tuning complete.")
    print(f"🏆 Best F1 Score: {best_f1:.4f}")
    print(f"🏆 Best Params: {best_params}")
    
    # Save Results
    results_path = os.path.join(MODELS_DIR, "hyperparameter_results.json")
    with open(results_path, "w") as f:
        json.dump({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "best_params": best_params,
            "best_f1_score": best_f1,
            "all_results": results
        }, f, indent=4)
    print(f"💾 Saved results to {results_path}")
    
    # Save Best Model
    if best_model:
        model_path = os.path.join(MODELS_DIR, "isolation_forest_optimized.pkl")
        joblib.dump(best_model, model_path)
        print(f"💾 Saved best model to {model_path}")
        
    # Generate Markdown Report Content for the user to copy/paste or file creation
    return best_params, best_f1, results

if __name__ == "__main__":
    tune_hyperparameters()
