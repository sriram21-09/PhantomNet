import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, classification_report
)
import joblib
import json
from datetime import datetime

# Add project root directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from ml.registry.model_registry import ModelRegistry

class AutoEvaluator:
    def __init__(self, registry_dir="ml_models/registry", reports_dir="reports"):
        self.registry = ModelRegistry(registry_dir=registry_dir)
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def load_latest_model(self):
        latest_version = self.registry.get_latest_version()
        if not latest_version:
            print("No models found in registry.")
            return None, None
        
        model_meta = self.registry.get_model(latest_version)
        model_path = model_meta["path"]
        
        if not os.path.exists(model_path):
            print(f"Model file not found at {model_path}")
            return None, None
            
        print(f"Loading model version {latest_version} from {model_path}")
        model = joblib.load(model_path)
        return model, latest_version

    def load_eval_data(self, data_path="backend/ml/datasets/labeled_events_v2_enhanced.csv"):
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Dataset not found at {data_path}")
        
        df = pd.read_csv(data_path)
        X = df.drop("label", axis=1)
        y = df["label"]
        return X, y

    def evaluate(self, model, X, y, version):
        print(f"Running evaluation for model {version}...")
        
        # Predictions
        y_pred = model.predict(X)
        
        # Handle probability scores if available
        y_score = None
        if hasattr(model, "predict_proba"):
            y_score = model.predict_proba(X)[:, 1]
        elif hasattr(model, "decision_function"):
            y_score = model.decision_function(X)
            
        # Basic Metrics
        metrics = {
            "accuracy": float(accuracy_score(y, y_pred)),
            "precision": float(precision_score(y, y_pred, zero_division=0)),
            "recall": float(recall_score(y, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y, y_pred, zero_division=0)),
            "timestamp": datetime.now().isoformat(),
            "model_version": version
        }
        
        print(f"Metrics: {json.dumps(metrics, indent=2)}")
        
        # 1. Confusion Matrix Visualization
        self._plot_confusion_matrix(y, y_pred, version)
        
        # 2. ROC Curve Visualization
        if y_score is not None:
            self._plot_roc_curve(y, y_score, version)
            fpr, tpr, _ = roc_curve(y, y_score)
            metrics["auc"] = float(auc(fpr, tpr))
            
        # Update Registry Metadata
        self._update_registry_metadata(version, metrics)
        
        return metrics

    def _plot_confusion_matrix(self, y_true, y_pred, version):
        cm = confusion_matrix(y_true, y_pred)
        plt.figure(figsize=(8, 6))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False)
        plt.xlabel('Predicted Label')
        plt.ylabel('True Label')
        plt.title(f'Confusion Matrix - Model {version}')
        
        path = os.path.join(self.reports_dir, f"confusion_matrix_{version}.png")
        plt.savefig(path)
        plt.close()
        print(f"Confusion matrix saved to {path}")

    def _plot_roc_curve(self, y_true, y_score, version):
        fpr, tpr, _ = roc_curve(y_true, y_score)
        roc_auc = auc(fpr, tpr)
        
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'Receiver Operating Characteristic - Model {version}')
        plt.legend(loc="lower right")
        
        path = os.path.join(self.reports_dir, f"roc_curve_{version}.png")
        plt.savefig(path)
        plt.close()
        print(f"ROC curve saved to {path}")

    def _update_registry_metadata(self, version, metrics):
        # We need to reach into the ModelRegistry and update the metadata
        index = self.registry._load_index()
        if version in index["models"]:
            index["models"][version]["metrics"].update(metrics)
            self.registry._save_index(index)
            print(f"Successfully updated registry metadata for version {version}")

if __name__ == "__main__":
    evaluator = AutoEvaluator()
    try:
        model, version = evaluator.load_latest_model()
        if model:
            X, y = evaluator.load_eval_data()
            evaluator.evaluate(model, X, y, version)
        else:
            print("Auto-evaluation skipped: No model found.")
    except Exception as e:
        print(f"Error during auto-evaluation: {e}")
