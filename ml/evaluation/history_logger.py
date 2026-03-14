import os
import sys
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

# Add project root directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from ml.registry.model_registry import ModelRegistry

class HistoryLogger:
    def __init__(self, registry_dir="ml_models/registry", history_path="ml/evaluation/evaluation_history.jsonl", reports_dir="reports"):
        self.registry = ModelRegistry(registry_dir=registry_dir)
        self.history_path = history_path
        self.reports_dir = reports_dir
        os.makedirs(os.path.dirname(self.history_path), exist_ok=True)
        os.makedirs(self.reports_dir, exist_ok=True)

    def log_history(self):
        """Extracts metrics from all models in registry and updates the history log."""
        index = self.registry._load_index()
        models = index.get("models", {})
        
        # Sort versions to maintain temporal order if needed
        versions = sorted(models.keys(), key=lambda x: self.registry._parse_version(x))
        
        history_entries = []
        for v in versions:
            meta = models[v]
            metrics = meta.get("metrics", {})
            if metrics:
                entry = {
                    "version": v,
                    "timestamp": metrics.get("timestamp", meta.get("training_date")),
                    "accuracy": metrics.get("accuracy"),
                    "precision": metrics.get("precision"),
                    "recall": metrics.get("recall"),
                    "f1_score": metrics.get("f1_score"),
                    "auc": metrics.get("auc")
                }
                history_entries.append(entry)
        
        # Save as JSONL
        with open(self.history_path, "w") as f:
            for entry in history_entries:
                f.write(json.dumps(entry) + "\n")
        
        print(f"History log updated at {self.history_path} with {len(history_entries)} entries.")
        return history_entries

    def visualize_timeline(self):
        """Generates reports/evaluation_history_timeline.png."""
        if not os.path.exists(self.history_path):
            print("No history file found to visualize.")
            return

        df = pd.read_json(self.history_path, lines=True)
        if df.empty:
            print("History is empty.")
            return

        # Ensure timestamp is datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df = df.sort_values('timestamp')

        plt.figure(figsize=(12, 6))
        metrics_to_plot = ["accuracy", "precision", "recall", "f1_score"]
        for metric in metrics_to_plot:
            if metric in df.columns:
                plt.plot(df['version'], df[metric], marker='o', label=metric.capitalize())

        plt.ylim(0, 1.05)
        plt.title("Model Performance History Timeline")
        plt.xlabel("Model Version")
        plt.ylabel("Score")
        plt.legend()
        plt.grid(True, linestyle='--', alpha=0.7)
        
        path = os.path.join(self.reports_dir, "evaluation_history_timeline.png")
        plt.savefig(path)
        plt.close()
        print(f"Performance timeline saved to {path}")

if __name__ == "__main__":
    logger = HistoryLogger()
    logger.log_history()
    logger.visualize_timeline()
