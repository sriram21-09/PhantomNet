import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Add project root directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from ml.registry.model_registry import ModelRegistry

class ComparisonVisualizer:
    def __init__(self, registry_dir="ml_models/registry", reports_dir="reports"):
        self.registry = ModelRegistry(registry_dir=registry_dir)
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def visualize_comparison(self, limit=3):
        """Generates reports/evaluation_comparison.png."""
        index = self.registry._load_index()
        models = index.get("models", {})
        
        # Get versions, sort by version, and take top N
        versions = sorted(models.keys(), key=lambda x: self.registry._parse_version(x), reverse=True)
        top_versions = versions[:limit]
        top_versions.reverse() # Show oldest to newest in chart

        comparison_data = []
        for v in top_versions:
            meta = models[v]
            metrics = meta.get("metrics", {})
            if metrics:
                comparison_data.append({
                    "Version": v,
                    "Accuracy": metrics.get("accuracy", 0),
                    "Precision": metrics.get("precision", 0),
                    "Recall": metrics.get("recall", 0),
                    "F1-Score": metrics.get("f1_score", 0)
                })

        if not comparison_data:
            print("No metrics found for comparison.")
            return

        df = pd.DataFrame(comparison_data)
        metrics_list = ["Accuracy", "Precision", "Recall", "F1-Score"]
        
        # Plotting
        x = np.arange(len(top_versions))
        width = 0.2
        
        plt.figure(figsize=(12, 7))
        for i, metric in enumerate(metrics_list):
            plt.bar(x + i*width, df[metric], width, label=metric)

        plt.xlabel('Model Version')
        plt.ylabel('Score')
        plt.title(f'Comparison of Top {len(top_versions)} Model Versions')
        plt.xticks(x + width*1.5, top_versions)
        plt.ylim(0, 1.1)
        plt.legend(loc='lower right')
        plt.grid(axis='y', linestyle='--', alpha=0.5)

        path = os.path.join(self.reports_dir, "evaluation_comparison.png")
        plt.savefig(path)
        plt.close()
        print(f"Model comparison chart saved to {path}")

if __name__ == "__main__":
    visualizer = ComparisonVisualizer()
    visualizer.visualize_comparison()
