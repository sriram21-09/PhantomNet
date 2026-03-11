import json
from typing import List, Dict, Any
from ml.registry.model_registry import ModelRegistry
import os

class ModelComparator:
    """
    Compares models from the ModelRegistry to generate a performance report.
    """
    
    def __init__(self, registry: ModelRegistry):
        self.registry = registry

    def compare_models(self, version_1: str, version_2: str) -> Dict[str, Any]:
        """
        Compares two specific model versions.
        """
        model_1 = self.registry.get_model(version_1)
        model_2 = self.registry.get_model(version_2)
        
        if not model_1 or not model_2:
            raise ValueError(f"One or both models not found in registry: {version_1}, {version_2}")
            
        m1_metrics = model_1.get("metrics", {})
        m2_metrics = model_2.get("metrics", {})
        
        comparison = {}
        all_metric_keys = set(m1_metrics.keys()).union(set(m2_metrics.keys()))
        
        for key in all_metric_keys:
            val1 = m1_metrics.get(key, None)
            val2 = m2_metrics.get(key, None)
            
            diff = None
            if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                diff = val2 - val1 # Positive means v2 is better (usually)
            
            comparison[key] = {
                f"{version_1}": val1,
                f"{version_2}": val2,
                "difference": diff
            }
            
        return comparison

    def generate_report(self, versions: List[str], output_path: str = "model_comparison_report.md"):
        """
        Generates a Markdown report comparing the given list of model versions.
        """
        if len(versions) < 2:
            raise ValueError("Need at least 2 versions to generate a report.")
            
        models = [self.registry.get_model(v) for v in versions]
        
        if any(m is None for m in models):
            missing = [versions[i] for i, m in enumerate(models) if m is None]
            raise ValueError(f"Missing models from registry: {missing}")

        all_metric_keys = set()
        for m in models:
            all_metric_keys.update(m.get("metrics", {}).keys())
            
        report_lines = [
            f"# Model Comparison Report",
            f"Comparing versions: {', '.join(versions)}",
            "",
            "## Primary Metrics",
            ""
        ]
        
        # Build Table Header
        header = "| Metric | " + " | ".join(versions) + " |"
        separator = "|---|" + "|".join(["---" for _ in versions]) + "|"
        report_lines.extend([header, separator])
        
        for metric in sorted(all_metric_keys):
            row_data = []
            for m in models:
                val = m.get("metrics", {}).get(metric, "N/A")
                if isinstance(val, float):
                    val = f"{val:.4f}"
                row_data.append(str(val))
                
            row = f"| **{metric}** | " + " | ".join(row_data) + " |"
            report_lines.append(row)
            
        report_lines.append("")
        report_lines.append("## Conclusion")
        report_lines.append("Review differences above to determine model promotion.")
        
        with open(output_path, "w") as f:
            f.write("\n".join(report_lines))
            
        return output_path

if __name__ == "__main__":
    # Test script for "Test comparison with v1, v2, v3 models"
    print("Testing Model Comparator...")
    
    # 1. Setup a dummy registry
    dummy_registry_dir = "ml_models/test_registry"
    registry = ModelRegistry(registry_dir=dummy_registry_dir)
    
    # Create simple dummy model files
    os.makedirs("ml_models", exist_ok=True)
    with open("ml_models/dummy.pkl", "w") as f:
        f.write("dummy")
        
    # 2. Register dummy models v1, v2, v3
    v1_meta = {"metrics": {"accuracy": 0.85, "precision": 0.82, "recall": 0.88, "f1_score": 0.85}}
    v2_meta = {"metrics": {"accuracy": 0.88, "precision": 0.85, "recall": 0.90, "f1_score": 0.87}}
    v3_meta = {"metrics": {"accuracy": 0.91, "precision": 0.89, "recall": 0.93, "f1_score": 0.91}}
    
    v1 = registry.register_model("ml_models/dummy.pkl", "DummyTest", bump_type="major", metadata=v1_meta)
    v2 = registry.register_model("ml_models/dummy.pkl", "DummyTest", bump_type="minor", metadata=v2_meta)
    v3 = registry.register_model("ml_models/dummy.pkl", "DummyTest", bump_type="patch", metadata=v3_meta)
    
    print(f"Registered dummy models: {v1}, {v2}, {v3}")
    
    # 3. Compare v1 and v3
    comparator = ModelComparator(registry)
    diff = comparator.compare_models(v1, v3)
    print(f"\nComparison between {v1} and {v3}:")
    print(json.dumps(diff, indent=2))
    
    # 4. Generate markdown report
    report_file = "docs/test_comparison_report.md"
    os.makedirs("docs", exist_ok=True)
    out_path = comparator.generate_report([v1, v2, v3], output_path=report_file)
    print(f"\nGenerated report at: {out_path}")
