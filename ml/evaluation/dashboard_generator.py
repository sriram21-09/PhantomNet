import os
import sys
import json
import base64
from datetime import datetime

# Add project root directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from ml.registry.model_registry import ModelRegistry

class DashboardGenerator:
    def __init__(self, registry_dir="ml_models/registry", reports_dir="reports"):
        self.registry = ModelRegistry(registry_dir=registry_dir)
        self.reports_dir = reports_dir
        os.makedirs(self.reports_dir, exist_ok=True)

    def _get_image_base64(self, path):
        if not os.path.exists(path):
            return ""
        with open(path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')

    def generate_dashboard(self):
        index = self.registry._load_index()
        models = index.get("models", {})
        latest_version = self.registry.get_latest_version()
        latest_model = models.get(latest_version, {})
        
        # Prepare content
        confusion_matrix_b64 = self._get_image_base64(os.path.join(self.reports_dir, f"confusion_matrix_{latest_version}.png"))
        roc_curve_b64 = self._get_image_base64(os.path.join(self.reports_dir, f"roc_curve_{latest_version}.png"))
        timeline_b64 = self._get_image_base64(os.path.join(self.reports_dir, "evaluation_history_timeline.png"))
        comparison_b64 = self._get_image_base64(os.path.join(self.reports_dir, "evaluation_comparison.png"))

        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhantomNet ML Evaluation Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background-color: #f8f9fa; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        .header {{ background-color: #212529; color: white; padding: 2rem 0; margin-bottom: 2rem; border-bottom: 5px solid #0d6efd; }}
        .card {{ border: none; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 2rem; }}
        .card-header {{ background-color: #fff; border-bottom: 1px solid #eee; font-weight: bold; color: #0d6efd; }}
        .metric-value {{ font-size: 2.5rem; font-weight: bold; color: #212529; }}
        .metric-label {{ color: #6c757d; text-transform: uppercase; font-size: 0.8rem; letter-spacing: 1px; }}
        .img-container {{ text-align: center; padding: 1rem; }}
        .img-container img {{ max-width: 100%; height: auto; border-radius: 8px; }}
        .footer {{ padding: 2rem 0; color: #6c757d; text-align: center; font-size: 0.9rem; }}
    </style>
</head>
<body>
    <div class="header text-center">
        <div class="container">
            <h1>PhantomNet ML Insights</h1>
            <p class="lead">Automated Model Evaluation & Performance Report</p>
            <span class="badge bg-primary">Latest Version: {latest_version}</span>
            <span class="badge bg-secondary">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
        </div>
    </div>

    <div class="container">
        <!-- Key Metrics -->
        <div class="row text-center mb-4">
            <div class="col-md-3">
                <div class="card p-3">
                    <div class="metric-label">Accuracy</div>
                    <div class="metric-value">{latest_model.get('metrics', {}).get('accuracy', 0):.4f}</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3">
                    <div class="metric-label">Precision</div>
                    <div class="metric-value">{latest_model.get('metrics', {}).get('precision', 0):.4f}</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3">
                    <div class="metric-label">Recall</div>
                    <div class="metric-value">{latest_model.get('metrics', {}).get('recall', 0):.4f}</div>
                </div>
            </div>
            <div class="col-md-3">
                <div class="card p-3">
                    <div class="metric-label">F1-Score</div>
                    <div class="metric-value">{latest_model.get('metrics', {}).get('f1_score', 0):.4f}</div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- Latest Model Detailed Analysis -->
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">Confusion Matrix ({latest_version})</div>
                    <div class="img-container">
                        <img src="data:image/png;base64,{confusion_matrix_b64}" alt="Confusion Matrix">
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">ROC Curve ({latest_version})</div>
                    <div class="img-container">
                        <img src="data:image/png;base64,{roc_curve_b64}" alt="ROC Curve">
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- History and Comparison -->
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">Model Performance History (Timeline)</div>
                    <div class="img-container">
                        <img src="data:image/png;base64,{timeline_b64}" alt="Performance Timeline">
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-12">
                <div class="card">
                    <div class="card-header">Model Version Comparison</div>
                    <div class="img-container">
                        <img src="data:image/png;base64,{comparison_b64}" alt="Model Comparison">
                    </div>
                </div>
            </div>
        </div>

        <!-- Registry Summary Table -->
        <div class="card">
            <div class="card-header">Model Registry Overview</div>
            <div class="card-body">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Version</th>
                            <th>Name</th>
                            <th>Status</th>
                            <th>Accuracy</th>
                            <th>F1-Score</th>
                            <th>Training Date</th>
                        </tr>
                    </thead>
                    <tbody>
        """
        
        # Sort versions for the table
        sorted_versions = sorted(models.keys(), key=lambda x: self.registry._parse_version(x), reverse=True)
        for v in sorted_versions:
            m = models[v]
            html_template += f"""
                        <tr>
                            <td><code>{v}</code></td>
                            <td>{m.get('name')}</td>
                            <td><span class="badge bg-{'success' if m.get('status') == 'Production' else 'warning'}">{m.get('status')}</span></td>
                            <td>{m.get('metrics', {}).get('accuracy', 'N/A')}</td>
                            <td>{m.get('metrics', {}).get('f1_score', 'N/A')}</td>
                            <td>{m.get('training_date', 'N/A')[:10]}</td>
                        </tr>
            """

        html_template += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div class="footer">
        <p>&copy; 2026 PhantomNet Cybersecurity Platform. All rights reserved.</p>
    </div>
</body>
</html>
        """
        
        output_path = os.path.join(self.reports_dir, "evaluation_dashboard.html")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        
        print(f"Evaluation dashboard generated at {output_path}")
        return output_path

if __name__ == "__main__":
    generator = DashboardGenerator()
    generator.generate_dashboard()
