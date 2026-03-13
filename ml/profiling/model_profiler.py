import cProfile
import pstats
import timeit
import joblib
import os
import io
import numpy as np

def get_model_size(model_path):
    if not os.path.exists(model_path):
        return 0
    return os.path.getsize(model_path) / (1024 * 1024)

def profile_inference(model_path, num_samples=1000):
    if not os.path.exists(model_path):
        print(f"Error: Model not found at {model_path}")
        return

    print(f"Loading model from {model_path}...")
    model = joblib.load(model_path)
    
    try:
        n_features = model.n_features_in_
    except AttributeError:
        # fallback
        n_features = 30 # Adjust if needed
        if hasattr(model, "estimators_"):
            try:
                n_features = model.estimators_[0].n_features_in_
            except AttributeError:
                pass

    print(f"Model expects {n_features} features.")
    
    X_dummy = np.random.rand(num_samples, n_features)
    X_single = X_dummy[[0]]

    def run_inference():
        model.predict(X_dummy)

    def run_single():
        model.predict(X_single)

    print("Measuring single sample latency (100 runs)...")
    single_time = timeit.timeit(run_single, number=100) / 100
    
    print(f"Measuring batch ({num_samples} samples) latency (10 runs)...")
    batch_time = timeit.timeit(run_inference, number=10) / 10

    size_mb = get_model_size(model_path)
    single_ms = single_time * 1000
    batch_ms = batch_time * 1000

    print(f"--- Profiling Results for {os.path.basename(model_path)} ---")
    print(f"Model Size: {size_mb:.2f} MB")
    print(f"Average Single Inference Latency: {single_ms:.2f} ms")
    print(f"Average Batch ({num_samples}) Inference Latency: {batch_ms:.2f} ms")

    pr = cProfile.Profile()
    pr.enable()
    for _ in range(500):
        model.predict(X_single)
    pr.disable()
    
    s = io.StringIO()
    ps = pstats.Stats(pr, stream=s).sort_stats('cumulative')
    ps.print_stats(15)
    
    report_content = f"""# Model Performance Baseline (Week 11)

## Metrics
- **Model Size**: {size_mb:.2f} MB
- **Single Inference Latency**: {single_ms:.2f} ms
- **Batch Latency ({num_samples} samples)**: {batch_ms:.2f} ms
- **Number of Features expected**: {n_features}

## Profiling (Top Operations)
```text
{s.getvalue()}
```
"""
    
    report_path = "reports/model_performance_baseline_week11.md"
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report_content)
    
    print(f"\nBaseline report saved to {report_path}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="backend/ml/models/attack_classifier_v3_enhanced.pkl")
    args = parser.parse_args()
    profile_inference(args.model)
