import os
import sys
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Configure paths
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DOCS_DIR = os.path.join(PROJECT_ROOT, "docs")
model_path = os.path.join(MODELS_DIR, "isolation_forest_optimized.pkl")
model_v2_path = os.path.join(MODELS_DIR, "isolation_forest_optimized_v2.pkl")
scaler_path = os.path.join(MODELS_DIR, "scaler_v1.pkl")
dataset_path = os.path.join(DATA_DIR, "training_dataset.csv")

def benchmark_model():
    print("🚀 Starting Model Benchmark...")
    
    # 1. Load Resources
    if not os.path.exists(model_path):
        print(f"❌ Error: Model not found at {model_path}")
        sys.exit(1)
        
    print("📦 Loading model and scaler...")
    start_load = time.time()
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
    load_time = (time.time() - start_load) * 1000
    print(f"   Load Time: {load_time:.2f} ms")
    
    # 2. Prepare Sample Data
    # We need a single sample for latency testing
    # Let's create a dummy sample based on feature count (15 features)
    dummy_sample = np.random.rand(1, 15)
    
    # Warmup
    print("🔥 Warming up model...")
    for _ in range(10):
        model.predict(dummy_sample)
        
    # 3. Measure Latency (Single Prediction)
    print("⏱️ Measuring inference latency (1000 runs)...")
    latencies = []
    for _ in range(1000):
        start = time.perf_counter()
        # Scale (part of inference pipeline)
        # Note: Scaler expects 2D array, which we have
        # In real pipeline, we'd scale then predict
        s_sample = scaler.transform(dummy_sample)
        model.predict(s_sample)
        model.decision_function(s_sample)
        latencies.append((time.perf_counter() - start) * 1000)
        
    avg_latency = np.mean(latencies)
    p95_latency = np.percentile(latencies, 95)
    p99_latency = np.percentile(latencies, 99)
    
    print(f"   Avg Latency: {avg_latency:.4f} ms")
    print(f"   P95 Latency: {p95_latency:.4f} ms")
    print(f"   P99 Latency: {p99_latency:.4f} ms")
    
    if avg_latency < 50:
        print("✅ Goal < 50ms PASSED")
    else:
        print("⚠️ Goal < 50ms FAILED")

    # 4. Model Compression
    print("💾 Optimizing model file size...")
    original_size = os.path.getsize(model_path) / 1024 # KB
    
    # Save with compression
    joblib.dump(model, model_v2_path, compress=3) # compress=3 is a good balance
    
    compressed_size = os.path.getsize(model_v2_path) / 1024 # KB
    reduction = (1 - (compressed_size / original_size)) * 100
    
    print(f"   Original Size: {original_size:.2f} KB")
    print(f"   Compressed Size: {compressed_size:.2f} KB")
    print(f"   Reduction: {reduction:.2f}%")
    
    # 5. Document Results
    report_path = os.path.join(DOCS_DIR, "performance_benchmark.md")
    with open(report_path, "w") as f:
        f.write("# Model Performance Benchmark\n\n")
        f.write(f"**Date:** {time.strftime('%Y-%m-%d')}\n\n")
        f.write("## Inference Latency\n")
        f.write(f"- **Average:** {avg_latency:.4f} ms\n")
        f.write(f"- **95th Percentile:** {p95_latency:.4f} ms\n")
        f.write(f"- **99th Percentile:** {p99_latency:.4f} ms\n")
        f.write(f"- **Target (<50ms):** {'PASSED' if avg_latency < 50 else 'FAILED'}\n\n")
        f.write("## Model Storage Optimization\n")
        f.write(f"- **Original Size:** {original_size:.2f} KB\n")
        f.write(f"- **Compressed (v2) Size:** {compressed_size:.2f} KB\n")
        f.write(f"- **Reduction:** {reduction:.2f}%\n")
        f.write(f"- **Compression Method:** joblib (zlib, level 3)\n")
        
    print(f"📄 Report saved to {report_path}")

if __name__ == "__main__":
    benchmark_model()
