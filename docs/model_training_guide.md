# Model Training Guide

**Project:** PhantomNet  
**Version:** v2.0 (Updated Month 3 — Week 11)  
**Date:** March 11, 2026

---

## 1. Prerequisites

- **Python:** 3.8+
- **Dependencies:** `pip install -r requirements.txt`
- **Dataset:** `data/training_dataset.csv`
- **GPU (optional):** Required only for LSTM model training (`ml_models/lstm_attack_predictor.h5`)

---

## 2. Step-by-Step Training Process

### Step 1: Prepare the Dataset
Ensure the training dataset is available and clean.

```bash
# Verify dataset exists
ls data/training_dataset.csv

# Check for data quality issues (optional)
python -c "
import pandas as pd
df = pd.read_csv('data/training_dataset.csv')
print(f'Rows: {len(df)}, Columns: {len(df.columns)}')
print(f'Missing values:\n{df.isnull().sum()}')
print(f'Class distribution:\n{df[\"is_malicious\"].value_counts()}')
"
```

### Step 2: Train Baseline Isolation Forest Model
Train the anomaly detection model with default parameters.

```bash
python ai-ml-dev/train_isolation_forest.py
```

**Outputs:**
| Artifact | Path | Description |
|---|---|---|
| Baseline Model | `models/isolation_forest_v1.pkl` | Untunded Isolation Forest |
| Feature Scaler | `models/scaler_v1.pkl` | Fitted `StandardScaler` for the 15-feature vector |

### Step 3: Hyperparameter Tuning (Recommended)
Optimize the Isolation Forest for better F1-score using grid search.

```bash
python ai-ml-dev/tune_isolation_forest.py
```

**Outputs:**
| Artifact | Path | Description |
|---|---|---|
| Optimized Model | `models/isolation_forest_optimized.pkl` | Tuned Isolation Forest |
| Tuning Report | `docs/hyperparameter_tuning.md` | Best parameters and search results |

### Step 4: Benchmark & Compress for Production
Measure inference latency and create a production-optimized model.

```bash
python ai-ml-dev/benchmark_model.py
```

**Outputs:**
| Artifact | Path | Description |
|---|---|---|
| Production Model | `models/isolation_forest_optimized_v2.pkl` | Compressed, optimized for inference speed |
| Benchmark Report | `docs/performance_benchmark.md` | Latency and throughput metrics |

### Step 5: Generate Performance Visualizations
Create plots for model evaluation.

```bash
python ai-ml-dev/generate_plots.py
```

**Outputs:**
| Artifact | Path |
|---|---|
| Confusion Matrix | `reports/model_performance/confusion_matrix.png` |
| ROC Curve | `reports/model_performance/roc_curve.png` |

### Step 6: Register Model in the Registry
After training and benchmarking, register the final model in the `ModelRegistry` for version tracking.

```python
from ml.registry.model_registry import ModelRegistry

registry = ModelRegistry()
version = registry.register_model(
    model_path="models/isolation_forest_optimized_v2.pkl",
    model_name="IsolationForest_Anomaly",
    bump_type="minor",  # or "major" for architecture changes
    metadata={
        "metrics": {"accuracy": 0.91, "f1_score": 0.89, "precision": 0.88, "recall": 0.93},
        "features": [
            "packet_length", "protocol_encoding", "source_ip_event_rate",
            "destination_port_class", "threat_score", "malicious_flag_ratio",
            "attack_type_frequency", "time_of_day_deviation", "burst_rate",
            "packet_size_variance", "honeypot_interaction_count",
            "session_duration_estimate", "unique_destination_count",
            "rolling_average_deviation", "z_score_anomaly"
        ],
        "hyperparameters": {"n_estimators": 200, "contamination": 0.05, "max_features": 1.0}
    }
)
print(f"Registered as: {version}")

# Promote to Production
registry.update_model_status(version, "Production")
```

---

## 3. Model Artifacts Reference

| Filename | Description | Required At |
|---|---|---|
| `models/scaler_v1.pkl` | StandardScaler (fitted) | Inference time — must load before prediction |
| `models/isolation_forest_optimized_v2.pkl` | Primary production model | Inference time |
| `ml_models/lstm_attack_predictor.h5` | LSTM sequence model | Inference time (optional) |
| `backend/ai_engine/model_rf.pkl` | Random Forest classifier | Inference time (optional) |
| `ml_models/registry/models_index.json` | Registry metadata index | Model management |

---

## 4. Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|---|---|---|
| `FileNotFoundError: data/training_dataset.csv` | Dataset not in expected location | Verify the dataset is downloaded and placed in `data/` |
| `ModuleNotFoundError: No module named 'sklearn'` | Missing dependencies | Run `pip install -r requirements.txt` |
| `ImportError: ml.registry...` | Running script directly instead of as module | Use `python -m ai-ml-dev.train_isolation_forest` or run from project root |
| Low accuracy (<0.80) on evaluation | Insufficient or imbalanced training data | Check class distribution; consider SMOTE oversampling or adjusting `contamination` parameter |
| Model file too large (>100MB) | Uncompressed model serialization | Run `benchmark_model.py` to generate compressed production model |
| `MemoryError` during LSTM training | Insufficient RAM/VRAM | Reduce batch size or use a smaller sequence length |
| Scaler mismatch at inference | Training/inference scaler versions differ | Always use the same `scaler_v1.pkl` that was fitted during training |

### Performance Optimization Tips
1. **Feature selection:** Drop features with importance <0.02 (see `docs/ml_features_v2.md`) if inference speed is critical.
2. **Batch inference:** Process multiple events together for higher throughput.
3. **Model quantization:** For LSTM models, consider TensorFlow Lite conversion.
4. **Caching:** Cache `StandardScaler` in memory — avoid reloading from disk per request.

---

## 5. Retraining Schedule

| Trigger | Bump Type | Frequency |
|---|---|---|
| Weekly drift monitoring shows accuracy drop >3% | `patch` | Weekly |
| New feature added to the extraction pipeline | `minor` | As needed |
| New model architecture adopted | `major` | Quarterly |
| Post-incident retraining with new attack samples | `patch` or `minor` | As needed |
