# Model Training Guide

## 1. Prerequisites
- Python 3.8+
- Dependencies installed: `pip install -r requirements.txt`
- Dataset available at `data/training_dataset.csv`

## 2. Training Pipeline
The training pipeline consists of three main stages: Training, Tuning, and Evaluation.

### Step 1: Train Baseline Model
To train a standard Isolation Forest model with default parameters:
```bash
python ai-ml-dev/train_isolation_forest.py
```
**Output:**
- Model: `models/isolation_forest_v1.pkl`
- Scaler: `models/scaler_v1.pkl`

### Step 2: Hyperparameter Tuning (Optional but Recommended)
To optimize model parameters for better F1-score:
```bash
python ai-ml-dev/tune_isolation_forest.py
```
**Output:**
- Optimized Model: `models/isolation_forest_optimized.pkl`
- Tuning Report: `docs/hyperparameter_tuning.md`

### Step 3: Benchmarking & Optimization
To measure latency and create a compressed production model:
```bash
python ai-ml-dev/benchmark_model.py
```
**Output:**
- Production Model: `models/isolation_forest_optimized_v2.pkl`
- Benchmark Report: `docs/performance_benchmark.md`

### Step 4: Generate Performance Plots
To visualize model performance:
```bash
python ai-ml-dev/generate_plots.py
```
**Output:**
- Confusion Matrix: `reports/model_performance/confusion_matrix.png`
- ROC Curve: `reports/model_performance/roc_curve.png`

## 3. Model Artifacts
| Filename | Description | Usage |
|----------|-------------|-------|
| `scaler_v1.pkl` | StandardScaler object | Required for preprocessing input data |
| `isolation_forest_optimized_v2.pkl` | Compressed Optimized Model | Primary model for production inference |
| `training_config.json` | Configuration file | Metadata about training parameters |

## 4. Troubleshooting
- **Missing Dataset:** Ensure `data/training_dataset.csv` exists.
- **Import Errors:** Run from the project root (`c:\Users\shalo\PhantomNet`).
