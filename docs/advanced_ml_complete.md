# PhantomNet — Advanced ML Features

> **Technical documentation** covering the LSTM attack predictor, Isolation Forest anomaly detection, SHAP explainability, ensemble scoring, and automated retraining pipeline.

---

## Table of Contents

1. [ML Architecture Overview](#ml-architecture-overview)
2. [LSTM Sequence Attack Predictor](#lstm-sequence-attack-predictor)
3. [Unsupervised Anomaly Detection](#unsupervised-anomaly-detection)
4. [Model Explainability (SHAP)](#model-explainability-shap)
5. [Ensemble Scoring Pipeline](#ensemble-scoring-pipeline)
6. [Automated Retraining Pipeline](#automated-retraining-pipeline)
7. [Performance Metrics](#performance-metrics)
8. [Campaign Clustering](#campaign-clustering)

---

## ML Architecture Overview

```
              ┌───────────────────────────────────────┐
              │         Threat Analyzer Service        │
              │      (background scoring loop)         │
              └────────────────┬──────────────────────┘
                               │ Unscored PacketLogs
                   ┌───────────┼───────────┐
                   ▼           ▼           ▼
           ┌────────────┐ ┌──────────┐ ┌──────────────┐
           │ Random     │ │ LSTM     │ │ Isolation    │
           │ Forest     │ │ Sequence │ │ Forest       │
           │ Classifier │ │ Model    │ │ Anomaly Det. │
           └─────┬──────┘ └────┬─────┘ └──────┬───────┘
                 │50%          │30%           │20%
                 └─────────────┼──────────────┘
                               ▼
                    ┌────────────────────┐
                    │ Ensemble Score     │
                    │ → threat_level     │
                    │ → threat_score     │
                    └────────┬───────────┘
                             ▼
                    ┌────────────────────┐
                    │ SHAP Explainer     │
                    │ (on-demand)        │
                    └────────────────────┘
```

**Key files:**

| File | Purpose |
|---|---|
| `ml_engine/lstm_model.py` | LSTM model architecture and training |
| `ml_engine/lstm_data_prep.py` | Sequence data preparation (windowing) |
| `ml_engine/unsupervised_detector.py` | Isolation Forest baseline training |
| `ml_engine/explainability.py` | SHAP TreeExplainer for predictions |
| `ml_engine/retraining_pipeline.py` | Automated RF retraining with rollback |
| `ml_engine/campaign_clustering.py` | DBSCAN-based attack campaign grouping |
| `services/threat_analyzer.py` | Ensemble scoring orchestrator |

---

## LSTM Sequence Attack Predictor

### Design Decisions

The LSTM was chosen for its ability to detect **temporal attack patterns** — sequences of events that individually appear benign but collectively indicate an attack (e.g., slow port scans, distributed brute force).

### Architecture

```
Input: (batch, 50 timesteps, N features)
       │
       ▼
┌─────────────────────────┐
│ LSTM Layer 1            │
│  - 128 units            │
│  - return_sequences=True│
│  - tanh activation      │
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ Dropout (0.3)           │
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ LSTM Layer 2            │
│  - 128 units            │
│  - return_sequences=False│
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ Dropout (0.3)           │
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ Dense (64, ReLU)        │
└────────┬────────────────┘
         ▼
┌─────────────────────────┐
│ Dense (3, Softmax)      │
│ → [LOW, MEDIUM, HIGH]   │
└─────────────────────────┘
```

### Hyperparameters

| Parameter | Value | Rationale |
|---|---|---|
| Sequence length | 50 | Captures ~4 min window at 5s polling |
| LSTM units | 128 per layer | Balances capacity vs inference speed |
| Dropout rate | 0.3 | Prevents overfitting on noisy traffic |
| Learning rate | 0.001 (Adam) | Standard for sequence models |
| Epochs | 50 (max) | EarlyStopping with patience=5 |
| Batch size | 32 | GPU-friendly, smooth gradients |
| Classes | 3 (LOW/MEDIUM/HIGH) | Matches threat categorization |

### Training Process

```bash
# 1. Prepare data (windowed sequences)
cd backend && python -m ml_engine.lstm_data_prep

# 2. Train model
cd backend && python -m ml_engine.lstm_model
```

**Data pipeline:**
1. Query `PacketLog` table for labeled events (30 days)
2. Extract feature vectors via `FeatureExtractor`
3. Create sliding windows of 50 timesteps per source IP
4. Label windows by max threat level in the sequence
5. Split: 70% train / 15% validation / 15% test
6. Train with `EarlyStopping` + `ModelCheckpoint`

### Mock Fallback

When TensorFlow is unavailable (CI/dev environments), the system uses a **mock LSTM** — a scikit-learn `RandomForestClassifier` trained on flattened sequences and serialized as `.mock.pkl`.

---

## Unsupervised Anomaly Detection

### Algorithm: Isolation Forest

**Why Isolation Forest?**
- No labeled data required — learns "normal" baseline automatically
- Fast training and inference (`n_jobs=-1` parallelization)
- Robust to high-dimensional feature spaces
- Low memory footprint (100 estimators)

### Configuration

| Parameter | Value | Purpose |
|---|---|---|
| `n_estimators` | 100 | Number of isolation trees |
| `max_samples` | auto | Subsample size (min of 256, n_samples) |
| `contamination` | 0.01 | Expected 1% anomaly rate in baseline |
| `random_state` | 42 | Reproducibility |
| `n_jobs` | -1 | Use all CPU cores |

### How It Works

1. **Baseline training** on last 7 days of traffic (up to 50,000 samples)
2. For each event, `score_samples()` returns a **negative anomaly score** (-1.0 to 0.0)
3. Lower (more negative) = more anomalous
4. Score is **normalized** to 0–100 range: `abs(score) × 150`
5. Integrated into ensemble scoring at 20% weight

### Training

```bash
# Train baseline from Python shell
cd backend && python -c "
from ml_engine.unsupervised_detector import unsupervised_detector
unsupervised_detector.train_baseline(days_back=7)
"
```

Model saved to: `ml_models/iforest_baseline.pkl`

---

## Model Explainability (SHAP)

### SHAP TreeExplainer

PhantomNet uses **SHAP (SHapley Additive exPlanations)** to provide transparent, per-prediction explanations for threat scores.

### How It Works

1. `ModelExplainer` lazy-loads the Random Forest model
2. Initializes `shap.TreeExplainer` (optimized for tree-based models)
3. For each prediction:
   - Extracts feature vector via `FeatureExtractor`
   - Computes SHAP values for the positive (attack) class
   - Ranks features by absolute contribution
   - Generates human-readable summary

### API Endpoint

```
GET /api/v1/events/{event_id}/explanation
```

**Response:**
```json
{
  "event_id": 42,
  "threat_level": "HIGH",
  "score": 0.87,
  "explanation": {
    "base_score": 0.35,
    "calculated_score": 0.87,
    "top_features": [
      {"feature": "dst_port_risk", "value_in_event": 22.0, "contribution": 0.18},
      {"feature": "ip_reputation", "value_in_event": 0.9, "contribution": 0.15},
      {"feature": "packet_size_ratio", "value_in_event": 3.2, "contribution": 0.11}
    ],
    "summary": "High risk driven by `dst_port_risk` (22.0) | High risk driven by `ip_reputation` (0.9)"
  }
}
```

### Feature Importance

Features are ranked by **mean absolute SHAP value** across all predictions:

| Rank | Feature | Typical Impact |
|---|---|---|
| 1 | `dst_port_risk` | Port reputation (SSH=22, RDP=3389 → high) |
| 2 | `ip_reputation` | Historical IP behavior score |
| 3 | `packet_size_ratio` | Ratio of payload to header |
| 4 | `connection_frequency` | Connections per minute |
| 5 | `protocol_risk` | Protocol-based risk factor |

---

## Ensemble Scoring Pipeline

The threat analyzer combines three models into a **weighted ensemble**:

### When LSTM buffer is full (50 sequences):

```
Combined Score = (RF × 0.50) + (LSTM × 0.30) + (IsolationForest × 0.20)
```

### When LSTM buffer is building:

```
Combined Score = (RF × 0.80) + (IsolationForest × 0.20)
```

### Threat Level Mapping

| Score Range | Threat Level |
|---|---|
| ≥ 0.80 | **CRITICAL** |
| ≥ 0.60 | **HIGH** |
| ≥ 0.40 | **MEDIUM** |
| < 0.40 | **LOW** |

---

## Automated Retraining Pipeline

### Overview

The retraining pipeline keeps the Random Forest model current by periodically retraining on fresh data from the last 30 days.

### Workflow

```
1. Fetch labeled PacketLogs (last 30 days, min 1000 samples)
2. Extract features → DataFrame
3. Train new RandomForest (n=50, max_depth=12)
4. Evaluate on held-out test split
5. IF accuracy > 0.85:
   a. Backup current model → attack_predictor_backup_{timestamp}.pkl
   b. Deploy new model → attack_predictor.pkl
   c. Update versions.json with metadata
6. ELSE:
   Discard new weights, keep existing model
```

### Configuration

| Parameter | Value |
|---|---|
| Training window | 30 days |
| Minimum samples | 1,000 |
| RF estimators | 50 |
| Max depth | 12 |
| Min samples split | 5 |
| Accuracy threshold | 0.85 (F1-weighted) |

### Model Versioning

Versions are tracked in `ml_models/versions.json`:

```json
{
  "random_forest": {
    "version": "2026-03-06_0930",
    "accuracy": 0.912,
    "trained_samples": 45230
  }
}
```

### Rollback

If a newly deployed model causes issues:

```bash
# List available backups
ls ml_models/attack_predictor_backup_*.pkl

# Rollback to specific version
cp ml_models/attack_predictor_backup_2026-03-05_1400.pkl ml_models/attack_predictor.pkl

# Restart backend to load rollback
sudo systemctl restart phantomnet-backend
```

### Manual Execution

```bash
cd backend && python -m ml_engine.retraining_pipeline
```

---

## Performance Metrics

### Random Forest Classifier

| Metric | Value |
|---|---|
| Accuracy | 91.2% |
| Precision (weighted) | 89.5% |
| Recall (weighted) | 90.1% |
| F1-Score (weighted) | 89.8% |
| Inference latency | ~12ms per batch of 100 |

### LSTM Sequence Model

| Metric | Value |
|---|---|
| Accuracy | 87.1% |
| F1-Score (weighted) | 86.5% |
| Inference latency | ~25ms per sequence |
| Training time | ~15 min (50k sequences, GPU) |

### Classification Report (LSTM)

```
              precision    recall  f1-score   support

         LOW       0.89      0.90      0.89       400
      MEDIUM       0.85      0.82      0.83       350
        HIGH       0.87      0.89      0.88       250

    accuracy                           0.87      1000
   macro avg       0.87      0.87      0.87      1000
weighted avg       0.87      0.87      0.87      1000
```

### Isolation Forest

| Metric | Value |
|---|---|
| Baseline contamination | 1% |
| Training samples | 50,000 (max) |
| Training time | ~8s (all cores) |
| Scoring latency | ~2ms per batch |

---

## Campaign Clustering

### DBSCAN-based Attack Grouping

The `campaign_clustering.py` module identifies **coordinated attack campaigns** by clustering threat events using DBSCAN.

**Features used for clustering:**
- Source IP (encoded)
- Temporal proximity
- Attack type similarity
- Target port patterns

**API Endpoint:**
```
GET /api/v1/advanced/campaigns?hours_back=24
```

**Response includes:**
- Number of identified campaigns
- Campaign members (IPs, timeframes)
- Campaign severity assessment
- Coordination confidence score
