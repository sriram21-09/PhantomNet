# PhantomNet ML Architecture — Complete Documentation

**Project:** PhantomNet  
**Version:** v3.0 (Month 3 Final)  
**Date:** March 11, 2026

---

## 1. System Components

PhantomNet's ML subsystem consists of five core components that work together to detect, classify, and respond to network threats in real time.

### 1.1 Honeypot Event Collectors
The frontline data sources that generate raw events for the ML pipeline.

| Collector | Protocol | Path | Purpose |
|---|---|---|---|
| SSH Honeypot | SSH (port 22) | `honeypots/ssh_honeypot.py` | Captures brute-force login attempts, command injection |
| HTTP Honeypot | HTTP (port 80/443) | `honeypots/http_honeypot.py` | Web exploit probes, directory traversal, SQLi attempts |
| FTP Honeypot | FTP (port 21) | `honeypots/ftp_honeypot.py` | Credential stuffing, data exfiltration attempts |
| SMTP Honeypot | SMTP (port 25) | `honeypots/smtp_honeypot.py` | Spam relay, phishing delivery attempts |
| AsyncSSH Honeypot | SSH (async) | `honeypots/asyncssh_honeypot.py` | High-concurrency SSH attack capture |

### 1.2 Feature Extraction Pipeline
Transforms raw honeypot events into a normalized 15-feature vector for model inference.

- **Source code:** `ai-ml-dev/` pipeline scripts
- **Specification:** `docs/FEATURE_EXTRACTION_SPEC_FINAL.md` (frozen)
- **Primary data source:** `packet_logs` table
- **Secondary enrichment:** `ssh_logs`, `http_logs`, `ftp_logs`, `asyncssh_logs`
- **Output:** Standardized feature vector (mean=0, variance=1 via `StandardScaler`)

### 1.3 ML Models
Three distinct model types serve different detection goals:

| Model | Type | File | Purpose |
|---|---|---|---|
| Isolation Forest v1 | Unsupervised Anomaly Detection | `models/isolation_forest_v1.pkl` | Baseline anomaly detection |
| Isolation Forest v2 (Optimized) | Unsupervised Anomaly Detection | `models/isolation_forest_optimized_v2.pkl` | Production-optimized with tuned hyperparameters |
| LSTM Attack Predictor | Supervised Sequence Model | `ml_models/lstm_attack_predictor.h5` | Temporal pattern recognition for attack prediction |
| Random Forest Classifier | Supervised Classification | `backend/ai_engine/model_rf.pkl` | Multi-class threat type classification |

### 1.4 Model Registry & Versioning
Centralized model lifecycle management built in Week 11.

- **Registry class:** `ml/registry/model_registry.py` → `ModelRegistry`
- **Version scheme:** `v{major}.{minor}.{patch}` (see `docs/model_versioning.md`)
- **Metadata index:** `ml_models/registry/models_index.json`
- **Status lifecycle:** `Staging` → `Production` → `Archived`
- **Comparison engine:** `ml/evaluation/model_comparator.py` → `ModelComparator`
- **Rollback tests:** `ml/tests/test_rollback.py` (3 scenarios validated)

### 1.5 Inference Service (Month 4 — Planned)
REST API for real-time threat classification.

- **Framework:** FastAPI (async)
- **Endpoints:** 6 routes under `/api/v2/inference/` (see `docs/ml_inference_api_spec.md`)
- **Architecture:** `docs/ml_inference_architecture.png`

---

## 2. Data Flow

The end-to-end data flow from raw network events to actionable threat responses:

```
┌─────────────────┐
│  Network Traffic │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│    Honeypot Collectors      │
│  (SSH, HTTP, FTP, SMTP)     │
└────────────┬────────────────┘
             │ Raw events (JSON)
             ▼
┌─────────────────────────────┐
│  Feature Extraction Pipeline │
│  15 features extracted       │
│  StandardScaler applied      │
└────────────┬────────────────┘
             │ Feature vector [15-dim]
             ▼
┌─────────────────────────────┐
│     ML Inference Engine      │
│  ┌───────────────────────┐  │
│  │ Isolation Forest (v2) │  │ ← Primary: anomaly score
│  ├───────────────────────┤  │
│  │ LSTM Predictor        │  │ ← Temporal: attack prediction
│  ├───────────────────────┤  │
│  │ Random Forest (RF)    │  │ ← Classification: threat type
│  └───────────────────────┘  │
└────────────┬────────────────┘
             │ Prediction result
             ▼
┌─────────────────────────────┐
│   Threat Classification     │
│  • benign / malicious       │
│  • confidence score (0–1)   │
│  • threat_type label        │
└────────────┬────────────────┘
             │
     ┌───────┴────────┐
     ▼                ▼
┌──────────┐  ┌───────────────┐
│Dashboard │  │  Automated    │
│(React UI)│  │  Response     │
│WebSocket │  │  Engine       │
└──────────┘  │  (IP block,   │
              │   alerting)   │
              └───────────────┘
```

### Data Flow Details

| Stage | Input | Output | Latency Target |
|---|---|---|---|
| Event Collection | Raw network packets | JSON event records | <10ms |
| Feature Extraction | JSON event | 15-dim feature vector | <20ms |
| Model Inference | Feature vector | Classification + confidence | <100ms (p95) |
| Response Action | Classification | Block/alert/log | <50ms |
| **End-to-end** | **Raw packet** | **Response action** | **<200ms** |

---

## 3. Model Versioning

### Versioning Scheme
All models follow **Semantic Versioning** adapted for ML artifacts: `v{MAJOR}.{MINOR}.{PATCH}`

| Version Component | When to Increment | Example |
|---|---|---|
| **MAJOR** | Architecture change (e.g., RF → LSTM), breaking feature schema changes | `v1.0.0` → `v2.0.0` |
| **MINOR** | New features added, significant retrain on larger data, new outputs | `v1.0.0` → `v1.1.0` |
| **PATCH** | Minor retrain, bug fix, hyperparameter tweak | `v1.1.0` → `v1.1.1` |

### Registry Operations

```python
from ml.registry.model_registry import ModelRegistry

registry = ModelRegistry()

# Register a new model
version = registry.register_model(
    model_path="models/new_model.pkl",
    model_name="IsolationForest",
    bump_type="minor",
    metadata={
        "metrics": {"accuracy": 0.91, "f1_score": 0.89},
        "features": ["packet_length", "burst_rate", "..."],
        "hyperparameters": {"n_estimators": 200}
    }
)

# Promote to production
registry.update_model_status(version, "Production")

# Retrieve production model
prod = registry.get_model_by_status("Production")
```

### Rollback Procedures
- **Automated:** Evaluation gate in `ModelComparator` blocks staging models that drop >5% below production accuracy.
- **Manual:** Operator archives the failing model and restores the previous production version via `update_model_status()`.
- **Full guide:** `docs/model_rollback_guide.md`

---

## 4. Directory Structure

```
PhantomNet/
├── ai-ml-dev/                      # Training scripts
│   ├── train_isolation_forest.py
│   ├── tune_isolation_forest.py
│   ├── benchmark_model.py
│   └── generate_plots.py
├── ml/                             # ML infrastructure (Week 11+)
│   ├── registry/
│   │   ├── __init__.py
│   │   └── model_registry.py       # ModelRegistry class
│   ├── evaluation/
│   │   ├── __init__.py
│   │   └── model_comparator.py     # ModelComparator class
│   └── tests/
│       ├── __init__.py
│       └── test_rollback.py        # Rollback test suite
├── models/                         # Trained model artifacts
│   ├── scaler_v1.pkl
│   ├── isolation_forest_v1.pkl
│   ├── isolation_forest_optimized_v2.pkl
│   └── isolation_forest_optimized.pkl
├── ml_models/                      # LSTM models & registry
│   ├── lstm_attack_predictor.h5
│   ├── lstm_training_data.pkl
│   └── registry/                   # Model registry index
│       └── models_index.json
├── backend/
│   └── ai_engine/
│       └── model_rf.pkl            # Random Forest classifier
└── honeypots/                      # Event collectors
    ├── ssh_honeypot.py
    ├── http_honeypot.py
    ├── ftp_honeypot.py
    ├── smtp_honeypot.py
    └── asyncssh_honeypot.py
```
