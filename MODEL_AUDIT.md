# PhantomNet Model Training, Evaluation & Benchmarking Audit

**Document:** Model Architecture & Evaluation Forensic Audit (`MODEL_AUDIT.md`)  
**Auditor:** Lead ML & Reproducibility Auditor  
**Date:** 2026-10-01  
**Project:** PhantomNet  
**Status:** COMPLETE — REMEDIATION SPECIFIED  

---

## 1. Inventory of Model Architectures & Training Pipelines

The PhantomNet codebase contains multiple training pipelines developed across various project stages:

| Training Script | Target Model(s) | Dataset Source | Feature Set | Stated Purpose / Claim | Audited Finding |
|---|---|---|---|---|---|
| `experiments/reproduce_paper.py` | RF + IF Ensemble | `labeled_events_v2_enhanced.csv` | 12 Behavioral | Reproduces paper Section V.G | **SYNTHETIC OVERFIT:** 100% metrics across all folds due to 3 zero-overlap features. |
| `backend/scripts/unified_evaluation.py` | RF + XGB + IF | `labeled_events_15d_unified.csv` | 15 Network Flow | Single source of truth for V3.0 | **LEAKAGE CONTAMINATION:** Trains on `malicious_flag_ratio` (100% separable) and `threat_score`. |
| `backend/ml/train_enhanced_model.py` | RF Classifier | `labeled_events_v2_enhanced.csv` | 12 Behavioral | Retraining attack classifier | Hardcodes canned impact report claiming "Target improvement 2-5% achieved". |
| `backend/ml/train_model.py` | Isolation Forest | SQLite DB / Mock Traffic | 3 Minimal Ports (`src_port`, `dst_port`, `proto`) | Operational baseline | Generates fake normal/attack data if DB empty; trains on only 3 unscaled ports. |
| `backend/ai_engine/train_final.py` | RF Classifier | Synthetic generator | 6 Dimensions (Netflow + IP) | Reality check model | Hardcodes private subnet `192.168.29.49` into training profiles. |
| `backend/ml/run_training.py` | RF Classifier | `week6_test_events.csv` | 1 Dimension (`payload_length`) | Early Week 6 baseline | Single-feature classifier on payload length with MLflow logging. |
| `backend/ml_engine/unsupervised_detector.py` | Isolation Forest | SQLite PacketLog history | 15 Dimensions | Dynamic runtime baseline | Unsupervised training on live DB; scales raw outputs arbitrarily (`abs(s) * 1.5`). |

---

## 2. Forensic Evaluation of Model Checkpoints

### 2.1 The Deployed Production Checkpoint: `AttackClassifier_Enhanced_v1.0.0.pkl`
- **Location:** `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl`
- **Architecture:** `RandomForestClassifier(n_estimators=500, max_depth=20, random_state=42)`
- **Expected Features:** 12 features (`FeatureExtractorV2`)
- **Empirical Test:** Evaluated against `labeled_events_v2_enhanced.csv` (5,000 samples) in `run_publication_validation.py`:
  - `Accuracy: 0.6976`, `Balanced Accuracy: 0.5000`
  - `Precision: 0.0000`, `Recall: 0.0000`, `F1-Score: 0.0000`
  - Confusion Matrix: $\begin{bmatrix} 3488 & 0 \\ 1512 & 0 \end{bmatrix}$ (Predicts 100% Benign).
- **Forensic Diagnosis:** The serialized production model in the registry is completely broken. It classifies every incoming vector as class `0` (benign), achieving zero attack recall.

### 2.2 The Retrained Reproduction Model: `reproduce_paper.py`
- **Architecture:** `RandomForestClassifier(n_estimators=500, max_depth=20, random_state=42)`
- **Dataset:** `labeled_events_v2_enhanced.csv`
- **Reported Metrics:** `Accuracy = 1.0000`, `Precision = 1.0000`, `Recall = 1.0000`, `F1 = 1.0000`.
- **Confidence Intervals:** Bootstrap $B=1,000$ yields $[100.0\%, 100.0\%]$ accuracy CI and $[1.0000, 1.0000]$ F1 CI.
- **Forensic Diagnosis:** Zero variance and perfect metrics occur because the decision tree splits on `avg_command_length == 24.0` or `payload_entropy == 4.0535`, perfectly isolating the static benign string.

### 2.3 The Leakage-Removed Behavioral Benchmark
When features with trivial separability (`avg_command_length`, `payload_entropy`, `payload_to_cmd_ratio`, `ua_diversity`) are removed:
- **Remaining Features (8):** `command_count`, `shell_escape_count`, `directory_traversal_count`, `failed_login_count`, `interaction_interval_var`, `persistence_score`, `lateral_movement_index`, `sensitive_file_count`.
- **Evaluated Performance (Stratified 80/20 Test Split):**
  - Accuracy: **98.20%**
  - Precision: **99.64%**
  - Recall: **94.37%**
  - F1-Score: **0.9693**
  - False Positive Rate: **0.14%** (1 / 698)
  - False Negative Rate: **5.63%** (17 / 302)
- **Key Takeaway:** When trivial artifacts are stripped away, the model achieves a genuine, realistic performance profile with measurable error rates (5.63% missed attacks).

---

## 3. Discrepancies in Ensemble Weighting Specifications

The ensemble blending weights between the supervised classifier (RF) and unsupervised anomaly detector (IF) vary wildly across the repository without reconciliation:

1. **`experiments/reproduce_paper.py:L46-47`:**
   $$S_{\text{ensemble}} = 0.70 \cdot P_{\text{RF}} + 0.30 \cdot S_{\text{IF}}$$
2. **`backend/scripts/unified_evaluation.py:L284-300` & `MASTER_FINAL_PROJECT_REPORT.md:L368`:**
   $$S_{\text{ensemble}} = 0.85 \cdot P_{\text{RF}} + 0.15 \cdot S_{\text{IF}}$$
   (Derived from grid search on `labeled_events_15d_unified.csv`).
3. **`backend/services/threat_analyzer.py:L298-307`:**
   - When sequence buffer is full (LSTM enabled):
     $$S_{\text{composite}} = 0.50 \cdot P_{\text{RF}} + 0.30 \cdot S_{\text{LSTM}} + 0.20 \cdot S_{\text{IF}}$$
   - When sequence buffer is incomplete:
     $$S_{\text{composite}} = 0.80 \cdot P_{\text{RF}} + 0.20 \cdot S_{\text{IF}}$$
4. **`README.md:L218-220`:**
   Documents a 4-signal weighted playbook confidence formula ($0.35 \times S_{\text{cluster}} + 0.35 \times \bar{S}_{\text{ML}} + 0.20 \times D_{\text{IOC}} + 0.10 \times B_{\text{protocol}}$).

**Verdict:** The system lacks a unified mathematical justification for its ensemble blending. In production, RF probability dominates almost entirely, and IF contributes negligible signal due to high variance and uncalibrated anomaly score ranges.

---

## 4. LSTM Temporal Sequence Predictor Reality

- **Claim:** PhantomNet utilizes an LSTM deep learning model (`backend/ml_engine/lstm_model.py`) to forecast multi-stage attack evolution and predict attacker intent.
- **Code Audit:**
  - `ml_models/lstm_attack_predictor.h5` is a **24-byte mock file**.
  - `threat_analyzer.py:L104` generates dummy zero-vectors: `vec = [0.0] * len(self.lstm_feature_cols)`.
  - When invoked, if the mock Keras model fails to load, it falls back to a dummy unweighted score of `0.0`.
- **Verdict:** The deep learning temporal prediction component is an unverified prototype and cannot be cited as a functional empirical contribution in publication materials without genuine training and validation.

---

## 5. Remediation Plan for Model Training & Validation

1. **Defensible Benchmark Model:**
   - Train on the remediated 12-dimensional, zero-leakage dataset (DS-REMED).
   - Use `RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_leaf=2, class_weight='balanced', random_state=42)`.
   - Constrain tree depth to avoid leaf memorization.
2. **Standardized Pipeline Serialization:**
   - Persist models as `sklearn.pipeline.Pipeline` objects containing fitted `StandardScaler` + `RandomForestClassifier`.
   - Update `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl` with the verified, functional pipeline.
3. **Empirical Ensemble Calibration:**
   - Calibrate Isolation Forest decision scores using isotonic regression or Platt scaling to output legitimate probabilities $P(\text{anomaly}) \in [0, 1]$.
   - Grid search optimal weights on validation folds with objective: $\max (\text{Recall})$ subject to $\text{FPR} \le 2.0\%$.
4. **Statistical Evaluation Protocols:**
   - Run 10-fold Stratified Cross-Validation reporting mean $\pm$ std for Accuracy, Balanced Accuracy, Precision, Recall, F1, and ROC-AUC.
   - Compute non-degenerate 95% bootstrap confidence intervals ($B=1,000$).
