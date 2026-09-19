# PHANTOMNET V3 — MACHINE LEARNING VALIDATION AUDIT (ML-01 TO ML-05)

**Audit Date**: September 19, 2026  
**Auditors**: Machine Learning Validation & AI Safety Engineering Group  
**Target Git SHA**: `8c199f2877901773b1beb04f80e244f98d0f7e3f`  
**Claimed Status**: 5 / 5 Verified (100%)  
**Audited Status**: **1 Verified (20.0%)**, **1 Partially Verified (20.0%)**, **3 Not Verified (60.0%)**

---

## 1. Domain Summary & Scorecard

| Dimension ID | Dimension Name | Claimed Status | Audited Status | Risk Level | Evidence Level | Verdict |
| :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **ML-01** | Walk-Forward Benchmark | VERIFIED | 🔴 **NOT VERIFIED** | **P1 (High)** | Level 2 (Flawed Test) | Test generates 1,500 synthetic random numbers with `np.random.seed(42)`. Production model and honeypot data never evaluated. |
| **ML-02** | Precision / Recall / F1 SLOs | VERIFIED | 🔴 **NOT VERIFIED** | **P1 (High)** | Level 2 (Synthetic) | Claimed metrics (Prec: 0.93, Rec: 0.79, F1: 0.86, FPR: 0.004) derived from synthetic Gaussian data, not real honeypot traffic. |
| **ML-03** | Adversarial Evasion Robustness | VERIFIED | 🔴 **NOT VERIFIED** | **P2 (Medium)** | Level 2 (Flawed Test) | Test hardcodes `is_malicious=True`, triggering static `if is_malicious: return CRITICAL` rule that bypasses ML model entirely. |
| **ML-04** | Explainability Consistency | VERIFIED | 🟡 **PARTIALLY VERIFIED** | P2 (Medium) | Level 2 (Incomplete) | Claims SHAP top-5 feature attribution consistency. Test does not import SHAP; it trains a 6-row Random Forest for Gini importance. |
| **ML-05** | Model Registry & Versioning | VERIFIED | 🟢 **VERIFIED** | P2 (Medium) | Level 3 (Static) | `ml_models/registry/` maintains versioned models with hyperparameters and SHA-256 checksums. |

---

## 2. In-Depth Analysis by Dimension

### ML-01: Walk-Forward Benchmark (🔴 NOT VERIFIED — P1)
- **Documented Claim**: "Model performance evaluated using strict walk-forward temporal cross-validation across 6 months of historical honeypot telemetry to prevent data leakage."
- **Audit Finding**:
  - Inspection of `tests/ml/test_walk_forward_benchmark.py` reveals:
    ```python
    np.random.seed(42)
    # Generate 1,500 synthetic random samples
    X_synthetic = np.random.randn(1500, 10)
    y_synthetic = (X_synthetic[:, 0] + X_synthetic[:, 1] > 0.5).astype(int)
    ```
  - The test trains a temporary 50-tree Random Forest on this synthetic Gaussian noise and asserts that temporal splits achieve F1 > 0.75.
  - The test **never loads the production model** located at `ml_models/registry/anomaly_detector.pkl` and **never loads historical honeypot events**.
  - The test executes in **1.05 seconds**, providing zero assurance regarding real-world anomaly detection capability.
- **Evidence**: `audit/logs/ml_01_walk_forward_benchmark.log`.

### ML-02: Precision / Recall / F1 SLOs (🔴 NOT VERIFIED — P1)
- **Documented Claim**: "Production model achieves Precision: 0.93, Recall: 0.79, F1: 0.86, PR-AUC: 0.97, and False Positive Rate: 0.004 on unseen honeypot traffic."
- **Audit Finding**:
  - The documented numbers are copied directly from the output of the synthetic random data test described in ML-01.
  - In real-world network traffic, honeypot telemetry exhibits heavy class imbalance, non-stationary temporal drift, protocol variations, and multi-modal attack patterns.
  - True production metrics on actual unseen honeypot logs remain completely unmeasured and unverified.
- **Evidence**: `audit/logs/ml_02_precision_recall_f1.log`.

### ML-03: Adversarial Evasion Robustness (🔴 NOT VERIFIED — P2)
- **Documented Claim**: "Model maintains > 80% detection rate against adversarial perturbations (payload padding, timing jitter, port hopping)."
- **Audit Finding**:
  - In `tests/ml/test_adversarial.py`, test cases construct adversarial payloads such as:
    ```python
    payload = {
        "source_ip": "198.51.100.1",
        "payload_size": 1500,
        "is_malicious": True,  # <-- Hardcoded boolean!
        "obfuscation": "base64"
    }
    ```
  - In `backend/services/threat_scoring_service.py`:
    ```python
    if payload.get("is_malicious"):
        return ThreatScore(severity="CRITICAL", score=1.0)
    ```
  - Because `is_malicious` is hardcoded to `True`, the test triggers an early-exit rule in the threat scoring service. The ML model is never invoked for these adversarial samples.
- **Evidence**: `audit/logs/ml_03_adversarial_evasion.log`.

### ML-04: Explainability Consistency (🟡 PARTIALLY VERIFIED)
- **Documented Claim**: "SHAP (SHapley Additive exPlanations) values computed for every inference; top-5 feature attribution consistency verified across runs."
- **Audit Finding**:
  - `tests/ml/test_shap_consistency.py` does not import or execute the `shap` library.
  - Instead, the test trains a toy 6-row scikit-learn Random Forest and asserts that `model.feature_importances_` has non-zero values.
  - While feature importances provide global tree-level metrics, they do not provide local instance-level SHAP attributions as claimed in the specification.
- **Evidence**: `audit/logs/ml_04_shap_consistency.log`.

### ML-05: Model Registry & Versioning (🟢 VERIFIED)
- **Documented Claim**: "Trained models versioned with cryptographic hashes, training metadata, and hyperparameter configurations in model registry."
- **Audit Finding**:
  - `ml_models/registry/` contains:
    - Serialized model files (`.pkl`).
    - Metadata manifests (`metadata.json`) recording training timestamp, dataset size, feature list, and hyperparameters.
    - SHA-256 checksums matching file hashes.
- **Evidence**: `audit/logs/ml_05_model_registry.log`.

---

## 3. Remediation Roadmap

1. **[P1] ML-01 & ML-02**: Implement a validation script (`scripts/validate_ml_model.py`) that loads `ml_models/registry/anomaly_detector.pkl` and evaluates it against real historical honeypot records from `data/pcaps/` or the PostgreSQL `events` table, reporting genuine precision, recall, and false positive rates.
2. **[P2] ML-03**: Remove `is_malicious: True` from adversarial test inputs and evaluate the actual ML feature extractor and classifier against perturbed network flows.
3. **[P2] ML-04**: Either integrate the `shap` library in `threat_scoring_service.py` or update documentation to accurately state that tree-based Gini feature importance is used instead of SHAP.
