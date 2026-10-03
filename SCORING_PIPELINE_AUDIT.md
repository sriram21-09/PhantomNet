# PhantomNet Threat Scoring Service & Pipeline Forensic Audit

**Document:** Threat Scoring Pipeline Forensic Audit (`SCORING_PIPELINE_AUDIT.md`)  
**Auditor:** Lead ML & Reproducibility Auditor  
**Date:** 2026-10-01  
**Project:** PhantomNet  
**Status:** COMPLETE — REMEDIATION SPECIFIED  

---

## 1. Overview of Scoring Pipeline Components

The threat scoring subsystem consists of two interlocking services:
1. **`backend/ml/threat_scoring_service.py` (`score_threat` & `score_threat_batch`):** The synchronous request-response scoring engine invoked by the REST API and ingestion routes.
2. **`backend/services/threat_analyzer.py` (`ThreatAnalyzerService`):** A background polling worker that processes unscored `PacketLog` records from the SQLite database, combines RF scores with unsupervised anomaly scores and mock LSTM outputs, and updates database records.

---

## 2. Forensic Findings in `threat_scoring_service.py`

### 2.1 Missing Module Import: `import os`
- **Location:** `backend/ml/threat_scoring_service.py:L21-24`
- **Code:**
  ```python
  redis_client = redis.Redis(
      host=os.getenv("REDIS_HOST", "localhost"),
      port=int(os.getenv("REDIS_PORT", "6379")),
      ...
  )
  ```
- **Finding:** `os` is never imported at the module header. When this block runs, Python raises a `NameError: name 'os' is not defined`.
- **Silent Failure:** Because lines 20–35 are wrapped in `try...except Exception:`, the `NameError` is caught, forcing `REDIS_AVAILABLE = False`. Redis caching is permanently disabled at runtime.

### 2.2 Feature Vector Alignment Collision & Slicing
- **Location:** `backend/ml/threat_scoring_service.py:L155-168`
- **Code:**
  ```python
  if hasattr(model, "n_features_in_") and isinstance(getattr(model, "n_features_in_", None), int):
      n_feat = model.n_features_in_
      feat_names = getattr(model, "feature_names_in_", None)
      if feat_names is not None and len(avail_cols) == n_feat:
          X_input = feature_vector[avail_cols]
      else:
          X_input = feature_vector.iloc[:, :n_feat].values
  ```
- **Finding:** When the model in the registry expects 12 features, and the runtime extractor yields 15 features, the service blindly slices the first 12 columns. Network packet sizes, rates, and IP counts are fed into model slots expecting command lengths and payload entropies.

### 2.3 Bypass of Feature Scaling
- The service passes unscaled raw data `X_input` directly to `model.predict_proba(X_input)` without passing through `feature_scaler_v2.pkl` or `scaler_unified.pkl`.

### 2.4 Caching Thread-Safety & Mutation
- When Redis is disabled, the service falls back to a global dictionary `_LOCAL_PRED_CACHE`.
- In a multi-threaded server (FastAPI/Uvicorn with multiple workers or threads), dictionary access without locks risks race conditions during concurrent cache writes.

---

## 3. Forensic Findings in `threat_analyzer.py`

### 3.1 Divergent Threat Level Thresholds
A severe discrepancy exists between the classification thresholds in `threat_scoring_service.py` and `threat_analyzer.py`:

| Threat Level | `threat_scoring_service.py` | `threat_analyzer.py` | `MASTER_FINAL_PROJECT_REPORT.md` |
|---|---|---|---|
| **CRITICAL** | $\text{score} > 0.90$ (Default) | $\text{score} \ge 0.80$ | $\text{score} \ge 0.80$ |
| **HIGH** | $\text{score} > 0.75$ | $\text{score} \ge 0.60$ | $\text{score} \ge 0.60$ |
| **MEDIUM** | $\text{score} > 0.40$ | $\text{score} \ge 0.40$ | $\text{score} \ge 0.40$ |
| **LOW** | $\text{score} \le 0.40$ | $\text{score} < 0.40$ | $\text{score} < 0.40$ |

- **Impact:** An event with threat score $0.65$ is classified as **`MEDIUM`** by `threat_scoring_service.py`, but classified as **`HIGH`** by `threat_analyzer.py`.
- Because `log.is_malicious = result.threat_level in ["HIGH", "CRITICAL"]`, this threshold conflict causes inconsistent downstream security actions depending on whether the event was evaluated synchronously or asynchronously.

### 3.2 Arbitrary Weight Composition Formulas
`threat_analyzer.py:L298-307` implements ad-hoc weighted formulas:
- With LSTM: $0.50 \times \text{RF} + 0.30 \times \text{LSTM} + 0.20 \times \text{Unsupervised}$.
- Without LSTM: $0.80 \times \text{RF} + 0.20 \times \text{Unsupervised}$.
Neither formula is grounded in cross-validated grid search or published documentation. Furthermore, because LSTM outputs are ungrounded zeros, the LSTM formula effectively depresses true threat scores by multiplying RF by only $0.50$.

---

## 4. Remediation Plan for the Scoring Pipeline

1. **Bug Fixes:**
   - Add `import os` to `threat_scoring_service.py`.
   - Implement thread-safe local cache locking (`threading.Lock`) for `_LOCAL_PRED_CACHE`.
2. **Unified Threshold Configuration:**
   - Define a single source of truth for threat levels and decisions in `backend/ml/config/thresholds.py`:
     - `CRITICAL`: $\ge 0.80$
     - `HIGH`: $\ge 0.60$
     - `MEDIUM`: $\ge 0.40$
     - `LOW`: $< 0.40$
3. **Pipeline Coupling:**
   - Ensure `model` is a `Pipeline` containing `StandardScaler()`. Both `threat_scoring_service.py` and `threat_analyzer.py` must pass standard 12D vectors without manual slicing.
4. **Calibrated Ensemble Scoring:**
   - Remove dummy LSTM weights. Use mathematically calibrated weights ($0.85 \times \text{RF} + 0.15 \times \text{IF}$) consistently across both synchronous and background workers.
