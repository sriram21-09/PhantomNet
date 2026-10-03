# PHANTOMNET ML-2 CANONICAL THREAT-SCORING SPECIFICATION

**Document Version:** 1.0.0  
**Phase:** Master Audit Phase ML-2 (Remediation)  
**Status:** CANONICAL PRODUCTION & EXPERIMENTAL SPECIFICATION  
**Authoritative SHA:** `686e880a240a671390e68eb42f24ece21156c1f2` (Branch: `fix/full-codebase-audit-remediation`)  
**Scope:** Repository-wide Threat-Scoring Contract, Preprocessing, Feature Compatibility, Calibration, and Severity Classification.

---

## 1. Scope & Objective

This specification establishes the **SINGLE authoritative source of truth** for cyber threat scoring across the entire PhantomNet repository, resolving all architecture drifts and conflicting implementations identified in Phase ML-1:

1. **Elimination of Obsolete Weights:** The legacy `0.70 RF / 0.30 IF` formulation in `backend/ml/models/ensemble_predictor.py` is permanently superseded and rejected.
2. **Harmonization of Scoring Semantics:** Single-event inference (`backend/ml/threat_scoring_service.py`), batch scoring, and background analysis (`backend/services/threat_analyzer.py`) all delegate to the canonical `0.85 RF + 0.15 Calibrated IF` hybrid ensemble.
3. **Strict 12D Feature Schema Enforcement:** Positional truncation (e.g. `iloc[:, :12]`) and silent reshaping are strictly prohibited. Incompatible 6D, 13D, 15D, and 32D models fail explicitly with `ValueError`.
4. **Deterministic Isolation Forest Calibration:** Robust Min-Max inversion maps raw decision scores to $[0.0, 1.0]$ where higher values monotonically denote higher anomaly and threat evidence.
5. **Experimental LSTM Isolation:** Legacy/experimental 3-model blends ($0.50 \text{RF} + 0.30 \text{LSTM} + 0.20 \text{IF}$) are quarantined behind explicit feature flags (`PHANTOMNET_ENABLE_EXPERIMENTAL_LSTM=false` by default) and never mixed with the canonical scoring contract.

---

## 2. Canonical Feature Contract Reference

All inference consumers, pipeline stages, and models must strictly adhere to the 12-Dimensional Flow Feature Contract defined in `backend/ml/feature_extractor.py` and `backend/ml/config/thresholds.py`:

| Index | Feature Name | Data Type | Physical / Flow Interpretation |
|:---:|:---|:---:|:---|
| 0 | `packet_length` | `float` | Length of packet payload in bytes |
| 1 | `protocol_encoding` | `int` | Transport layer protocol (1=TCP, 2=UDP, 3=ICMP, 0=Other) |
| 2 | `dst_port_class` | `int` | Destination port class (1=Privileged/Standard, 2=Common Web/App, 3=Ephemeral/Dynamic) |
| 3 | `src_port_ephemeral` | `int` | Boolean indicator (1 if ephemeral $\ge 1024$, else 0) |
| 4 | `event_rate_1m` | `float` | Flow events observed from source IP within 60s window |
| 5 | `burst_rate_10s` | `float` | Peak event burst count within sliding 10s sub-window |
| 6 | `inter_arrival_mean` | `float` | Mean inter-arrival time between consecutive packets (seconds) |
| 7 | `inter_arrival_std` | `float` | Standard deviation of packet inter-arrival times (seconds) |
| 8 | `packet_size_variance` | `float` | Empirical sample variance of packet sizes in window |
| 9 | `payload_entropy` | `float` | Shannon byte entropy of payload ($0.0 \le H \le 8.0$) |
| 10 | `unique_dst_ips` | `int` | Unique destination IP addresses contacted in window |
| 11 | `unique_dst_ports` | `int` | Unique destination ports contacted in window |

### Prohibited Actions
- **No Positional Truncation:** Subsetting arrays or dataframes by slice without column validation is forbidden.
- **No Target/Label Leakage:** The target variable `is_malicious` / `label` and downstream composite `threat_score` must never enter the feature extractor.

---

## 3. Supervised Model Contract: Random Forest

- **Active Production Checkpoint:** `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl`
- **Fallback Production Checkpoint:** `ml_models/attack_classifier_latest.pkl`
- **Architecture:** `sklearn.pipeline.Pipeline` with `StandardScaler` followed by `RandomForestClassifier`
- **Hyperparameters:**
  - `n_estimators`: 100
  - `max_depth`: 12
  - `min_samples_split`: 5
  - `min_samples_leaf`: 2
  - `n_jobs`: -1
  - `random_state`: 42
- **Input Dimension:** $X \in \mathbb{R}^{N \times 12}$
- **Output:** Posterior class probability $P(\text{Malicious} \mid X) \in [0.0, 1.0]$ via `predict_proba(X)[:, 1]`.

---

## 4. Unsupervised Model Contract: Isolation Forest

- **Active Checkpoint:** `ml_models/iforest_baseline.pkl`
- **Architecture:** `sklearn.ensemble.IsolationForest`
- **Hyperparameters:**
  - `n_estimators`: 100
  - `contamination`: 0.10
  - `n_jobs`: -1
  - `random_state`: 42
- **Input Dimension:** $X \in \mathbb{R}^{N \times 12}$ (Standard scaled)
- **Raw Metric:** $s(x) = \text{decision\_function}(x)$
  - Standard scikit-learn convention: Inliers/normal flows yield positive scores ($s(x) > 0$), while anomalies/outliers yield negative scores ($s(x) < 0$).

---

## 5. Isolation Forest Calibration Method

To blend the unsupervised anomaly detector with the supervised classifier, the raw decision function $s(x)$ must be calibrated to match probability semantics ($0.0 = \text{benign inlier}$, $1.0 = \text{extreme anomaly}$):

### Calibration Formula
$$S_{\text{IF}}(x) = \text{clip}\left(1.0 - \frac{s(x) - s_{\min}}{s_{\max} - s_{\min} + 10^{-9}},\, 0.0,\, 1.0\right)$$

### Reference Distribution Parameters
Derived from the empirical percentiles of the verified clean training dataset (`data/remediated_dataset_v3.csv`, SHA-256 `390f653966...`):
- $s_{\min} = -0.181713$ (`IF_CALIBRATION_MIN`)
- $s_{\max} = +0.166857$ (`IF_CALIBRATION_MAX`)

### Directionality & Dynamic Range
- For extreme inliers ($s \ge 0.166857$): $S_{\text{IF}} \to 0.0$
- For average baseline traffic ($s \approx 0.0$): $S_{\text{IF}} \approx 0.48$
- For extreme outliers ($s \le -0.181713$): $S_{\text{IF}} \to 1.0$
- **Monotonicity:** $\frac{\partial S_{\text{IF}}}{\partial s} < 0$. As anomaly evidence increases ($s \downarrow$), $S_{\text{IF}} \uparrow$.

---

## 6. Canonical Hybrid Threat-Scoring Formula

The single authoritative scoring contract across PhantomNet is:

$$S_{\text{composite}} = w_{\text{rf}} \cdot P_{\text{RF}} + w_{\text{if}} \cdot S_{\text{IF}}$$

Substituting the canonical weights:

$$S_{\text{composite}} = 0.85 \cdot P_{\text{RF}} + 0.15 \cdot S_{\text{IF}}$$

Where:
- $P_{\text{RF}} \in [0.0, 1.0]$ is the Random Forest posterior probability of attack.
- $S_{\text{IF}} \in [0.0, 1.0]$ is the calibrated Isolation Forest anomaly score.
- $S_{\text{composite}} \in [0.0, 1.0]$ is the final composite threat score.

---

## 7. Weight Definitions & Deprecation Rules

Defined in `backend/ml/config/thresholds.py`:

```python
RF_WEIGHT: float = 0.85
IF_WEIGHT: float = 0.15

OBSOLETE_RF_WEIGHT: float = 0.70
OBSOLETE_IF_WEIGHT: float = 0.30
```

### Deprecation Enforcement
If any client attempts to instantiate `EnsemblePredictor(w_rf=0.70, w_if=0.30)`, the constructor logs an audit warning and automatically overrides the weights to the canonical values (`0.85` and `0.15`).

---

## 8. Threat Score Semantics & Range

- **Score Range:** Strictly bounded in $[0.0, 1.0]$.
- **Semantics:**
  - $0.00 \le S < 0.40$: Normal baseline traffic / benign activity.
  - $0.40 \le S < 0.60$: Moderate anomaly or suspicious activity requiring enrichment.
  - $0.60 \le S < 0.80$: High-confidence threat indication; automatic alert generation.
  - $0.80 \le S \le 1.00$: Severe, verified attack activity; immediate automated mitigation (BLOCK).

---

## 9. Severity & Decision Thresholds

Authoritative repository-wide thresholds established from production contracts:

### Severity Mapping
$$\text{Severity}(S) = \begin{cases}
\text{CRITICAL}, & S \ge 0.80 \\
\text{HIGH}, & 0.60 \le S < 0.80 \\
\text{MEDIUM}, & 0.40 \le S < 0.60 \\
\text{LOW}, & S < 0.40
\end{cases}$$

### Automated Enforcement Decision
$$\text{Decision}(S) = \begin{cases}
\text{BLOCK}, & S \ge 0.80 \\
\text{ALERT}, & 0.50 \le S < 0.80 \\
\text{ALLOW}, & S < 0.50
\end{cases}$$

---

## 10. Model Checkpoint Compatibility Rules

The canonical scoring engine (`EnsemblePredictor.validate_model_compatibility`) enforces strict dimensional and topological compatibility:

1. **Dimensional Check:** The model's `n_features_in_` property must equal `12`.
2. **Explicit Rejections:** Checkpoints with 6D, 13D, 15D, or 32D inputs (such as legacy `ml_models/registry/anomaly_detector.pkl` with 32 features) trigger an immediate `ValueError`.
3. **Pipeline Support:** `sklearn.pipeline.Pipeline` objects are unrolled and inspected recursively to ensure internal estimators receive exactly 12 features.
4. **Feature Name Alignment:** Feature names must match `FeatureExtractor.FEATURE_NAMES` in exact sequence.

---

## 11. API Integration Path

All HTTP and REST API threat scoring requests (`POST /api/v1/threats/score` and batch endpoints) route exclusively through `ThreatScoringService`:

```text
HTTP Request (Raw Event Dict)
   ↓
ThreatScoringService.score_threat(event_dict)
   ↓
FeatureExtractor.extract_features(event_dict)  → Validated 12D Dict
   ↓
FeatureExtractor.to_vector(features)           → (1, 12) np.ndarray
   ↓
EnsemblePredictor.score_vector(x_vec)
   ├── Pipeline[Scaler + RF].predict_proba()  → P_RF
   ├── IsolationForest.decision_function()     → Raw IF
   ├── Robust Min-Max Inversion Calibration   → S_IF
   └── 0.85 * P_RF + 0.15 * S_IF              → S_composite
   ↓
Map Score to Severity & Decision
   ↓
ThreatResponse (with structured audit fields: rf_score, raw_if_score, calibrated_if_score, model_version)
```

---

## 12. Background Threat Analyzer Integration Path

Background log ingestion and polling loops (`backend/services/threat_analyzer.py`) follow the exact same scoring pipeline:

1. Raw socket events are parsed and normalized.
2. `ThreatScoringService.score_threat(event)` is invoked.
3. The analyzer uses `result.score`, `result.threat_level`, and `result.decision` directly.
4. No secondary re-blending or redundant score recalculation occurs in the background loop.

---

## 13. Error Handling & Failsafe Protocols

1. **Missing / Malformed Fields:** Missing flow features are filled with stable physical zero-values by `FeatureExtractor.extract_features`.
2. **Model Failure Failsafe:** If the underlying ML models are unavailable or uninitialized:
   - Heuristic fallback scores the event based on protocol anomaly and destination port risk.
   - Severity is capped at `LOW` or `MEDIUM` unless high-confidence indicators exist.
3. **Incompatible Checkpoints:** Never fallback silently to heuristic when a corrupted or wrong-dimension model is loaded; raise `ValueError` explicitly to alert telemetry.

---

## 14. Testing & Empirical Verification Evidence

All 5 core test suites pass without regression:

| Test Suite | Path | Tests Passed | Status |
|:---|:---|:---:|:---:|
| ML Unit & Canonical Scoring | `tests/ml` | 53 / 53 | **PASS** |
| Backend ML Integration | `tests/backend` | 11 / 11 | **PASS** |
| Integration Suite | `tests/integration` | 8 / 8 | **PASS** |
| End-to-End Pipeline | `tests/e2e` | 235 / 235 | **PASS** |
| Experiment Integrity | `tests/experiments` | 6 / 6 | **PASS** |
| **Total Test Suite** | **Active Suites** | **313 / 313** | **PASS** |

Key verified properties in `tests/ml/test_canonical_scoring.py`:
- Requirement A: RF-only score generation verified.
- Requirement B: IF score generation verified.
- Requirement C: Calibrated IF score strictly in $[0.0, 1.0]$.
- Requirement D: Hybrid score satisfies $0.85 \times P_{\text{RF}} + 0.15 \times S_{\text{IF}}$ within $10^{-6}$.
- Requirement E: Obsolete $0.70/0.30$ weights overridden and rejected.
- Requirement F: Missing features or wrong dimensions raise explicit `ValueError`.
- Requirement G: Incompatible 6D/13D/15D/32D checkpoints rejected.
- Requirement H: Monotonic directionality verified ($\frac{\partial S_{\text{IF}}}{\partial \text{anomaly}} > 0$).
- Requirement I: API and background analyzer produce bitwise identical scores.
- Requirement J: Deterministic execution verified across identical random states.
- Requirement K: Concurrent thread safety verified under 50 parallel scoring requests.

---

## 15. Known Legacy Paths & Deprecation Status

1. **Experimental LSTM Model:**
   - **Path:** `backend/services/threat_analyzer.py` (line 280) & `backend/ml_engine/lstm_model.py`
   - **Status:** `ISOLATED_EXPERIMENTAL`
   - **Rule:** Disabled by default. Only enabled when `PHANTOMNET_ENABLE_EXPERIMENTAL_LSTM=true` is set. Even when active, it is tracked as an experimental side-car metric and does not mutate the canonical threat score contract.
2. **32D Anomaly Detector:**
   - **Path:** `ml_models/registry/anomaly_detector.pkl`
   - **Status:** `QUARANTINED_INCOMPATIBLE`
   - **Rule:** Preserved for historical audit trail; strictly rejected by `validate_model_compatibility()`.

---

## 16. Reproducibility Information

The entire experimental and analytical benchmark reproduces from scratch with exit code 0:

```bash
python experiments/reproduce_all.py
```

- **Clean Dataset:** `data/remediated_dataset_v3.csv`
- **SHA-256 Hash:** `390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363`
- **Zero Leakage:** Formally confirmed across all 12 feature distributions ($ARI \ge 0.70$, 0 separable leakage columns).
- **Benchmark Metrics ($N=30$ Monte Carlo Runs):**
  - Standalone RF Accuracy: $0.9327 \pm 0.0042$ | FPR: $0.0103 \pm 0.0031$
  - Hybrid Ensemble Accuracy: $0.9273 \pm 0.0048$ | FPR: $0.0075 \pm 0.0024$
  - FPR Reduction: $27.2\%$ relative false-positive alarm reduction via calibrated IF filtering.
