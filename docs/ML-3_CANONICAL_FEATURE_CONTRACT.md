# PhantomNet ML-3: Canonical 12-Dimensional Feature Contract & Legacy Model Quarantine Specification

## Executive Summary

This document establishes and formalizes the single authoritative 12-dimensional (12D) feature contract across the entire PhantomNet architecture. Phase ML-3 eliminates schema ambiguities, eliminates runtime positional array slicing (`iloc[:, :12]`, `[:, :12]`), isolates and quarantines incompatible historical model checkpoints (6D, 13D, 15D, 32D, and host-schema 12D), and enforces rigorous validation boundaries across feature extraction, model loading, online API scoring, and batch evaluation.

---

## 1. Canonical 12D Feature Contract

The machine-readable source of truth is defined in [`backend/ml/config/feature_schema.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/config/feature_schema.py).

* **Schema Version:** `12D-v1`
* **Feature Count:** Exactly `12`
* **Feature Scope:** Continuous and discrete numeric representations extracted exclusively from network socket and packet flow dynamics.
* **Leakage-Free Guarantee:** The feature schema excludes all target indicators, ground truth labels (`label`), post-hoc threat assessments (`threat_score`), honeypot interaction counters, and administrative flags.

### Formal Schema Definition

| Index | Feature Name | Data Type | Physical / Statistical Meaning | Unit / Scale |
| :---: | :--- | :--- | :--- | :--- |
| **0** | `packet_length` | `float64` | Byte length of the observed packet or frame payload | Bytes ($[0, 65535]$) |
| **1** | `protocol_encoding` | `float64` | Numeric categorical encoding of IP transport protocol | Discrete ($1=\text{ICMP}, 6=\text{TCP}, 17=\text{UDP}$) |
| **2** | `dst_port_class` | `float64` | Service port criticality class | Categorical ($0=\text{well-known}, 1=\text{registered}, 2=\text{ephemeral}$) |
| **3** | `src_port_ephemeral` | `float64` | Ephemeral source port indicator flag | Binary ($1.0 \text{ if } \ge 1024 \text{ else } 0.0$) |
| **4** | `event_rate_1m` | `float64` | Exponentially smoothed event rate across a 60-second window | Events / second |
| **5** | `burst_rate_10s` | `float64` | Short-window packet event burst density over 10 seconds | Events / 10s |
| **6** | `inter_arrival_mean` | `float64` | Sample mean of packet inter-arrival time ($\Delta t$) in window | Milliseconds |
| **7** | `inter_arrival_std` | `float64` | Sample standard deviation of packet inter-arrival time in window | Milliseconds |
| **8** | `packet_size_variance` | `float64` | Variance of packet byte sizes observed within the flow buffer | $\text{Bytes}^2$ |
| **9** | `payload_entropy` | `float64` | Shannon entropy calculated over raw packet byte distribution | Bits / byte ($[0.0, 8.0]$) |
| **10** | `unique_dst_ips` | `float64` | Rolling cardinality of unique destination IP addresses accessed | Count ($\ge 1.0$) |
| **11** | `unique_dst_ports` | `float64` | Rolling cardinality of unique destination ports targeted | Count ($\ge 1.0$) |

---

## 2. Deterministic Feature Ordering

Feature vectors must strictly adhere to the tuple ordering defined in `CANONICAL_FEATURE_NAMES`:

$$\mathbf{x} = \begin{bmatrix}
x_{\text{packet\_length}} \\
x_{\text{protocol\_encoding}} \\
x_{\text{dst\_port\_class}} \\
x_{\text{src\_port\_ephemeral}} \\
x_{\text{event\_rate\_1m}} \\
x_{\text{burst\_rate\_10s}} \\
x_{\text{inter\_arrival\_mean}} \\
x_{\text{inter\_arrival\_std}} \\
x_{\text{packet\_size\_variance}} \\
x_{\text{payload\_entropy}} \\
x_{\text{unique\_dst\_ips}} \\
x_{\text{unique\_dst\_ports}}
\end{bmatrix} \in \mathbb{R}^{12}$$

* **Array / Matrix Shape:** 1D array of shape `(12,)` or 2D batch matrix of shape `(N, 12)`.
* **DataFrame Columns:** When serialized into a `pandas.DataFrame`, column headers must strictly equal `list(CANONICAL_FEATURE_NAMES)` in identical sequence.
* **No Positional Truncation:** Workarounds slicing arbitrary prefixes (e.g. `X = X[:, :12]` or `df.iloc[:, :12]`) are strictly forbidden and intercepted by validation boundaries.

---

## 3. Canonical Target Definition

* **Target Variable Name:** `label`
* **Target Type:** Binary integer classification label:
  * `0`: Benign / normal operational network traffic.
  * `1`: Malicious / adversary probe, intrusion, or exploit attempt.
* **Target Separation:** The feature extraction pipeline must NEVER read or accept `label` (or historical column aliases `is_malicious`, `attack_cat`, `threat_score`). Any feature dictionary or DataFrame containing target fields triggers an immediate validation failure (`ValueError: Target/label leakage detected`).

---

## 4. Extractor Responsibilities

The canonical feature extractor is implemented in [`backend/ml/feature_extractor.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/feature_extractor.py):

1. **Stateful Window Buffering:** Maintains bounded LRU per-source IP history buffers for temporal velocity features (`event_rate_1m`, `burst_rate_10s`, `inter_arrival_mean`, `inter_arrival_std`, `unique_dst_ips`, `unique_dst_ports`).
2. **Payload Parsing:** Computes byte-level Shannon entropy and length from raw packet headers/payloads.
3. **Stateless Vector Conversion:** Transforms dictionary representations into canonical 1D numpy arrays via `dict_to_canonical_vector()`.
4. **Validation Boundary Enforcement:** Executes `validate_feature_vector()` prior to returning any numerical vector or matrix.
5. **Thread Safety:** Implements thread-safe locking across window state updates to protect concurrent REST API invocations.

---

## 5. Model Compatibility Rules

Before any model checkpoint is loaded into memory or executed for inference, [`backend/ml/model_loader.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/model_loader.py) executes `validate_checkpoint_schema()`:

1. **Input Dimension Check:** The model's input feature expectation (`n_features_in_`) must strictly equal `12`.
2. **Pipeline Step Inspection:** If the artifact is a scikit-learn `Pipeline`, every transformer (e.g. `StandardScaler`) and estimator (e.g. `RandomForestClassifier`) must have `n_features_in_ == 12`.
3. **Domain Verification:** If the artifact provides `feature_names_in_`, every feature name must exactly match `CANONICAL_FEATURE_NAMES` in sequence. Checkpoints trained on host command telemetry (e.g. `backend/ml/models/feature_scaler_v2.pkl`) having 12 dimensions but mismatched feature names (`command_count`, etc.) are rejected.
4. **Strict Failure Mode:** Any mismatch raises `ValueError` detailing the model path, detected dimension, expected dimension, status, and recommended disposition. Under no circumstances does the loader truncate or pad weights.

---

## 6. Legacy and Quarantine Policy

Historical artifacts with non-canonical dimensions or deprecated feature sets are preserved for scientific auditability and provenance, but quarantined from production execution:

### Quarantined Model Manifest

A machine-readable audit manifest is maintained in [`experiments/results/ml3_model_quarantine.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml3_model_quarantine.json).

| Artifact Path | Detected Dim | Historical Purpose | Rejection Reason | Disposition |
| :--- | :---: | :--- | :--- | :--- |
| `backend/ai_engine/model_rf.pkl` | 6D | Early prototype | Incompatible 6D input dimension | Quarantined |
| `backend/ml/evaluation_output/if_model_unified.pkl` | 13D | Offline evaluation | 13D feature schema mismatch | Quarantined |
| `backend/ml/evaluation_output/rf_model_unified.pkl` | 13D | Offline evaluation | 13D feature schema mismatch | Quarantined |
| `backend/ml/evaluation_output/scaler_unified.pkl` | 13D | Offline evaluation | 13D feature schema mismatch | Quarantined |
| `backend/ml/models/feature_scaler_v2.pkl` | 12D | Host behavioral scaler | Host domain schema mismatch | Quarantined |
| `ml_models/registry/anomaly_detector.pkl` | 32D | CompleteFeatureExtractor | Incompatible 32D input dimension | Quarantined |
| `models/isolation_forest_optimized.pkl` | 15D | Legacy research IF | Incompatible 15D dimension | Quarantined |
| `models/isolation_forest_optimized_v2.pkl` | 15D | Legacy research IF | Incompatible 15D dimension | Quarantined |
| `models/isolation_forest_v1.pkl` | 15D | Legacy baseline IF | Incompatible 15D dimension | Quarantined |
| `models/scaler_v1.pkl` | 15D | Legacy scaler | 15D dimension; target leakage | Quarantined |
| `ml_models/lstm_attack_predictor.h5` | Null | Experimental LSTM | Time-series sequence stub | Isolated behind flag |
| `ml_models/lstm_attack_predictor.h5.mock.pkl` | 350D | Historical mock | 350D mock estimator | Quarantined / Legacy |

### Deprecated Extractors

* **`CompleteFeatureExtractor` (32D):** Located in [`backend/ml/feature_engineering_complete.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/feature_engineering_complete.py). Emits a `DeprecationWarning` upon instantiation and is quarantined from production inference.
* **`FeatureExtractorV2` (12D Host):** Located in [`backend/ml/feature_engineering_v2.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/feature_engineering_v2.py). Extracts host telemetry (`command_count`, `shell_escape_count`, etc.) rather than network flow dynamics. Emits a `DeprecationWarning` upon instantiation.

---

## 7. API and Runtime Service Contract

All production scoring paths process inputs through the canonical contract:

1. **Synchronous REST Endpoint:** `POST /api/v1/analyze/threat-score` in [`backend/api/threat_scoring.py`](file:///c:/Users/srira/Project/PhantomNet/backend/api/threat_scoring.py).
2. **Threat Scoring Service:** `score_threat()` in [`backend/ml/threat_scoring_service.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/threat_scoring_service.py).
3. **Background Threat Analyzer:** `ThreatAnalyzer.analyze_event()` in [`backend/services/threat_analyzer.py`](file:///c:/Users/srira/Project/PhantomNet/backend/services/threat_analyzer.py).
4. **Hybrid Ensemble Predictor:** `HybridEnsemblePredictor.score_vector()` in [`backend/ml/models/ensemble_predictor.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/models/ensemble_predictor.py).

### Bitwise Parity Guarantee

For identical canonical 12D input vectors $\mathbf{x}$, the composite threat score is invariant across all callers:

$$\text{Score}_{\text{API}}(\mathbf{x}) \equiv \text{Score}_{\text{Analyzer}}(\mathbf{x}) \equiv \text{Score}_{\text{Ensemble}}(\mathbf{x}) = 0.85 \cdot P_{\text{RF}}(\mathbf{x}) + 0.15 \cdot S_{\text{IF}}(\mathbf{x})$$

Tested and empirically verified in `tests/ml/test_feature_schema_contract.py::test_req_o_api_and_service_consistency`.

---

## 8. Failure Behavior and Boundary Guards

The validation function `validate_feature_vector()` enforces the following deterministic failure behaviors:

| Violation Condition | Error Raised | Error Message Example |
| :--- | :--- | :--- |
| **Wrong feature count ($D \ne 12$)** | `ValueError` | `Expected exactly 12 features, got 15` |
| **Missing column in DataFrame** | `ValueError` | `Missing required canonical features: {'payload_entropy'}` |
| **Extra column in DataFrame** | `ValueError` | `Extra features not permitted in 12D schema: {'threat_score'}` |
| **Non-deterministic column order** | `ValueError` | `Feature order mismatch at index 0: expected packet_length, got protocol_encoding` |
| **Non-numeric value (string/object)** | `ValueError` | `Input contains non-numeric values: could not convert string to float: 'abc'` |
| **Non-finite value (NaN, Inf, -Inf)** | `ValueError` | `Input contains NaN or infinite values` |
| **Target/label leakage column** | `ValueError` | `Target/label leakage detected: {'label'}` |
| **Positional slicing bypass attempt** | `ValueError` | `Positional array slicing detected: input length 15 does not match canonical 12` |

---

## 9. Reproducibility Procedure

To verify the canonical schema contract and execute the full reproducibility pipeline:

1. **Verify Unit & Contract Tests:**
   ```bash
   python -m pytest tests/ml/test_feature_schema_contract.py -v
   python -m pytest tests/ml -v
   ```
2. **Execute Full Test Battery:**
   ```bash
   python -m pytest tests/backend tests/experiments tests/integration tests/e2e -v
   ```
3. **Execute End-to-End Orchestrator:**
   ```bash
   python experiments/reproduce_all.py
   ```
4. **Inspect Machine Evidence:**
   Verify `experiments/results/ml3_schema_audit.json` and `experiments/results/ml3_model_quarantine.json`.

---

## 10. Architectural Limitations

1. **Scope of Telemetry:** The canonical 12D schema models transport-layer and network flow behavior. It does not ingest host operating system events, kernel process trees, or application-layer HTTP payloads.
2. **Temporal Window Sensitivity:** Velocity and burst features (`event_rate_1m`, `burst_rate_10s`) depend on sliding window state. Warm-up time is required for accurate rate estimation on newly observed source IP addresses.
3. **Entropy Approximation:** Shannon entropy is computed over the byte distribution of the captured packet payload slice ($[0, 65535]$ bytes). Empty or truncated payloads default to $0.0$ entropy.
4. **Quantization of Protocol Encoding:** IP protocol types are mapped onto discrete real values ($1, 6, 17$). Non-standard protocols default to $0.0$.
