# PHANTOMNET ML-3: SCHEMA FORENSIC INVENTORY

**Phase:** Master Audit Phase ML-3 (Feature Contract & Quarantine)  
**Authoritative SHA:** `686e880a240a671390e68eb42f24ece21156c1f2`  
**Branch:** `fix/full-codebase-audit-remediation`  
**Purpose:** Forensic catalog of all model checkpoints, feature extractors, and dimensionality states across the repository.

---

## 1. Executive Summary

This inventory documents all serialized machine learning models (`*.pkl`, `*.joblib`, `*.h5`) and feature extractors identified in the PhantomNet repository.

### Key Inventory Findings
- **Total Serialized Model Files Inspected:** 19 unique project artifacts (excluding tracking runs and virtual environment dependencies).
- **Canonical 12D Checkpoints (Active):** 4 artifacts (`ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl`, `ml_models/attack_classifier_latest.pkl`, `ml_models/iforest_baseline.pkl`, `ml_models/registry/scaler.pkl`).
- **Incompatible Quarantined Checkpoints:** 10 artifacts across 6D, 13D, 15D, 32D, and host-schema 12D models.
- **Experimental / Mock Artifacts:** 3 artifacts (`ml_models/lstm_attack_predictor.h5`, `ml_models/lstm_attack_predictor.h5.mock.pkl`, `ml_models/lstm_training_data.pkl`).
- **Data / Report Fixtures:** 2 artifacts (`backend/reports/stability_data.joblib`, `backend/ml/models/attack_classifier_v3_enhanced.pkl`).

---

## 2. Model Checkpoint Forensic Matrix

| File Path | Component / Class | Dim | Feature Names (if recoverable) | Target Usage | Serialization | Production Status | Compatibility Status | Empirical Evidence | Recommended Disposition |
|:---|:---|:---:|:---|:---:|:---:|:---|:---|:---|:---|
| `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl` | `Pipeline(['scaler', 'rf'])` | 12 | `packet_length`, `protocol_encoding`, `dst_port_class`, `src_port_ephemeral`, `event_rate_1m`, `burst_rate_10s`, `inter_arrival_mean`, `inter_arrival_std`, `packet_size_variance`, `payload_entropy`, `unique_dst_ips`, `unique_dst_ports` | None (`label` used in training) | joblib / pickle | **ACTIVE_CANONICAL** | **COMPATIBLE** | `n_features_in_=12`, matches `FeatureExtractor.FEATURE_NAMES` | Retain as Primary Production Classifier |
| `ml_models/attack_classifier_latest.pkl` | `Pipeline(['scaler', 'rf'])` | 12 | Canonical 12 Flow Features | None | joblib / pickle | **CANONICAL** | **COMPATIBLE** | Bitwise identical to registry model | Retain as Local Fallback Classifier |
| `ml_models/iforest_baseline.pkl` | `IsolationForest` | 12 | Canonical 12 Flow Features | Unsupervised | joblib / pickle | **ACTIVE_CANONICAL** | **COMPATIBLE** | `n_features_in_=12`, fits canonical feature contract | Retain as Canonical Anomaly Detector |
| `ml_models/registry/scaler.pkl` | `StandardScaler` | 12 | Canonical 12 Flow Features | None | joblib / pickle | **CANONICAL** | **COMPATIBLE** | `n_features_in_=12`, matches flow schema | Retain as Reference Scaler |
| `backend/ml/models/attack_classifier_v3_enhanced.pkl` | `RandomForestClassifier` | 12 | None recorded in estimator | None | joblib / pickle | **LEGACY_UNWRAPPED** | **COMPATIBLE_ESTIMATOR_ONLY** | `n_features_in_=12`, but raw RF without pipeline scaler | Quarantine; superseded by pipeline checkpoint |
| `backend/ai_engine/model_rf.pkl` | `RandomForestClassifier` | 6 | None | Historical label | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (6D)** | `n_features_in_=6`. Prototype 6D network model | Quarantine; block in `model_loader.py` |
| `backend/ml/evaluation_output/if_model_unified.pkl` | `IsolationForest` | 13 | 13 features (incl. `rolling_average_deviation`, `z_score_anomaly`) | Unsupervised | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (13D)** | `n_features_in_=13`. Early evaluation artifact | Quarantine; preserve for audit trail |
| `backend/ml/evaluation_output/rf_model_unified.pkl` | `RandomForestClassifier` | 13 | 13 features (incl. `rolling_average_deviation`, `z_score_anomaly`) | Historical label | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (13D)** | `n_features_in_=13`. Early evaluation artifact | Quarantine; preserve for audit trail |
| `backend/ml/evaluation_output/scaler_unified.pkl` | `StandardScaler` | 13 | 13 features | None | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (13D)** | `n_features_in_=13` | Quarantine; preserve for audit trail |
| `backend/ml/models/feature_scaler_v2.pkl` | `StandardScaler` | 12 | 12 Host/Command features (`command_count`, `shell_escape_count`, `failed_login_count`, etc.) | None | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE_SCHEMA_MISMATCH** | `n_features_in_=12`, but features are host commands, NOT network flow features | Quarantine; prevent loading in network flow inference |
| `ml_models/registry/anomaly_detector.pkl` | `IsolationForest` | 32 | None (Generated from `CompleteFeatureExtractor`) | None | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (32D)** | `n_features_in_=32`. Legacy 32-feature anomaly detector | Quarantine; reject explicitly in `model_loader.py` |
| `models/isolation_forest_optimized.pkl` | `IsolationForest` | 15 | None | None | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (15D)** | `n_features_in_=15`. Legacy Phase 15 model | Quarantine; reject explicitly |
| `models/isolation_forest_optimized_v2.pkl` | `IsolationForest` | 15 | None | None | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (15D)** | `n_features_in_=15`. Legacy Phase 15 model | Quarantine; reject explicitly |
| `models/isolation_forest_v1.pkl` | `IsolationForest` | 15 | None | None | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (15D)** | `n_features_in_=15`. Legacy Phase 15 model | Quarantine; reject explicitly |
| `models/scaler_v1.pkl` | `StandardScaler` | 15 | 15 features including `threat_score`, `malicious_flag_ratio` | **CRITICAL TARGET LEAKAGE** | joblib / pickle | **QUARANTINED_INCOMPATIBLE** | **INCOMPATIBLE (15D + LEAKAGE)** | Scaler contains leaked downstream metrics | Quarantine; strictly forbidden in production |
| `ml_models/lstm_attack_predictor.h5` | `Keras HDF5` | N/A | Sequential time-series payload vectors | Target classification | HDF5 | **ISOLATED_EXPERIMENTAL** | **EXPERIMENTAL** | 24-byte empty placeholder file | Isolate behind feature flag |
| `ml_models/lstm_attack_predictor.h5.mock.pkl` | `RandomForestClassifier` | 350 | None | Synthetic class | joblib / pickle | **ISOLATED_EXPERIMENTAL** | **EXPERIMENTAL_MOCK** | 350-dimensional mock estimator for test isolation | Quarantine to mock test harness |
| `ml_models/lstm_training_data.pkl` | `dict` | N/A | Historical sequence tensors | Training data | joblib / pickle | **DATA_FIXTURE** | **NON_MODEL** | Dictionary of numpy training arrays | Preserve in test data |
| `backend/reports/stability_data.joblib` | `dict` | N/A | Statistical test observations | Evaluation report | joblib / pickle | **DATA_FIXTURE** | **NON_MODEL** | Dictionary of runtime stability metrics | Preserve in report data |

---

## 3. Feature Extractor Forensic Inventory

### A. Canonical Feature Extractor
- **Module:** `backend/ml/feature_extractor.py`
- **Class:** `FeatureExtractor`
- **Output Dimensionality:** Exactly 12.
- **Features Emitted:** `['packet_length', 'protocol_encoding', 'dst_port_class', 'src_port_ephemeral', 'event_rate_1m', 'burst_rate_10s', 'inter_arrival_mean', 'inter_arrival_std', 'packet_size_variance', 'payload_entropy', 'unique_dst_ips', 'unique_dst_ports']`.
- **Target Access:** None (`is_malicious` and `threat_score` are strictly ignored).
- **Status:** **ACTIVE_CANONICAL**.

### B. Legacy Host Feature Extractor (V2)
- **Module:** `backend/ml/feature_engineering_v2.py`
- **Class:** `FeatureExtractorV2`
- **Output Dimensionality:** 12 (Host/Command domain).
- **Features Emitted:** `['command_count', 'avg_command_length', 'shell_escape_count', 'directory_traversal_count', 'failed_login_count', 'payload_entropy', 'interaction_interval_var', 'persistence_score', 'ua_diversity', 'lateral_movement_index', 'sensitive_file_count', 'payload_to_cmd_ratio']`.
- **Status:** **LEGACY_HOST_SPECIFIC** (Not network flow features). Must be quarantined from flow inference.

### C. Legacy Combined Extractor (32D)
- **Module:** `backend/ml/feature_engineering_complete.py`
- **Class:** `CompleteFeatureExtractor`
- **Output Dimensionality:** 32 (Combines 15 base + 12 V2 + 5 custom).
- **Target Access:** Accesses `threat_score` on event dictionary (leaked historical design).
- **Status:** **QUARANTINED_INCOMPATIBLE** (Target leakage + 32D incompatible schema).

---

## 4. Recommended Action Plan (ML-3)
1. **Define Schema Contract:** Create `backend/ml/config/feature_schema.py` as the single authoritative definition.
2. **Harden `FeatureExtractor`:** Add strict schema and finite value validation (`validate_feature_vector`).
3. **Harden `model_loader.py`:** Enforce explicit rejection on 6D, 13D, 15D, and 32D models, outputting model ID, detected dim, expected dim, and quarantine status.
4. **Mark Deprecations:** Add deprecation warnings to `FeatureExtractorV2` and `CompleteFeatureExtractor`.
5. **Generate Quarantine Manifest:** Serialize `experiments/results/ml3_model_quarantine.json`.
