# PHANTOMNET — PHASE ML-1 FORENSIC BASELINE VERIFICATION REPORT
**Audit Date:** 2026-10-01  
**Scope:** Forensic Baseline Verification of Historical Defects A through T  
**Status:** COMPLETE — AWAITING EXPLICIT APPROVAL FOR REMEDIATION PHASE

---

## 1. Executive Summary

This forensic verification re-examined all 20 historical defect categories (A through T) directly against the current codebase, active datasets, serialized models, test execution logs, and experimental artifacts.

**Key Findings:**
1. **Remediated Core is Clean:** The primary production path (`FeatureExtractor`, `remediated_dataset_v3.csv`, `reproduce_clean_paper.py`, and `test_full_pipeline_e2e.py`) is verified free of target leakage, iloc slicing, and fabricated contingency tables.
2. **Material Architecture Inconsistencies Discovered:**
   - **Ensemble Logic Drift:** `backend/services/threat_analyzer.py` blends 0.85 RF + 0.15 IF, while `backend/ml/models/ensemble_predictor.py` hardcodes 0.70 RF + 0.30 IF, and `backend/ml/threat_scoring_service.py` only executes standalone RF during single-event scoring.
   - **Model Dimensional Diversity:** Serialized models in `ml_models/` and `backend/` have 6, 12, 13, 15, and 32 features, creating potential runtime deserialization traps if legacy models are loaded.
   - **Pickle vs. Joblib Fragility:** Several models require `joblib.load()` rather than standard `pickle.load()` due to compression headers.
   - **Documentation vs. Code Divergence:** Earlier draft reports incorrectly listed a hypothetical 12-feature set (`packet_size`, `flow_duration`...), whereas the actual verified codebase and dataset implement `packet_length`, `protocol_encoding`, `dst_port_class`, etc.

---

## 2. Detailed Verification Table: Historical Defects A → T

| Item | Defect Category | Current Status | Primary File(s) & Location | Evidence & Root Cause | Severity | Recommended Action |
| :---: | :--- | :---: | :--- | :--- | :---: | :--- |
| **A** | **Dataset Target Leakage** | **VERIFIED FIXED** (Active)<br>**VERIFIED PRESENT** (Legacy) | Active: `data/remediated_dataset_v3.csv`<br>Legacy: `data/ground_truth.csv`, `data/training_dataset.csv` | Single-feature decision stumps on `remediated_dataset_v3.csv` show max accuracy of 81.08% (clean). Legacy files contain `threat_score` and `malicious_flag_ratio`. | High (Legacy) | Maintain permanent quarantine of legacy datasets. Enforce `remediated_dataset_v3.csv` as sole source of truth. |
| **B** | **`threat_score` Leakage** | **VERIFIED FIXED** (Active)<br>**VERIFIED PRESENT** (Legacy) | Active: `backend/ml/feature_extractor.py`<br>Legacy: `backend/ml/feature_engineering_complete.py:30` | Active extractor has zero access to `threat_score`. Obsolete `CompleteFeatureExtractor` still casts `threat_score` in its input loop. | Medium | Deprecate and isolate `CompleteFeatureExtractor`. |
| **C** | **`is_malicious` Leakage** | **VERIFIED FIXED** | `backend/ml/feature_extractor.py` | Extractor operates strictly on network headers (`src_ip`, `dst_port`, `length`, `protocol`, `payload`). Zero label leakage. | Critical | Keep current verified implementation. |
| **D** | **Feature/Label Contamination** | **VERIFIED FIXED** | `experiments/reproduce_clean_paper.py:145` | `StandardScaler` is enclosed in scikit-learn `Pipeline` and fitted exclusively on `X_train`. Held-out test set ($N=1,000$) is transformed only. | High | Keep current verified protocol. |
| **E** | **Duplicate Datasets** | **VERIFIED PRESENT** | `data/remediated_dataset_v3.csv`<br>`backend/ml/datasets/labeled_events_remediated.csv` | Both files share identical SHA-256 (`390f653966...`). Multiple historical dataset variants exist in `backend/ml/evaluation_output/`. | Low | Consolidate onto `data/remediated_dataset_v3.csv` via symlink or reference. |
| **F** | **Conflicting Feature Extractors** | **VERIFIED PRESENT** | `backend/ml/feature_extractor.py` (12D Flow)<br>`backend/ml/feature_engineering_v2.py` (12D Host)<br>`backend/ml/feature_engineering_complete.py` (32D Combined) | Three distinct extractors exist with conflicting names, feature spaces, and threading models. | High | Formally designate `FeatureExtractor` as canonical production contract. Mark others as legacy/experimental. |
| **G** | **15D vs 12D Mismatch** | **VERIFIED FIXED** (Active)<br>**VERIFIED PRESENT** (Checkpoints) | Active: `ThreatScoringService`<br>Checkpoints: `models/isolation_forest_optimized_v2.pkl` (15D) | Production scoring expects strict 12D. Checkpoints in `models/` still expect 15 features. | Medium | Deprecate 15D checkpoints to prevent accidental runtime loading. |
| **H** | **`iloc[:, :12]` Slicing** | **VERIFIED FIXED** | `backend/ml/threat_scoring_service.py:163-165` | Grep confirmed 0 occurrences. DataFrame is constructed with explicit named columns `FeatureExtractor.FEATURE_NAMES`. | High | Enforce named column assertions. |
| **I** | **Corrupted / Incompatible Models** | **VERIFIED PRESENT** | `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl`<br>`backend/ai_engine/model_rf.pkl` | Model files compressed with joblib fail with standard `pickle.load()` (`invalid load key` / `STACK_GLOBAL`). They succeed with `joblib.load()`. | Medium | Ensure all model loading code uses `joblib.load()` with standard exception handling. |
| **J** | **Isolation Forest Near-Random Behavior** | **VERIFIED FIXED** (Ensemble Role)<br>**VERIFIED WEAK** (Standalone) | `experiments/reproduce_clean_paper.py`<br>`backend/ml_engine/unsupervised_detector.py` | Standalone IF achieves 66.9% accuracy and 0.702 ROC-AUC. However, when blended (0.85/0.15), it significantly suppresses false positives ($p = 1.73 \times 10^{-6}$). | Medium | Accurately document IF as a precision/FPR filter rather than an independent high-accuracy classifier. |
| **K** | **Arbitrary Ensemble Weights** | **VERIFIED PRESENT** | `backend/services/threat_analyzer.py:304` (0.85 / 0.15)<br>`backend/ml/models/ensemble_predictor.py:22` (0.70 / 0.30)<br>`backend/ml/threat_scoring_service.py` (1.00 RF) | Conflicting ensemble implementations across the codebase. Scoring service does not execute the 0.85/0.15 hybrid blend on single-event requests. | High | Unify ensemble scoring logic across `ThreatScoringService`, `ThreatAnalyzerService`, and `EnsemblePredictor`. |
| **L** | **DBSCAN Scale Domination** | **VERIFIED FIXED** | `backend/ml_engine/campaign_clustering.py` | Skewed flow features receive `np.log1p` + `StandardScaler`. DBSCAN ($\epsilon=0.80, \text{min}=4$) discovers 8 campaigns with 95.04% homogeneity and 0 cross-campaign false merges. | Critical | Maintain log1p + StandardScaler pipeline. |
| **M** | **Fabricated Contingency Tables** | **VERIFIED FIXED** | `experiments/results/statistical_tests.json`<br>`experiments/reproduce_clean_paper.py` | Symmetric table `[[0, 30], [30, 0]]` was purged. Replaced by real discordant pairs ($b=32, c=1$, McNemar $p = 7.15 \times 10^{-8}$) from $N=1,000$ test observations. | Critical | Retain empirical discordance tracking. |
| **N** | **Missing Imports / Dependencies** | **VERIFIED FIXED** | Python 3.11 Environment | All core libraries (`fakeredis`, `shap`, `scipy`, `scikit-learn`, `fastapi`, `sqlalchemy`) import without errors. | Medium | Maintain pinned `requirements.txt`. |
| **O** | **SHAP Pipeline Incompatibility** | **VERIFIED FIXED** | `backend/ml_engine/explainability.py` | `ModelExplainer` inspects whether input is a `Pipeline`, extracts estimator, scales instances, and satisfies additivity to machine precision ($< 1.42 \times 10^{-6}$). | High | Maintain pipeline-aware explainer. |
| **P** | **Thread-Safety Hazards** | **PARTIALLY FIXED** | `backend/ml/feature_extractor.py` (Locked)<br>`backend/ml/feature_engineering_v2.py` (Unlocked)<br>`backend/services/threat_analyzer.py:44` (Buffer unlocked) | Active `FeatureExtractor` uses `threading.RLock()`. Secondary extractors and threat analyzer sequence buffers lack locks. | Medium | Add synchronization locks to threat analyzer sequence buffers; isolate secondary extractors. |
| **Q** | **Threshold Inconsistencies** | **PARTIALLY FIXED** | `backend/ml/threat_scoring_service.py:46`<br>`backend/services/threat_analyzer.py:310-321` | Base thresholds agree (`CRITICAL >= 0.80, HIGH >= 0.60, MEDIUM >= 0.40, LOW < 0.40`). However, documentation and tests occasionally mention `CRITICAL >= 0.85`. | Low | Align documentation and test assertions with production base threshold standard (0.80). |
| **R** | **Manual DB Mutation in E2E Tests** | **VERIFIED FIXED** | `tests/e2e/test_full_pipeline_e2e.py` | 14/14 automated stages execute through genuine HTTP/service APIs without SQL injection or manual score tampering. | High | Retain autonomous E2E test harness. |
| **S** | **Fabricated Latency Metrics** | **VERIFIED FIXED** | `experiments/results/latency_observations.csv` | 520 raw timing records captured. Fast-path scoring confirmed at 0.071 ms; full tree inference confirmed at 28.32 ms. | Medium | Report detailed stage latency breakdown. |
| **T** | **Hardcoded Statistical Values** | **VERIFIED FIXED** | `experiments/results/statistical_tests.json`<br>`experiments/generate_publication_evidence.py` | All p-values, statistics, and confidence intervals are computed dynamically from actual Monte Carlo runs. | Critical | Enforce automated evidence generation. |

---

## 3. Required Decisions Prior to Large-Scale Remediation

Per instructions, the following architectural consolidations are recommended for approval before applying modifications:

1. **Unify Hybrid Ensemble Wiring:** Update `backend/ml/threat_scoring_service.py` to optionally execute the calibrated 0.85 RF + 0.15 IF ensemble (or load an ensemble model object) so direct API requests receive the same hybrid score as background polling workers.
2. **Align Obsolete Extractors:** Mark `FeatureExtractorV2` and `CompleteFeatureExtractor` explicitly as `@deprecated` legacy modules, ensuring all production routes import only `backend.ml.feature_extractor.FeatureExtractor`.
3. **Consolidate EnsemblePredictor:** Align `backend/ml/models/ensemble_predictor.py` weights from `0.70 / 0.30` to canonical `0.85 / 0.15`.
4. **Synchronize Sequence Buffers:** Add `threading.Lock()` to `ThreatAnalyzerService._sequence_buffers` in `backend/services/threat_analyzer.py` to guarantee thread safety under concurrent event streams.
5. **Harmonize Documentation Feature Names:** Update `FEATURE_SPEC.md` and related cards to accurately list the true 12 features (`packet_length`, `protocol_encoding`, `dst_port_class`, `src_port_ephemeral`, `event_rate_1m`, `burst_rate_10s`, `inter_arrival_mean`, `inter_arrival_std`, `packet_size_variance`, `payload_entropy`, `unique_dst_ips`, `unique_dst_ports`) rather than the hypothetical labels from earlier draft reports.
