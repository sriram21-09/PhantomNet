# PHANTOMNET — ML & DATA REPOSITORY INVENTORY
**Audit Date:** 2026-10-01  
**Scope:** Complete Catalog of Machine Learning, Data Ingestion, Threat Scoring, Clustering, Explainability, Evaluation, and Research Artifacts  
**Audit Standard:** Forensic Repository Inspection (Phase ML-1)

---

## 1. Dataset Files

| Category | File Path | Format | Size | Rows × Cols | SHA-256 Checksum | Target Column | Role & Status |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- | :--- |
| **Clean Benchmark** | `data/remediated_dataset_v3.csv` | CSV | 267 KB | 5,000 × 13 | `390f653966410e70...` | `label` | Active Canonical Dataset (Clean, no leakage) |
| **Clean Backup** | `backend/ml/datasets/labeled_events_remediated.csv` | CSV | 267 KB | 5,000 × 13 | `390f653966410e70...` | `label` | Replica of `remediated_dataset_v3.csv` |
| **Historical/Overfit** | `backend/ml/datasets/labeled_events_v2_enhanced.csv` | CSV | 239 KB | 5,000 × 13 | `a2e22e7cbe8a5c6c...` | `label` | Quarantined (3 features with 100% artificial separation) |
| **Historical/Leaked** | `backend/ml/evaluation_output/labeled_events_15d_unified.csv` | CSV | 389 KB | 5,000 × 16 | `432fb772ffc4ae6f...` | `label` | Quarantined (Contains `threat_score`, `malicious_flag_ratio`) |
| **Legacy Training** | `data/training_dataset.csv` | CSV | 17.8 KB | 232 × 16 | `f3621ac80e74c9d7...` | `label` | Legacy (Contains target-derived fields) |
| **Ground Truth** | `data/ground_truth.csv` | CSV | 17.9 KB | 200 × 10 | `753bbe729828b2ca...` | `is_malicious` | Legacy Ground Truth (Contains `threat_score`) |
| **Base Events** | `data/week6_base_events.csv` | CSV | 223 B | 13 × 8 | `26d2d987a1fe6b09...` | N/A | Legacy test fixture |
| **Clustering Dataset** | `experiments/results/dbscan_normalization/controlled_experiment_dataset.csv` | CSV | 20.6 KB | 100 × 29 | `3f374afdc62bbf4b...` | `ground_truth_campaign` | DBSCAN benchmark fixture |

---

## 2. Dataset Generation Scripts

| Script Path | Purpose | Output File | Status |
| :--- | :--- | :--- | :--- |
| `scripts/generate_remediated_dataset.py` | Generates 12D continuous flow features with realistic overlap | `data/remediated_dataset_v3.csv` | Active & Verified |
| `scripts/generate_ground_truth.py` | Historical ground truth generator with hardcoded threat scores | `data/ground_truth.csv` | Legacy |
| `backend/ml/update_dataset.py` | Generates behavioral/terminal command logs | `backend/ml/datasets/labeled_events_v2_enhanced.csv` | Quarantined (Overfit) |

---

## 3. Feature Extractors & Feature Engineering Modules

| Module Path | Primary Class | Feature Count | Target Domain | Concurrency Model | Status |
| :--- | :--- | :---: | :--- | :--- | :--- |
| `backend/ml/feature_extractor.py` | `FeatureExtractor` | **12** | Network Flow (continuous) | Thread `RLock` + LRU sliding window | **ACTIVE CANONICAL** |
| `backend/ml/feature_engineering_v2.py` | `FeatureExtractorV2` | **12** | Terminal/Host commands | Unlocked `defaultdict` | Legacy / Secondary |
| `backend/ml/feature_engineering_complete.py` | `CompleteFeatureExtractor` | **32** | Combined Host + Flow | Unlocked `defaultdict` | Conflicting / Obsolete |
| `backend/ml_engine/profiler.py` | `TrafficProfiler` | N/A | IP profiling & baseline | Internal in-memory | Active Auxiliary |

---

## 4. Preprocessing & Scaling Pipelines

| Path | Components | Persistence File | Status |
| :--- | :--- | :--- | :--- |
| `backend/ml/preprocessing.py` | `StandardScaler`, label encoder | In-memory / dynamic | Active Utility |
| `backend/ml/preprocessor.py` | `EventPreprocessor` | In-memory | Legacy |
| `backend/ml/models/feature_scaler_v2.pkl` | `StandardScaler` (12 features) | Pickle / Joblib | Serialized Scaler |
| `backend/ml/evaluation_output/scaler_unified.pkl` | `StandardScaler` (13 features) | Pickle / Joblib | Legacy Scaler |
| `ml_models/registry/scaler.pkl` | `StandardScaler` (12 features) | Pickle / Joblib | Registry Scaler |

---

## 5. Training & Retraining Scripts

| Script Path | Algorithm(s) | Dataset Consumed | Output Model Artifact | Status |
| :--- | :--- | :--- | :--- | :--- |
| `experiments/reproduce_clean_paper.py` | Random Forest + Isolation Forest | `data/remediated_dataset_v3.csv` | In-memory N=30 Monte Carlo evaluation | Active Benchmark |
| `backend/ml/train_enhanced_model.py` | Random Forest (100 trees) | `datasets/labeled_events_v2_enhanced.csv` | `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl` | Legacy Training |
| `backend/ml/retrain_isolation_forest.py` | Isolation Forest | Unsupervised logs | `ml_models/iforest_baseline.pkl` | Maintenance |
| `backend/ml_engine/retraining_pipeline.py` | Random Forest | SQLite `PacketLog` | In-memory validation | Active Background |
| `backend/ml/run_training.py` | Random Forest | `week6_test_events_balanced.csv` | Local test model | Obsolete |
| `backend/ml/training_framework.py` | Generic Scikit-Learn wrapper | Pluggable CSV | Pluggable | Framework |

---

## 6. Serialized Model Checkpoints & Registry

| File Path | Architecture | Ingested Features | Classes | File Size | Serialization | Status |
| :--- | :--- | :---: | :---: | :---: | :--- | :--- |
| `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl` | `Pipeline(StandardScaler, RF)` | **12** | `[0, 1]` | 5.88 MB | Joblib compressed | **ACTIVE PRODUCTION RF** |
| `ml_models/attack_classifier_latest.pkl` | `Pipeline(StandardScaler, RF)` | **12** | `[0, 1]` | 5.88 MB | Joblib compressed | Identical to registry |
| `ml_models/iforest_baseline.pkl` | `IsolationForest` | **12** | N/A | 1.05 MB | Pickle protocol 4 | **ACTIVE BASELINE IF** |
| `ml_models/registry/anomaly_detector.pkl` | `IsolationForest` | **32** | N/A | 312 KB | Joblib compressed | Obsolete (Expects 32D) |
| `backend/ai_engine/model_rf.pkl` | `RandomForestClassifier` | **6** | `[0, 1]` | 101 KB | Joblib compressed | Obsolete (Expects 6D) |
| `backend/ml/evaluation_output/rf_model_unified.pkl` | `RandomForestClassifier` | **13** | `[0, 1]` | 15.6 MB | Joblib compressed | Legacy (Expects 13D) |
| `backend/ml/evaluation_output/if_model_unified.pkl` | `IsolationForest` | **13** | N/A | 1.31 MB | Joblib compressed | Legacy (Expects 13D) |
| `backend/ml/models/attack_classifier_v3_enhanced.pkl` | `RandomForestClassifier` | **12** | `[0, 1]` | 399 KB | Joblib compressed | Legacy standalone RF |
| `models/isolation_forest_optimized_v2.pkl` | `IsolationForest` | **15** | N/A | 128 KB | Joblib compressed | Obsolete (Expects 15D) |
| `ml_models/lstm_attack_predictor.h5` | Keras / TensorFlow LSTM | N/A | N/A | 24 B | Pointer / Stub | Mock / Unused |
| `ml_models/lstm_attack_predictor.h5.mock.pkl` | Mock LSTM predictor | N/A | N/A | 6.5 KB | Pickle | Test fixture |

---

## 7. Isolation Forest Implementations (Duplicate/Conflicting)

1. **Implementation A (Active Ingestion):** `backend/ml_engine/unsupervised_detector.py`
   - Class: `UnsupervisedAnomalyDetector`
   - Model Path: `ml_models/iforest_baseline.pkl`
   - Feature Contract: Canonical 12 features (`ml.feature_extractor.FeatureExtractor`)
   - Role: Used by `ThreatAnalyzerService` background worker.
2. **Implementation B (Conflicting Obsolete):** `backend/ml/anomaly_detector.py`
   - Class: `AnomalyDetector`
   - Model Path: `ml_models/registry/anomaly_detector.pkl`
   - Feature Contract: 32 features (`CompleteFeatureExtractor`)
   - Role: Unused by main production flow; conflicting schema.
3. **Implementation C (Research Benchmark):** `experiments/reproduce_clean_paper.py`
   - Class: Standalone `IsolationForest(contamination=0.30)` inside scikit-learn pipeline.

---

## 8. Random Forest Implementations

1. **Implementation A (Production Ingestion):** `backend/ml/model_loader.py` + `backend/ml/threat_scoring_service.py`
   - Model: `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl` (12D Pipeline)
   - Interface: `.predict_proba()` returning probability of malicious class.
2. **Implementation B (Retraining Loop):** `backend/ml_engine/retraining_pipeline.py`
   - Model: Re-fits on `PacketLog` entries using canonical features.
3. **Implementation C (Legacy Engine):** `backend/ai_engine/model_rf.pkl` (6 features, obsolete).

---

## 9. Ensemble Logic & Weight Configurations

1. **Configuration A (Production Scoring Service):** `backend/ml/threat_scoring_service.py`
   - Only invokes `model.predict_proba()` (Standalone RF) if model has probability output.
   - Anomaly branch (`elif hasattr(model, 'predict')`) is only executed if model lacks `predict_proba`.
2. **Configuration B (Background Threat Analyzer):** `backend/services/threat_analyzer.py` (lines 294–306)
   - If LSTM score available: `0.50 * RF + 0.30 * LSTM + 0.20 * Anomaly`.
   - If LSTM not available: `0.85 * RF + 0.15 * Anomaly` (matches publication claim).
3. **Configuration C (Conflicting Class):** `backend/ml/models/ensemble_predictor.py`
   - Hardcoded weights: `w_rf = 0.70`, `w_if = 0.30` (Direct conflict with 0.85/0.15).
4. **Configuration D (Experimental Paper Script):** `experiments/reproduce_clean_paper.py`
   - Hardcoded weights: `0.85 * RF + 0.15 * IF` calibrated score.

---

## 10. Threat Scoring Services & Severity Mappings

| Service Module | Method | Canonical Thresholds | Decision Thresholds |
| :--- | :--- | :--- | :--- |
| `backend/ml/threat_scoring_service.py` | `score_threat()` | `CRITICAL >= 0.80`, `HIGH >= 0.60`, `MEDIUM >= 0.40`, `LOW < 0.40` | `BLOCK >= 0.80`, `ALERT >= 0.50`, `ALLOW < 0.50` |
| `backend/services/threat_analyzer.py` | `_poll_and_score()` | `CRITICAL >= 0.80`, `HIGH >= 0.60`, `MEDIUM >= 0.40`, `LOW < 0.40` | `BLOCK >= 0.80`, `ALERT >= 0.50`, `ALLOW < 0.50` |
| `backend/scripts/threat_severity_optimization.py` | Dynamic optimization | Quantile-based dynamic thresholds | Experimental tuning |

---

## 11. SHAP & Explainability Code

| Module Path | Target Model | Handling of Pipelines | Local Additivity | Status |
| :--- | :--- | :--- | :---: | :--- |
| `backend/ml_engine/explainability.py` | `RandomForestClassifier` or `Pipeline` | Extracted tree estimator + scaled inputs | **VERIFIED** ($|\Delta| < 10^{-6}$) | Active Canonical |
| `backend/ml/evaluation.py` | Global evaluation | Legacy tree explainer | Unscaled | Legacy |

---

## 12. Campaign Clustering (DBSCAN) Code

| Module Path | Algorithm | Scaling & Preprocessing | Epsilon / Min Samples | Status |
| :--- | :--- | :--- | :---: | :--- |
| `backend/ml_engine/campaign_clustering.py` | `DBSCAN` | `log1p` on volume features + `StandardScaler` | $\epsilon=0.80, \text{min}=4$ | **ACTIVE CANONICAL** |
| `experiments/validate_remediated_clustering.py` | `DBSCAN` | Controlled comparison (unscaled vs. scaled) | $\epsilon=0.80, \text{min}=4$ | Active Benchmark |
| `experiments/run_dbscan_normalization_experiment.py` | `DBSCAN` | Baseline normalization tests | Variable | Experimental |

---

## 13. MLflow Integration & Tracking

- **Config File:** `backend/ml/config/mlflow_env.py`
- **Tracking URI:** `sqlite:///mlruns/mlflow.db` (local fallback)
- **Production Model Name:** `AttackClassifier_Enhanced`
- **Fallback Policy:** If MLflow server is offline, `backend/ml/model_loader.py` gracefully falls back to local disk artifact `ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl`.

---

## 14. Test Suites

| Directory | Scope | Test Count | Passing | Failing | Primary Focus |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `tests/ml/` | ML unit & adversarial | 40 | 40 | 0 | Feature extraction, SHAP, models, scoring |
| `tests/backend/` | Backend ML services | 11 | 11 | 0 | Schema validation, concurrency, thresholds |
| `tests/integration/` | Integration pipelines | 8 | 8 | 0 | E2E data flow, pattern detection, latency |
| `tests/e2e/` | SOAR & playbook flows | 235 | 235 | 0 | Playbook synthesis, STIX, MITRE ATT&CK |
| `tests/experiments/` | Evidence integrity | 6 | 6 | 0 | Dataset hashing, leakage, provenance |
| `tests/e2e/test_full_pipeline_e2e.py` | Autonomous pipeline | 14 stages | 14 | 0 | Ingestion $\to$ STIX 2.1 & Sigma |

---

## 15. Experimental & Statistical Validation Scripts

| Script Path | Objective | Outputs Produced |
| :--- | :--- | :--- |
| `experiments/reproduce_clean_paper.py` | $N=30$ Monte Carlo repeated runs, paired Wilcoxon, McNemar, paired t-tests | `experiments/results/runs/*.json`, `statistical_tests.json`, `model_metrics.json` |
| `experiments/validate_remediated_clustering.py` | DBSCAN benchmark comparing unscaled vs scaled performance | `experiments/results/clustering_metrics.json` |
| `experiments/run_latency_benchmark.py` | 100 warm iterations profiling stage-by-stage latency | `experiments/results/latency_observations.csv`, `latency_metrics.json` |
| `experiments/generate_publication_evidence.py` | Aggregates artifacts into markdown publication tables | `experiments/results/publication_table.md` |
| `experiments/reproduce_all.py` | Master orchestrator running all experiments from scratch | All result files |

---

## 16. Research & Publication Artifacts

- Summary Table: `experiments/results/publication_table.md`
- Machine-Readable Manifest: `experiments/results/EXPERIMENT_MANIFEST.json`
- Statistical Results: `experiments/results/statistical_tests.json` & `statistical_tests.csv`
- Raw Runs: `experiments/results/runs/run_001.json` through `run_030.json`
- Latency Raw Data: `experiments/results/latency_observations.csv` (520 rows)
- E2E Execution Evidence: `experiments/results/e2e_metrics.json`

---

## 17. Backend API Endpoints Consuming ML

| Endpoint | Method | Implementation File | Consumed ML Service |
| :--- | :---: | :--- | :--- |
| `/api/threats/summary` | GET | `backend/main.py` | Aggregated threat stats from DB |
| `/api/threats/alerts` | GET | `backend/main.py` | High/Critical scored events |
| `/api/threats/indicators` | GET | `backend/main.py` | IOC and threat correlations |
| `/api/threats/top-vectors` | GET | `backend/main.py` | Threat vector classification |
| `/api/v1/advanced/campaigns` | GET | `backend/main.py` | `CampaignClusterer.cluster_events()` |
| `/api/v1/patterns/advanced` | GET | `backend/main.py` | `AdvancedPatternDetector` |
| `/api/v1/threats/score` | POST | `backend/api/threat_api.py` | `ThreatScoringService.score_threat()` |
| `/analyze-patterns` | POST | `backend/api/hunting.py` | Pattern detection engine |
| `/threat-metrics` | GET | `backend/api/metrics.py` | Scoring latency & accuracy telemetry |
| `/predictions/recent` | GET | `backend/api/model_metrics.py`| Model registry inference logs |
| `/risk-score` | GET | `backend/api/predictive.py` | Predictive ML risk scoring |

---

## 18. Frontend Consumers of ML APIs

- `frontend/src/pages/ThreatIntelligence.tsx` (Threat summary, top attack vectors)
- `frontend/src/pages/CampaignAnalysis.tsx` (DBSCAN clusters, attack campaigns)
- `frontend/src/components/ThreatAlertsTable.tsx` (Real-time scored events)
- `frontend/src/components/ExplainabilityModal.tsx` (SHAP waterfall & bar charts)
*(Note: Neural Operations Center is excluded per user directive)*

---

## 19. Database Schemas Involved in ML

| Table / Model | Columns Storing ML Data | Database Engine |
| :--- | :--- | :--- |
| `PacketLog` | `threat_score` (float), `threat_level` (str), `anomaly_score` (float), `confidence` (float), `decision` (str) | SQLite / PostgreSQL |
| `SentinelPlaybook` | `campaign_id` (str), `service_type` (str), `attack_type` (str), `confidence_score` (float), `quality_score` (float) | SQLite / PostgreSQL |
| `AttackCampaign` | `campaign_id` (str), `cluster_label` (int), `confidence` (float), `ioc_count` (int) | SQLite / PostgreSQL |

---

## 20. Duplicate or Obsolete ML Implementations

1. **Obsolete Feature Extractor:** `backend/ml/feature_engineering_complete.py` (32 features, combines host commands with flow; unused by production).
2. **Conflicting Ensemble Predictor:** `backend/ml/models/ensemble_predictor.py` (Weights 0.70/0.30 vs canonical 0.85/0.15).
3. **Conflicting Isolation Forest:** `backend/ml/anomaly_detector.py` (32 features vs canonical 12 features in `backend/ml_engine/unsupervised_detector.py`).
4. **Obsolete Checkpoints:** `backend/ai_engine/model_rf.pkl` (6 features), `backend/ml/evaluation_output/rf_model_unified.pkl` (13 features), `ml_models/registry/anomaly_detector.pkl` (32 features).
