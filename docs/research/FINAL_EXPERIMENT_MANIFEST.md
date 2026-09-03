# PhantomNet Final Experiment Manifest & Reproducibility Catalog

**Document Version:** 1.0.0  
**Repository Commit:** `94a08f750dcefc047e8ff6a3a95f4e20136e49ed`  
**Execution Environment:** Python 3.11.9 on Windows 11 (AMD/Intel x86_64, 16GB RAM)  
**Dependencies:** `scikit-learn==1.3.0`, `pandas==2.1.1`, `numpy==1.26.0`, `scipy==1.11.3`, `shap==0.44.0`, `xgboost==2.0.0`

---

## 1. Master Experiment Registry

| Experiment ID | Title / Purpose | Execution Script | Primary Dataset | Output Artifacts | Status |
|---|---|---|---|---|---|
| **EXP-ML-UNIFIED-001** | 15D Network Telemetry ML Training & Grid Search | `backend/scripts/unified_evaluation.py` | `labeled_events_15d_unified.csv` (SHA256: `9f2e...`) | `backend/ml/evaluation_output/evaluation_results.json` | **AUTHORITATIVE** |
| **EXP-ML-REPRO-002** | Independent Paper Metrics Regeneration | `experiments/reproduce_paper.py` | `labeled_events_v2_enhanced.csv` (SHA256: `7d1a...`) | `experiments/results/paper_metrics.json` | **VALIDATED** |
| **EXP-DBSCAN-NORM-003** | Controlled DBSCAN Normalization & E2E Benchmark | `experiments/run_dbscan_normalization_experiment.py` | `controlled_experiment_dataset.csv` (SHA256: `b4c1...`) | `experiments/results/dbscan_normalization/` | **AUTHORITATIVE** |
| **EXP-PUB-VALID-004** | Complete Multi-Layer Publication Validation Suite | `experiments/run_publication_validation.py` | Multi-dataset validation harness | `experiments/results/publication_validation/` | **VALIDATED** |
| **EXP-REGRESSION-005** | Full Software & API Suite Verification | `pytest` | 4,181 automated tests | `docs/post_fix_regression_test_week22_day4.md` | **PASS (100%)** |

---

## 2. Detailed Experiment Profiles

### Experiment 1: Unified ML Telemetry Evaluation (`EXP-ML-UNIFIED-001`)
* **Objective:** Benchmark supervised and unsupervised threat classifiers on the 15D network socket feature space.
* **Command:** `python backend/scripts/unified_evaluation.py`
* **Configuration:**
  - Seed: `42`
  - Split: 80% Train ($N=4,000$), 20% Test ($N=1,000$), Stratified by class.
  - Evaluation Space: 13 features (excluding $x_5, x_6$ to prevent feedback leakage).
  - Classifiers: Random Forest ($T=500, \text{depth}=20$), Isolation Forest ($n=100, \text{contamination}=0.05$), XGBoost ($T=200$).
  - Optimal Weights: $w_{RF} = 0.85, w_{IF} = 0.15$.
* **Primary Outputs:**
  - Test Accuracy: **96.90%**
  - 5-Fold CV Accuracy: **96.56% ± 0.37%**
  - Test Precision: **96.86%**
  - Test Recall: **92.67%**
  - Test F1: **0.9472**
  - ROC-AUC: **0.9569**
  - Artifact: [`backend/ml/evaluation_output/evaluation_results.json`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/evaluation_output/evaluation_results.json)

---

### Experiment 2: Controlled DBSCAN Normalization (`EXP-DBSCAN-NORM-003`)
* **Objective:** Quantify the effect of `StandardScaler` feature standardization on DBSCAN campaign clustering quality and autonomous end-to-end pipeline completion.
* **Command:** `python experiments/run_dbscan_normalization_experiment.py`
* **Configuration:**
  - Seed: `42`
  - Input: 100 events across 4 attack campaigns (SSH Brute Force, Web SQLi/Traversal, Port Scan, FTP Exfiltration) + benign noise.
  - DBSCAN Parameters: $eps=0.5, min\_samples=5$, Euclidean metric (held constant).
  - Conditions: Baseline (unscaled) vs. Normalized (`StandardScaler`).
* **Primary Outputs:**
  - Discovered Clusters: 0 (Baseline) vs. **2 (Normalized)**
  - Noise Ratio: 100.0% (Baseline) vs. **71.0% (Normalized)**
  - Adjusted Rand Index (ARI): 0.0000 (Baseline) vs. **0.2116 (Normalized, $p < 0.001$)**
  - Normalized Mutual Information (NMI): 0.0000 (Baseline) vs. **0.4680 (Normalized, $p < 0.001$)**
  - Silhouette Score: Undefined (Baseline) vs. **0.9895 (Normalized)**
  - Autonomous E2E Completion: **0.0% (0/30 runs)** vs. **100.0% (30/30 runs)**
  - Artifacts: [`experiments/results/dbscan_normalization/`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/dbscan_normalization)

---

### Experiment 3: Publication Validation & Latency Suite (`EXP-PUB-VALID-004`)
* **Objective:** Measure component synthesis latencies and validate MITRE ATT&CK, Snort/Sigma rule generation, and STIX 2.1 schemas.
* **Command:** `python experiments/run_publication_validation.py`
* **Configuration:** $N=100$ iterations per component.
* **Primary Outputs:**
  - Snort Rule Synthesis: Mean **0.488 ms**, Median **0.449 ms**, P95 **0.695 ms**
  - STIX 2.1 Construction: Mean **1.022 ms**, Median **0.970 ms**, P95 **1.335 ms**
  - Jinja2 Playbook Rendering: Mean **1.098 ms**, Median **0.348 ms**, P95 **0.484 ms**
  - MITRE Mapping Coverage: 12 signatures verified across 10 techniques and 8 tactics.
  - Artifacts: [`experiments/results/publication_validation/`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/publication_validation)

---

## 3. Dataset Forensics & Checksums

| Dataset Filename | Absolute Path | SHA256 Checksum | Rows | Domain | Role in Research |
|---|---|---|---|---|---|
| `labeled_events_15d_unified.csv` | `backend/ml/evaluation_output/` | `9f2e718b5b3236fa78dc71092e07171d7a31b659c40333db6a0662d5d8869c9b` | 5,000 | 15D Network Sockets | **Primary Paper Evaluation Dataset** |
| `controlled_experiment_dataset.csv` | `experiments/results/dbscan_normalization/` | `b4c107c132845c479421f2bb8bcf047246b14f885b5d19ec558be859345237ef` | 100 | Multi-Campaign 15D Sockets | **Authoritative DBSCAN Benchmark** |
| `labeled_events_v2_enhanced.csv` | `backend/ml/datasets/` | `7d1ad04313f80c6552bb76ee46fca475988544a4aa88ba7617b73c4f74d0ae8e` | 5,000 | 12D Host/Command Behavioral | Auxiliary Host-Behavioral Ablation |
