# PhantomNet ML-4: Dataset Provenance & Experimental Traceability Specification

## Executive Summary

This document formalizes the complete, end-to-end dataset provenance and experimental traceability architecture for the PhantomNet research program. It establishes a verifiable chain of custody from raw synthetic distribution definitions to published scientific tables, guaranteeing that every reported metric originates from an audited, reproducible, and leakage-free computational workflow.

---

## 1. Provenance Architecture & End-to-End Chain

The PhantomNet evaluation pipeline follows an explicit, un-broken, directed acyclic graph (DAG):

```text
Deterministic Synthetic Generator
(scripts/generate_remediated_dataset.py | Seed: 42)
                    ↓
Canonical 12D Network Flow Benchmark Dataset
(data/remediated_dataset_v3.csv | SHA-256: 390f6539... | 5000 x 13)
                    ↓
Stratified Monte Carlo Partitioning
(sklearn.model_selection.train_test_split | N=30 runs | Seeds: 100-129 | 80/20)
                    ↓
Strict Preprocessing Boundary
(StandardScaler fitted strictly on X_train | Zero Test Mutation)
                    ↓
Independent Estimator Training
(RandomForestClassifier [100 trees] + IsolationForest [100 trees, contam 0.10])
                    ↓
Calibrated Hybrid Ensemble Inference
(S_composite = 0.85 * P_RF + 0.15 * S_IF on X_test)
                    ↓
Inferential Statistical Testing
(Wilcoxon Signed-Rank, Paired t-test, Cohen's d, McNemar Exact, Fisher's Exact)
                    ↓
Machine-Readable Evidence Persistence
(experiments/results/statistical_tests.json | experiments/results/model_metrics.json)
                    ↓
Dynamic Publication Evidence Table
(experiments/results/publication_table.md via generate_publication_evidence.py)
```

---

## 2. Stage-by-Stage Forensic Specifications

### Stage 1: Deterministic Benchmark Generation
* **Executable Script:** [`scripts/generate_remediated_dataset.py`](file:///c:/Users/srira/Project/PhantomNet/scripts/generate_remediated_dataset.py)
* **Random Seeds:** `RANDOM_SEED = 42` applied to `np.random.seed(42)` and `random.seed(42)`.
* **Traffic Mixture:**
  * Benign ($n=3,500$): Web browsing ($55\%$), Network services DNS/NTP ($25\%$), Admin sync ($20\%$).
  * Malicious ($n=1,500$): SSH brute force ($35\%$), Web exploits ($30\%$), Reconnaissance port scans ($20\%$), C2 exfiltration ($15\%$).
* **Statistical Overlap:** Benign and malicious feature distributions possess wide overlapping supports across all 12 dimensions.
* **Trivial Separability Defense:** Enforces that no single feature achieves $\ge 85\%$ accuracy via decision stump or thresholding before writing to disk.

### Stage 2: Canonical Benchmark Dataset
* **Storage Location:** [`data/remediated_dataset_v3.csv`](file:///c:/Users/srira/Project/PhantomNet/data/remediated_dataset_v3.csv)
* **Backend Mirror:** [`backend/ml/datasets/labeled_events_remediated.csv`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/datasets/labeled_events_remediated.csv)
* **Immutable Checksum:** `SHA-256 = 390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363`
* **Schema Contract:** Exactly 12 features adhering to `CANONICAL_FEATURE_NAMES` plus target `label` (0 = benign, 1 = malicious).
* **Integrity:** Zero NaN values, zero infinite values, zero duplicate rows, zero conflicting duplicate labels.

### Stage 3: Train/Test Partitioning
* **Partitioning Strategy:** Repeated Stratified Monte Carlo cross-validation ($N=30$).
* **Split Ratio:** $80\%$ Training ($N_{\text{train}} = 4,000$), $20\%$ Held-Out Test ($N_{\text{test}} = 1,000$).
* **Seed Schedule:** Explicit and deterministic sequence: `seed = 100 + i` for $i \in \{0, \dots, 29\}$.
* **Cross-Split Independence:** For every run, $X_{\text{train}} \cap X_{\text{test}} = \emptyset$. Minimum normalized Euclidean distance between train and test vectors is $\ge 0.0693$.

### Stage 4: Preprocessing Isolation
* **Transformer:** `sklearn.preprocessing.StandardScaler`.
* **Execution Boundary:** Scaler is instantiated fresh inside each loop iteration:
  ```python
  scaler = StandardScaler()
  X_train_scaled = scaler.fit_transform(X_train)
  X_test_scaled = scaler.transform(X_test)
  ```
* **Leakage Proof:** The test set is transformed strictly with parameters learned on `X_train`. The test data is never passed to `fit()` or `fit_transform()`.

### Stage 5: Estimator Training & Calibration
* **Supervised Estimator:** `RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_split=5, min_samples_leaf=2, random_state=seed, n_jobs=-1)`.
* **Unsupervised Estimator:** `IsolationForest(n_estimators=100, contamination=0.10, random_state=seed, n_jobs=-1)`.
* **Score Calibration:** Raw Isolation Forest anomaly score $s_{\text{raw}} = - \text{score\_samples}(X)$ is linearly mapped to $[0, 1]$:
  $$S_{\text{IF}} = \frac{s_{\text{raw}} - \min(s_{\text{raw}})}{\max(s_{\text{raw}}) - \min(s_{\text{raw}}) + 10^{-9}}$$
* **Ensemble Formulation:** Strictly enforces canonical ML-2 weights:
  $$S_{\text{composite}} = 0.85 \cdot P_{\text{RF}} + 0.15 \cdot S_{\text{IF}}$$

### Stage 6: Inferential Statistical Testing
* **Hypothesis Testing:** Paired evaluations across $N=30$ runs comparing Calibrated Hybrid Ensemble against Standalone Random Forest and Standalone Isolation Forest:
  * Two-sided Wilcoxon signed-rank test.
  * Two-sided paired Student's t-test.
  * Cohen's d effect size for paired samples: $d = \frac{\bar{D}}{s_D}$.
* **Contingency Analysis (Primary Held-Out Test Split $N=1,000$):**
  * $2 \times 2$ classification discordance table ($a$: both correct, $b$: RF only, $c$: Ensemble only, $d$: both incorrect).
  * Exact McNemar test using binomial distribution: $p = \text{binom\_test}(\min(b, c), b+c, p=0.5)$.
  * Two-tailed Fisher's exact test.

### Stage 7: Evidence Compilation & Publication
* **Generator:** [`experiments/generate_publication_evidence.py`](file:///c:/Users/srira/Project/PhantomNet/experiments/generate_publication_evidence.py).
* **Source Artifacts:** Directly loads JSON metrics from [`experiments/results/statistical_tests.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/statistical_tests.json) and [`experiments/results/model_metrics.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/model_metrics.json).
* **Zero Hardcoding Guarantee:** All markdown tables in [`experiments/results/publication_table.md`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/publication_table.md) are constructed programmatically from the JSON outputs of executable experiments.

---

## 3. Publication Claim Traceability Matrix

| Reported Claim / Table Metric | Experimental Trace Path | Random Seed Policy | Primary Artifact |
| :--- | :--- | :--- | :--- |
| **RF Mean Accuracy ($93.27\%$)** | `EXP-STAT-N30-CLASSIFICATION` $\rightarrow$ `X_test` evaluation across 30 Monte Carlo runs | Seeds $100$ to $129$ | `experiments/results/statistical_tests.json` |
| **Ensemble Mean Accuracy ($92.73\%$)** | `EXP-STAT-N30-CLASSIFICATION` $\rightarrow$ $0.85 \text{ RF} + 0.15 \text{ IF}$ ensemble score | Seeds $100$ to $129$ | `experiments/results/statistical_tests.json` |
| **Ensemble FPR Reduction ($0.75\%$ vs $1.03\%$)** | `EXP-STAT-N30-CLASSIFICATION` $\rightarrow$ FPR evaluation on held-out test splits | Seeds $100$ to $129$ | `experiments/results/statistical_tests.json` |
| **Wilcoxon FPR $p$-value ($1.52 \times 10^{-4}$)** | Paired Wilcoxon signed-rank test across 30 paired FPR observations | Seeds $100$ to $129$ | `experiments/results/statistical_tests.json` |
| **Paired $t$-test FPR $p$-value ($2.82 \times 10^{-5}$)** | Paired Student's t-test on FPR differences across 30 runs | Seeds $100$ to $129$ | `experiments/results/statistical_tests.json` |
| **Cohen's $d$ Effect Size ($-0.95$)** | Computed on paired differences of FPR | Seeds $100$ to $129$ | `experiments/results/statistical_tests.json` |
| **Discordance McNemar $p$-value ($0.0703$)** | Binomial exact test on discordant predictions ($b=7, c=1$) | Seed $100$ | `experiments/results/statistical_tests.json` |
| **DBSCAN Discovered Clusters ($4$)** | Remediated standardized DBSCAN clustering on synthetic honeypot campaigns | Seed $42$ | `experiments/results/clustering_metrics.json` |
| **Pipeline Latency Mean ($1.077\text{ ms}$)** | 100 warm iterations through raw extraction and scoring service | Seed $42$ | `experiments/results/latency_metrics.json` |
| **Autonomous E2E Pipeline ($14/14\text{ Passed}$)** | End-to-end integration test from packet ingestion to STIX/Sigma export | Seed $42$ | `experiments/results/e2e_metrics.json` |

---

## 4. Historical Dataset Quarantine Governance

1. **Quarantine Isolation:** Contaminated historical datasets (`data/training_dataset.csv`, `data/ground_truth.csv`, and `backend/ml/datasets/labeled_events_v2_enhanced.csv`) are strictly quarantined.
2. **Execution Boundary Enforcement:**
   * Automated tests (`test_req_s_no_stale_active_dataset_references` in `tests/experiments/test_ml4_dataset_integrity.py`) scan active codebase files to ensure legacy datasets are never consumed by production or evaluation routines.
   * Model loaders (`backend/ml/model_loader.py`) reject checkpoints trained on non-canonical feature definitions.
3. **Audit Preservation:** Legacy datasets remain preserved in repository history for forensic auditability and baseline verification, accompanied by explicit warning notices.
