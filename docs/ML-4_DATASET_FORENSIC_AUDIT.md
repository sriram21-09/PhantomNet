# PhantomNet ML-4: Dataset Provenance, Leakage Re-Verification & Statistical Integrity Audit

## Executive Summary

Phase ML-4 provides a comprehensive forensic audit and empirical re-verification of the active canonical dataset (`data/remediated_dataset_v3.csv`), its generation mechanism, train/test preprocessing boundaries, cross-split isolation, and complete experimental statistical evaluation pipeline.

The audit establishes defensible evidence that:
1. The active dataset contains **zero target leakage** and **zero trivial separability** (single-feature decision stump accuracy $\le 81.34\%$, single-feature ROC-AUC $\le 0.8327$).
2. The dataset contains **zero duplicate rows**, **zero duplicate feature vectors**, and **zero conflicting labels**.
3. Preprocessing (StandardScaler) is strictly fitted on training splits, with zero test information leakage into training transformations.
4. Legacy contaminated datasets (`data/training_dataset.csv` with circular `threat_score`, and `backend/ml/datasets/labeled_events_v2_enhanced.csv` with 100% artificial separation) are completely quarantined and absent from all active production and experiment pipelines.
5. Experimental evaluation ($N=30$ Monte Carlo repeated runs) and inferential statistics (Wilcoxon signed-rank, paired t-tests, Cohen's d, McNemar exact tests) are generated programmatically without manual hardcoding.
6. Run A versus Run B execution demonstrates exact bitwise determinism across discrete predictions and classification metrics, and numerical identity within floating-point epsilon ($\le 2.22 \times 10^{-16}$) for continuous ensemble probabilities.

---

## 1. Dataset Identity & Physical Verification

The active canonical dataset is stored at [`data/remediated_dataset_v3.csv`](file:///c:/Users/srira/Project/PhantomNet/data/remediated_dataset_v3.csv) with an identical replica at [`backend/ml/datasets/labeled_events_remediated.csv`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/datasets/labeled_events_remediated.csv).

| Property | Audited Value | Compliance Status |
| :--- | :--- | :---: |
| **File Path** | `data/remediated_dataset_v3.csv` | **VERIFIED** |
| **SHA-256 Checksum** | `390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363` | **VERIFIED** |
| **Backend Replica SHA-256** | `390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363` | **MATCH** |
| **Total Row Count ($N$)** | `5,000` | **VERIFIED** |
| **Total Column Count** | `13` (12 features + 1 target) | **VERIFIED** |
| **Target Column Name** | `label` | **VERIFIED** |
| **Target Domain** | Binary integer: $\{0, 1\}$ | **VERIFIED** |
| **Class Distribution** | Benign ($0$): $3,500$ ($70.00\%$), Malicious ($1$): $1,500$ ($30.00\%$) | **VERIFIED** |
| **Missing / NaN Values** | `0` (0.00%) | **VERIFIED** |
| **Infinite Values ($\pm\infty$)** | `0` (0.00%) | **VERIFIED** |
| **Constant Columns** | `0` (None) | **VERIFIED** |
| **Non-Numeric Dtypes** | `0` (All int64 / float64) | **VERIFIED** |

---

## 2. Provenance & Generator Audit

The active dataset is generated deterministically by [`scripts/generate_remediated_dataset.py`](file:///c:/Users/srira/Project/PhantomNet/scripts/generate_remediated_dataset.py).

* **RNG Initialization:** Fixed seed `RANDOM_SEED = 42` applied to `np.random.seed(42)` and `random.seed(42)`.
* **Traffic Profiles & Composition:**
  * **Benign Traffic ($n=3,500$, $70\%$):**
    * Web browsing (HTTP/HTTPS mix of small ACKs, GET requests, responses): $55\%$
    * DNS / NTP / SNMP monitoring services: $25\%$
    * Administrative SSH / Sync / CI/CD pipelines: $20\%$
  * **Malicious Traffic ($n=1,500$, $30\%$):**
    * SSH brute force (rapid bursts and low-and-slow probes): $35\%$ ($n=525$)
    * Web application exploits (SQLi, LFI, RCE): $30\%$ ($n=450$)
    * Reconnaissance port sweeps (SYN scans across port classes): $20\%$ ($n=300$)
    * Data exfiltration & C2 tunneling: $15\%$ ($n=225$)
* **Synthetic Class-Conditional Distributions vs. Leakage:**
  * Distributions reflect realistic network physics: mechanized attacks display lower inter-arrival timing variances and tighter entropy bands than heterogeneous human traffic.
  * Overlapping distributions are enforced by design. Benign and malicious feature ranges overlap across all 12 dimensions.
* **Deterministic Regeneration:** Re-running `python scripts/generate_remediated_dataset.py` produces the exact SHA-256 checksum `390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363` with bitwise identity.

---

## 3. Feature Inventory & Physical Quantities

The 12 canonical features adhere strictly to the sequence defined in [`backend/ml/config/feature_schema.py`](file:///c:/Users/srira/Project/PhantomNet/backend/ml/config/feature_schema.py):

| Index | Feature Name | Dtype | Min | Max | Mean | Std Dev | Sample Variance |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| 0 | `packet_length` | `int64` | 40 | 1500 | 487.61 | 439.04 | 192,752.25 |
| 1 | `protocol_encoding` | `int64` | 1 | 3 | 1.18 | 0.36 | 0.13 |
| 2 | `dst_port_class` | `int64` | 1 | 3 | 1.48 | 0.51 | 0.26 |
| 3 | `src_port_ephemeral` | `int64` | 0 | 1 | 0.97 | 0.17 | 0.03 |
| 4 | `event_rate_1m` | `float64` | 1.13 | 55.43 | 14.19 | 11.06 | 122.37 |
| 5 | `burst_rate_10s` | `int64` | 1 | 15 | 3.01 | 2.24 | 5.03 |
| 6 | `inter_arrival_mean` | `float64` | 0.05 | 27.24 | 5.48 | 5.47 | 29.92 |
| 7 | `inter_arrival_std` | `float64` | 0.01 | 36.31 | 4.88 | 6.26 | 39.21 |
| 8 | `packet_size_variance` | `float64` | 0.00 | 179,936.85 | 17,994.48 | 22,937.93 | 526,148,417.46 |
| 9 | `payload_entropy` | `float64` | 1.50 | 5.60 | 3.84 | 0.68 | 0.46 |
| 10 | `unique_dst_ips` | `int64` | 1 | 6 | 1.34 | 0.81 | 0.65 |
| 11 | `unique_dst_ports` | `int64` | 1 | 25 | 2.50 | 3.67 | 13.44 |

---

## 4. Target Inventory & Separation

* **Canonical Target:** Column `label` in `data/remediated_dataset_v3.csv`.
* **Absence of Leakage Columns:** Static and dynamic inspection confirms that forbidden columns (`threat_score`, `is_malicious`, `attack_cat`, `malicious_flag_ratio`, `predicted_label`) are **completely absent** from the active dataset.
* **Extraction Independence:** `FeatureExtractor.extract_features()` and `dict_to_canonical_vector()` operate exclusively on raw packet dictionary payloads and ignore any target keys present in input event streams.

---

## 5. Statistical Target Leakage Audit

To verify the absence of circularity or trivial separability, four independent statistical screening tests were computed across all 12 canonical features against the binary target:

| Feature Name | Pearson Corr ($r$) | Decision Stump Acc | Single-Feature ROC-AUC | Mutual Information ($I$) | Leakage Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `packet_length` | $+0.0983$ | $71.56\%$ | $0.5294$ | $0.1116$ | **CLEAN** |
| `protocol_encoding` | $-0.1700$ | $70.00\%$ | $0.5722$ | $0.0380$ | **CLEAN** |
| `dst_port_class` | $+0.3706$ | $73.58\%$ | $0.6585$ | $0.0744$ | **CLEAN** |
| `src_port_ephemeral` | $+0.0903$ | $70.00\%$ | $0.5172$ | $0.0093$ | **CLEAN** |
| `event_rate_1m` | $+0.3873$ | $74.32\%$ | $0.7452$ | $0.0983$ | **CLEAN** |
| `burst_rate_10s` | $+0.3556$ | $73.40\%$ | $0.6909$ | $0.0665$ | **CLEAN** |
| `inter_arrival_mean` | $-0.1383$ | $72.26\%$ | $0.6419$ | $0.0663$ | **CLEAN** |
| `inter_arrival_std` | $-0.3507$ | $80.36\%$ | $0.8327$ | $0.1810$ | **CLEAN** |
| `packet_size_variance` | $-0.1483$ | $81.34\%$ | $0.7135$ | $0.1725$ | **CLEAN** |
| `payload_entropy` | $-0.1047$ | $73.32\%$ | $0.5436$ | $0.0927$ | **CLEAN** |
| `unique_dst_ips` | $+0.3212$ | $74.80\%$ | $0.5913$ | $0.0636$ | **CLEAN** |
| `unique_dst_ports` | $+0.3457$ | $76.00\%$ | $0.5983$ | $0.0882$ | **CLEAN** |

### Findings:
1. **Majority Class Baseline:** For a $70:30$ dataset, a naive constant predictor achieves $70.00\%$ accuracy. The maximum single-feature decision stump accuracy observed is **$81.34\%$** (`packet_size_variance`), well below the $85\%$ trivial separability ceiling.
2. **ROC-AUC Bounds:** Maximum single-feature ROC-AUC is **$0.8327$** (`inter_arrival_std`), confirming substantial class overlap and zero perfect separators ($AUC < 0.90$).
3. **Correlation Bounds:** Correlations range between $-0.3507$ and $+0.3873$. No linear dependency approaches circularity ($|r| \ll 1.0$).
4. **Mutual Information:** Values span $0.0093$ to $0.1810$ nats, exhibiting realistic non-deterministic statistical dependence.

---

## 6. Duplicate & Cross-Split Contamination Audit

* **Full Row Duplicates:** **0**
* **Duplicate Feature Vectors ($X$):** **0**
* **Conflicting Duplicate Labels ($X_i = X_j \land y_i \ne y_j$):** **0**
* **Cross-Split Leakage Across 30 Repetitions:** For every split ($i \in \{100, \dots, 129\}$), $X_{\text{train}} \cap X_{\text{test}} = \emptyset$. Zero overlapping feature vectors exist between training and test sets.
* **Nearest-Neighbor Split Proximity:** Minimum normalized Euclidean distance between test vectors and training vectors is strictly positive ($\min d \ge 0.0693$), proving the absence of synthetic duplicate copies or near-zero perturbation clones across splits.

---

## 7. Preprocessing & Split Boundary Audit

Inspection of [`experiments/reproduce_clean_paper.py`](file:///c:/Users/srira/Project/PhantomNet/experiments/reproduce_clean_paper.py) confirms that:
1. `train_test_split(..., test_size=0.20, random_state=seed, stratify=y)` executes **before** any feature scaling or modeling.
2. `StandardScaler` is initialized independently in each run:
   ```python
   scaler = StandardScaler()
   X_train_s = scaler.fit_transform(X_train)
   X_test_s = scaler.transform(X_test)
   ```
3. Training parameters (`mean_`, `scale_`) are fitted strictly on `X_train`.
4. Test set transformation applies training-derived parameters without updating or leaking test-set statistics.
5. In production inference, models are encapsulated as a single scikit-learn `Pipeline([('scaler', StandardScaler()), ('rf', RandomForestClassifier())])`, guaranteeing identical preprocessing transformations.

---

## 8. Legacy Dataset Quarantine

The repository contains historical datasets created during earlier development iterations. Each was inspected, hashed, and verified for quarantine status:

| Dataset Path | Rows $\times$ Cols | SHA-256 Prefix | Contamination / Defect Identified | Status | Disposition |
| :--- | :---: | :--- | :--- | :---: | :--- |
| `data/remediated_dataset_v3.csv` | $5,000 \times 13$ | `390f653966...` | Clean canonical 12D network flow benchmark | **ACTIVE** | Authoritative canonical dataset |
| `backend/ml/datasets/labeled_events_remediated.csv` | $5,000 \times 13$ | `390f653966...` | Clean canonical 12D network flow benchmark replica | **ACTIVE** | Active backend replica |
| `data/training_dataset.csv` | $232 \times 16$ | `f3621ac80e...` | Circular `threat_score` and `malicious_flag_ratio` leakage | **QUARANTINED** | Isolated from all active pipelines |
| `data/ground_truth.csv` | $200 \times 10$ | `753bbe7298...` | Circular `threat_score` leakage | **QUARANTINED** | Preserved for baseline historical record |
| `backend/ml/datasets/labeled_events_v2_enhanced.csv` | $5,000 \times 13$ | `a2e22e7cbe...` | 12D host command telemetry (3 features with 100% artificial separation) | **QUARANTINED** | Quarantined; incompatible with flow extractor |
| `docs/manually_reviewed_fps.csv` | $126 \times 13$ | `606bf44c8c...` | Audit false positive logs with `threat_score` | **QUARANTINED** | Documentation only |
| `experiments/audit/baseline_preservation/.../controlled_experiment_dataset.csv` | $100 \times 29$ | `3f374afdc6...` | Baseline preservation dataset with `feat_threat_score` | **QUARANTINED** | Historical preservation |

Static grep audit confirms that **zero active experiment scripts** reference `training_dataset.csv` or `labeled_events_v2_enhanced.csv`.

---

## 9. Experimental Split Integrity & Statistical Protocol

* **Repetition Count ($N$):** 30 independent runs.
* **Partitioning Strategy:** Stratified Monte Carlo train/test splitting ($80\%$ train, $20\%$ test).
* **Sample Sizes:** $N_{\text{train}} = 4,000$, $N_{\text{test}} = 1,000$ per run.
* **Seed Schedule:** Explicit and deterministic: $\{100, 101, \dots, 129\}$.
* **Independence:** Models (`rf`, `iso_forest`) and transformers (`scaler`) are re-instantiated and re-fitted on each iteration with the run's specific random seed.
* **Inferential Tests:**
  * Two-sided Wilcoxon signed-rank test across paired runs.
  * Paired Student's t-test with Cohen's d effect size.
  * McNemar's exact test using binomial distribution on discordant test predictions.
  * Fisher's exact test on $2 \times 2$ classification contingency matrices.

---

## 10. Metric Reproduction & Statistical Results

Reproduction across $N=30$ runs yielded the following programmatic results:

| Metric | Standalone Random Forest | Standalone Isolation Forest | Calibrated Hybrid Ensemble | Difference ($\Delta$) | Wilcoxon $p$-value | Paired $t$-test $p$-value | Cohen's $d$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Accuracy** | $0.9327 \pm 0.0061$ | $0.7332 \pm 0.0109$ | $0.9273 \pm 0.0062$ | $-0.0054$ | $3.59 \times 10^{-6}$ | $1.72 \times 10^{-7}$ | $-1.44$ |
| **Precision** | $0.9711 \pm 0.0108$ | $0.6699 \pm 0.0607$ | **$0.9782 \pm 0.0095$** | $+0.0071$ | $1.09 \times 10^{-4}$ | $2.31 \times 10^{-5}$ | $+0.97$ |
| **Recall** | $0.7996 \pm 0.0220$ | $0.2204 \pm 0.0273$ | $0.7750 \pm 0.0230$ | $-0.0246$ | $1.73 \times 10^{-6}$ | $1.39 \times 10^{-8}$ | $-1.81$ |
| **F1-Score** | $0.8768 \pm 0.0126$ | $0.3308 \pm 0.0357$ | $0.8646 \pm 0.0135$ | $-0.0122$ | $1.73 \times 10^{-6}$ | $6.21 \times 10^{-8}$ | $-1.67$ |
| **ROC-AUC** | $0.9859 \pm 0.0028$ | $0.7505 \pm 0.0163$ | $0.9806 \pm 0.0035$ | $-0.0053$ | $1.73 \times 10^{-6}$ | $2.44 \times 10^{-10}$ | $-2.05$ |
| **FPR** | $0.0103 \pm 0.0040$ | $0.0469 \pm 0.0128$ | **$0.0075 \pm 0.0034$** | **$-0.0028$** | $1.52 \times 10^{-4}$ | $2.82 \times 10^{-5}$ | $-0.95$ |
| **FNR** | $0.2004 \pm 0.0220$ | $0.7796 \pm 0.0273$ | $0.2250 \pm 0.0230$ | $+0.0246$ | $1.73 \times 10^{-6}$ | $1.39 \times 10^{-8}$ | $+1.81$ |

### Primary Held-Out Test Split Contingency & Discordance ($N=1,000$):
* Both Correct ($a$): $927$
* RF Only Correct ($b$): $7$
* Ensemble Only Correct ($c$): $1$
* Both Incorrect ($d$): $65$
* **McNemar Exact Test Discordance $p$-value:** $0.0703$ (Discordant pairs: $b=7, c=1$).
* **Fisher's Exact Test $p$-value:** $4.29 \times 10^{-114}$.

---

## 11. Reproducibility: Run A vs. Run B Audit

Independent evaluation was executed twice using the identical seed schedule to assess deterministic reproducibility:

* **Dataset SHA-256 Match:** `True`
* **Discrete Predictions Bitwise Equal:** `True` ($1,000 / 1,000$ test predictions identical)
* **Discrete Classification Metrics Equal:** `True` (all 30 runs of Accuracy, Precision, Recall, F1, FPR, FNR identical)
* **Continuous Probabilities Absolute Difference:** $\max |\Delta P| \le 2.22 \times 10^{-16}$
* **Determinism Classification:** `BITWISE_DETERMINISTIC_DISCRETE_NUMERICALLY_IDENTICAL_FLOAT_EPSILON`
* **Explanation:** Continuous probabilities differ by at most machine epsilon ($\le 2.22 \times 10^{-16}$) due to thread summation scheduling in scikit-learn's `n_jobs=-1`. When executed in single-threaded mode (`n_jobs=1`), continuous probabilities and ROC-AUC are **100% bitwise identical**.

---

## 12. Publication Evidence Traceability

Audit of publication artifacts (`experiments/results/publication_table.md`, `experiments/generate_publication_evidence.py`):
1. **Dynamic Loading:** `generate_publication_evidence.py` reads values directly from `statistical_tests.json`, `model_metrics.json`, `clustering_metrics.json`, `latency_metrics.json`, and `e2e_metrics.json`.
2. **Zero Hardcoded Metrics:** No accuracy, F1, ROC-AUC, or $p$-value strings are hardcoded into publication generators.
3. **Traceability Path:**
   $$\text{remediated\_dataset\_v3.csv} \xrightarrow{\text{reproduce\_clean\_paper.py}} \text{statistical\_tests.json} \xrightarrow{\text{generate\_publication\_evidence.py}} \text{publication\_table.md}$$

---

## 13. Limitations

1. **Synthetic Nature of Flow Telemetry:** Although statistical distributions model realistic network transport dynamics with high variance and overlap, the dataset is synthetically generated and does not represent captured real-world ISP or enterprise boundary traffic.
2. **Evaluation Sample Size:** The benchmark consists of $5,000$ events ($3,500$ benign, $1,500$ malicious). Large-scale evaluation across millions of continuous flows remains an area for extended operational testing.
3. **Single Domain Scope:** Telemetry is strictly restricted to transport-layer network flows (12 continuous features) and intentionally excludes host process execution graphs.
