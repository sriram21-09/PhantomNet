# PhantomNet DBSCAN & Campaign Clustering Forensic Audit

**Document:** Campaign Clustering Forensic Audit (`DBSCAN_AUDIT.md`)  
**Auditor:** Lead ML & Reproducibility Auditor  
**Date:** 2026-10-01  
**Project:** PhantomNet  
**Status:** COMPLETE — REMEDIATION SPECIFIED  

---

## 1. Executive Summary: Clustering Reality vs. Publication Claims

In the PhantomNet architecture, DBSCAN (`sklearn.cluster.DBSCAN`) is responsible for correlating discrete honeypot telemetry events into multi-source, multi-stage attack campaigns. 

A forensic audit of `backend/ml_engine/campaign_clustering.py` and `experiments/run_dbscan_normalization_experiment.py` reveals that **neither the unscaled production baseline nor the standardized experimental pipeline produces scientifically defensible campaign clusters**:

| Metric / Dimension | Baseline DBSCAN (Production) | Standardized DBSCAN (Experiment) | Published Claim | Forensic Truth |
|---|---|---|---|---|
| **Feature Scaling** | **None** (Raw feature values) | `StandardScaler` (Z-score) | "Normalized" | Production code has NO scaler (`fit_predict(df.values)`) |
| **Number of Clusters** | **0** | **2** | "+2 dense clusters" | Discovered 0 clean attack campaigns; merged SSH + SQLi into 1 cluster |
| **Noise Percentage** | **100.0%** (100 / 100 events) | **71.0%** (71 / 100 events) | "Discards noise" | Discards nearly three-quarters of all attack activity |
| **Adjusted Rand Index (ARI)** | **0.0000** | **0.2116** | "$p < 0.001$ partition gain" | ARI of 0.2116 represents very poor clustering agreement ($1.0$ is perfect) |
| **Pairwise F1 Score** | **0.0000** | **0.0317** | "Absolute improvement" | Pairwise recall is $0.0204$; almost no true pairs recovered |
| **Silhouette Score** | **Undefined** ($<2$ clusters) | **0.9895** | "0.9895 near-optimal" | Artifact of evaluating only 2 small non-noise islands while 71% was discarded |
| **Attack Campaign Recovery** | **0 / 4 campaigns** (0%) | **0 / 4 campaigns** (0%) | "Campaign discovery" | Port Scan & FTP Exfiltration 100% noise; SSH & SQLi collapsed together |
| **Benign Handling** | 100% noise | 0% noise (Cluster 1) | "Clean filtering" | Formed a spurious dense cluster out of benign background noise |
| **Autonomous E2E Success** | **0 / 30 runs** (0.0%) | **30 / 30 runs** (100.0%) | "Fisher's Exact $p < 10^{-17}$" | **FABRICATED:** The 30 runs were never executed; contingency matrix hardcoded |

---

## 2. Root Cause Analysis of Baseline DBSCAN Collapse

In `backend/ml_engine/campaign_clustering.py:L76-80`:
```python
df = pd.DataFrame(features_list, columns=FeatureExtractor.FEATURE_NAMES)
# Important: Keep src_ip behavior tightly grouped by enforcing its significance,
# or apply specific scaling if needed. Assuming FeatureExtractor standardizes.
predictions = self.model.fit_predict(df.values)
```
- **The Defect:** The author assumed `FeatureExtractor` standardizes values. In reality, `FeatureExtractor` outputs raw, unstandardized units:
  - `packet_length`: 40 to 1,500+ bytes ($\sigma \approx 450$)
  - `session_duration_estimate`: 0.0 to 600,000+ seconds ($\sigma \approx 250,000$)
  - `source_ip_event_rate`: 1.0 to 50.0 events/min
  - `destination_port_class`: 1, 2, or 3
- **Euclidean Metric Collapse:**
  $$\text{dist}(x_1, x_2) = \sqrt{(L_1 - L_2)^2 + (T_1 - T_2)^2 + \dots}$$
  With `eps = 0.5`, if two events differ in packet length by even **1 single byte**, their distance $\sqrt{(1)^2} = 1.0 > 0.5$. Every single event in the dataset had pairwise distance $> 0.5$.
- **Consequence:** DBSCAN classified 100.0% of events as noise ($cluster = -1$), forming zero clusters and halting the downstream Sentinel SOAR pipeline.

---

## 3. Dissection of the Standardized DBSCAN Experiment

To address the collapse, `experiments/run_dbscan_normalization_experiment.py` applied `StandardScaler`. However, the resulting cluster partition was forensically analyzed using `experiments/results/dbscan_normalization/campaign_analysis.csv`:

### Detailed Campaign Breakdown (100 Events Total):
1. **`CAMPAIGN-SSH-BRUTE` (25 Ground-Truth Events):**
   - 20 events (80.0%) classified as **noise** (`cluster = -1`).
   - 5 events (20.0%) assigned to **Cluster 0**.
2. **`CAMPAIGN-WEB-SQLI` (20 Ground-Truth Events):**
   - 16 events (80.0%) classified as **noise** (`cluster = -1`).
   - 4 events (20.0%) assigned to **Cluster 0**.
   - **False Merge:** SSH brute force and Web SQL injection were fused into the exact same cluster!
3. **`CAMPAIGN-PORT-SCAN` (20 Ground-Truth Events):**
   - 20 events (100.0%) classified as **noise** (`cluster = -1`).
   - **Zero campaign recovery.**
4. **`CAMPAIGN-FTP-EXFIL` (15 Ground-Truth Events):**
   - 15 events (100.0%) classified as **noise** (`cluster = -1`).
   - **Zero campaign recovery.**
5. **`BENIGN_NOISE` (20 Ground-Truth Events):**
   - 0 events (0.0%) classified as noise.
   - 20 events (100.0%) grouped into **Cluster 1**.

### Mathematical Interpretation:
- Standardized DBSCAN recovered **0 out of 4** ground-truth attack campaigns cleanly.
- It discarded 71.0% of all events as noise.
- It grouped benign background noise into an alertable incident cluster (`Cluster 1`), while fusing disparate attack vectors into `Cluster 0`.
- The reported Silhouette score of **0.9895** is misleading: Silhouette was computed only on the 29 points assigned to clusters 0 and 1, completely ignoring the 71 points rejected as noise.

---

## 4. Forensic Audit of Statistical Tests

### 4.1 The Fabricated Fisher's Exact Contingency Table
In `experiments/run_dbscan_normalization_experiment.py:L1472-1479`:
```python
# 2. Categorical Autonomous E2E Success/Failure Test (N=30 repeated runs)
# Baseline: 0/30 successes (0.0%). Normalized: 30/30 successes (100.0%).
contingency_table = [[0, 0], [30, 0]]
odds_ratio, fisher_p = stats.fisher_exact([[0, 30], [30, 0]])
```
- **Forensic Evidence:** The test function was called with hardcoded counts. No loop executing 30 pipeline runs exists in the script.
- **Publication Consequence:** Claims in `publication_table.md` and `MASTER_FINAL_PROJECT_REPORT.md` of "100.0% autonomous completion across 30 repeated runs ($p < 0.001$)" are scientifically invalid and must be retracted or re-run legitimately.

### 4.2 Latency Test Discrepancy
- `publication_table.md` states: `Wilcoxon W=794.0, p < 0.001`.
- `statistical_tests.csv` records: `Statistic = 817.5, p_value = 4.33e-09`.
- The raw latency values ($N=100$) were never saved to disk in the results folder, leaving `raw_latency_arrays.py` orphaned in the root directory.

---

## 5. Remediation Architecture for Campaign Correlation

To build a genuinely functional, peer-reviewable campaign correlation engine:

1. **Feature Engineering for Clustering:**
   - Eliminate raw packet lengths and timestamps.
   - Use normalized session behavior:
     - Log-scaled event rate: $\log(1 + \text{rate})$
     - Target port entropy / distribution
     - Protocol indicator encoding
     - Payload entropy variance
     - Dwell time ratio
2. **Proper Normalization & Distance Metric:**
   - Couple DBSCAN with `StandardScaler` or `RobustScaler` (to handle outliers without distorting density).
   - Evaluate **Cosine Distance** or **Mahalanobis Distance** to measure behavioral orientation rather than magnitude.
3. **Principled Hyperparameter Tuning:**
   - Determine `min_samples` based on domain context (minimum campaign threshold: $k \ge 3$ or $5$).
   - Determine `eps` via automated **k-distance elbow estimation** (k-NN distance graph sorted in ascending order).
4. **Legitimate Empirical Evaluation:**
   - Benchmark across multiple noise levels ($10\%, 20\%, 50\%$).
   - Execute actual repeated runs ($N \ge 30$) under varying seeds for all statistical tests.
