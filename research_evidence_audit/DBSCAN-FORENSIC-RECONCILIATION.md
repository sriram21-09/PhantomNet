# DBSCAN Normalization Experiment: Forensic Reconciliation Report

**Audit Target:** `experiments/run_dbscan_normalization_experiment.py` and `experiments/results/dbscan_normalization/`  
**Audit Commit:** `091c8fe8cc1ea4bc01532663a85058f72a6844db` (HEAD) / `94a08f750dcefc047e8ff6a3a95f4e20136e49ed` (Experiment Baseline)  
**Date:** 2026-10-01  
**Auditor:** Forensic Software & ML Experiment Auditor (Antigravity)  

---

## Executive Summary of Findings

1. **The ARI and NMI $p < 0.001$ claims are completely illegitimate.** There was only a single evaluation run ($N = 1$) for clustering quality on `controlled_experiment_dataset.csv`. No significance tests were performed on ARI or NMI. The `Significant partition gain ($p < 0.001$)` string in `publication_table.md` was hardcoded text.
2. **The 30 E2E scenarios were never executed.** The pipeline ran exactly **1 baseline execution** and **1 normalized execution**. The author hardcoded a theoretical $2 \times 2$ contingency table `[[0, 30], [30, 0]]` into `scipy.stats.fisher_exact`, manufacturing an artificial p-value ($p = 1.69 \times 10^{-17}$).
3. **The reported latency (15.81 ms / 17.08 ms) comes from pre-aggregated summary CSVs.** The original script did not save the 100 individual float measurements to disk. Furthermore, `publication_table.md` contains a hardcoded literal `Wilcoxon $W=794.0, p < 0.001$` that conflicts with `statistical_tests.csv` ($W = 817.5, p = 4.333 \times 10^{-9}$).
4. **Standardized DBSCAN did NOT recover the 4 attack campaigns.** It recovered **0 clean attack campaigns**. It clustered the 20 benign noise samples into an attack cluster (Cluster 1), merged 5 SSH samples and 4 SQLi samples together into a false merge (Cluster 0), and left 71% of all samples (including 100% of Port Scan and FTP Exfiltration) as unclustered noise.
5. **The E2E test produced 2 campaigns due to residual database state.** The 1-hour query window captured un-cleaned logs from an earlier test run (`10.99.99.10`), which DBSCAN clustered alongside the newly injected SSH brute force records.

---

## 1. Latency Reconciliation

### A. Raw Values & Sources Compared
- `latency_baseline.csv`:
  - `component`: Baseline DBSCAN (Raw)
  - `mean_ms`: 15.8149
  - `median_ms`: 15.6838
  - `std_ms`: 0.6586
  - `p95_ms`: 16.8766
  - `p99_ms`: 18.0489
  - `min_ms`: 14.6097
  - `max_ms`: 18.5641
- `latency_normalized.csv`:
  - Row 0 (StandardScaler): mean = 0.6147, median = 0.5827, std = 0.1211, min = 0.4055, max = 0.9980
  - Row 1 (Normalized DBSCAN): mean = 16.4616, median = 15.5435, std = 7.6141, min = 14.6142, max = 91.9230
  - Row 2 (Total Pipeline): mean = 17.0763, median = 16.1438, std = 7.6215, min = 15.0968, max = 92.5726
- `publication_table.md`:
  - Reported: `15.81 +/- 0.66 ms` vs `17.08 +/- 7.62 ms`, Difference = `+1.26 ms`

### B. Recalculated Values from Raw CSV Files
- Baseline Mean: `15.8149 ms` (Rounds to `15.81 ms`)
- Baseline Median: `15.6838 ms`
- Baseline Std Dev: `0.6586 ms` (Rounds to `0.66 ms`)
- Normalized Total Mean: `17.0763 ms` (Rounds to `17.08 ms`)
- Normalized Total Median: `16.1438 ms`
- Normalized Total Std Dev: `7.6215 ms` (Rounds to `7.62 ms`)
- Mean Difference: `17.0763 - 15.8149 = +1.2614 ms` (Rounds to `+1.26 ms`)
- Median Difference: `16.1438 - 15.6838 = +0.4600 ms`
- Paired Differences: Not directly computable per-iteration from the CSV files because `latency_baseline.csv` and `latency_normalized.csv` store exclusively 1-row summary statistics, not the 100 individual float rows.

### C. Reported Values
- Baseline: `15.81 +/- 0.66 ms`
- Standardized: `17.08 +/- 7.62 ms`
- Difference: `+1.26 ms`

### D. Discrepancy
- The summary statistics in `publication_table.md` strictly match `latency_baseline.csv` and `latency_normalized.csv`.
- However, the raw 100 float measurements were never saved to disk in any CSV. When re-run live on modern CPU environments, latency measurements vary with CPU load, OS thread scheduling, and timer resolution.

### E. Likely Source of Discrepancy
`experiments/run_dbscan_normalization_experiment.py` lines 680-692 generated `lat_base_list` and `lat_norm_total_list` in memory during a single 100-iteration execution, called `get_stats_dict()`, and dumped only the dictionary to CSV.

### F. Exact Files & Functions Responsible
- `experiments/run_dbscan_normalization_experiment.py`: `benchmark_latencies_and_statistics()` (lines 650-710)
- `experiments/run_dbscan_normalization_experiment.py`: `generate_publication_table()` (lines 870-890)

---

## 2. Wilcoxon Reconciliation

### A. Raw Values & Input Arrays
- Sample Size: $N = 100$ paired iterations.
- SciPy Version: `scipy >= 1.11.0`
- Call Signature: `scipy.stats.wilcoxon(lat_base_list, lat_norm_total_list)`
  - Default parameters: `zero_method='wilcox'`, `correction=False`, `alternative='two-sided'`, `mode='auto'`.

### B. Recalculated Values
- Historical run recorded in `statistical_tests.csv`:
  - Test Statistic: $W = 817.5$
  - p-value: $4.3332 \times 10^{-9}$
- Independent live replication ($N = 100$):
  - Test Statistic: $W = 612.0$ to $2122.0$ (depending on thread contention)
  - p-value: $p < 0.05$ to $p = 0.16$

### C. Reported Values
- `statistical_tests.csv`: $W = 817.5, p = 4.3332 \times 10^{-9}$
- `publication_table.md`: `Wilcoxon $W=794.0, p < 0.001$`

### D. Discrepancy
- Discrepancy of $\Delta W = 23.5$ between `statistical_tests.csv` ($W = 817.5$) and `publication_table.md` ($W = 794.0$).

### E. Likely Source of Discrepancy
In `experiments/run_dbscan_normalization_experiment.py` (line 885), the author wrote:
```markdown
| **DBSCAN Latency (ms)** | {t_base} | {t_norm} | {lat_diff} | Wilcoxon $W=794.0, p < 0.001$ |
```
The text `Wilcoxon $W=794.0, p < 0.001$` is a **hardcoded literal string** left over from an earlier test run. It was never parameterized with `{stat_w}` or `{p_val_w}`.

### F. Exact Files & Functions Responsible
- `experiments/run_dbscan_normalization_experiment.py`: `generate_publication_table()` (line 885)

---

## 3. Cohen's d Reconciliation

### A. Formula and Implementation
Extracted verbatim from `experiments/run_dbscan_normalization_experiment.py` (lines 703-705):
```python
diff = np.array(lat_norm_total_list) - np.array(lat_base_list)
cohens_d = float(np.mean(diff) / np.std(diff)) if np.std(diff) > 0 else 0.0
```

### B. Input Values, Numerator, and Denominator
- **Type of Effect Size:** **Cohen's $d_z$ for paired samples** (standardized mean difference of paired observations). It is **NOT** two-sample pooled independent Cohen's $d$.
- **Numerator ($\overline{D}$):** Mean paired difference = $+1.2614\text{ ms}$.
- **Denominator ($s_D$):** Sample standard deviation of paired differences (with `ddof=0`) = $7.5488\text{ ms}$.
- **Calculation:**
  $$d_z = \frac{1.2614}{7.5488} = +0.167099... \approx +0.1671$$

### C. Comparison with Independent Two-Sample Pooled Cohen's d
If calculated as independent pooled Cohen's $d$:
$$s_{pooled} = \sqrt{\frac{0.6586^2 + 7.6215^2}{2}} = 5.409\text{ ms}, \quad d = \frac{1.2614}{5.409} \approx +0.2332$$
The value $+0.1671$ in `statistical_tests.csv` definitively confirms that the paired formula `np.mean(diff) / np.std(diff)` was used.

### D. Exact Files & Functions Responsible
- `experiments/run_dbscan_normalization_experiment.py`: `benchmark_latencies_and_statistics()` (lines 703-705)

---

## 4. End-to-End (E2E) Pipeline Reconciliation

### A. Exact Number of Executions
- `E2E-BASELINE-001`: **1 execution** (timestamp: `2026-09-01T11:39:13.211600+00:00`)
- `E2E-NORMALIZED-001`: **1 execution** (timestamp: `2026-09-01T11:39:13.727668+00:00`)
- **Total Executions:** **2 single runs** (1 pair).

### B. Exact Input Records
- 15 `PacketLog` records: TCP port 2222, length 64, event `login_attempt`, rotating across 5 source IPs (`198.51.100.10` to `198.51.100.14`).
- 5 `Event` records: Honeypot SSH failed password records.

### C. Pipeline Stages
1. `1_attack_ingestion`: Ingests packet logs and raw events into SQLite.
2. `2_ml_scoring_and_threat_decision`: Calls `score_threat()` to score packets.
3. `3_dbscan_campaign_clustering`: Queries logs within 1 hour; executes DBSCAN.
4. `4_downstream_sentinel_pipeline`: Invokes Sentinel service for playbook generation.
5. `5_downstream_soc_artifacts_verification`: Validates MITRE, Snort, Sigma, and STIX artifacts.

### D. Origin of the Number 30 and Contingency Table
There was **no loop** over 30 runs. The author wrote (lines 712-720):
```python
# 2. Categorical Autonomous E2E Success/Failure Test (N=30 repeated runs)
# Baseline: 0/30 successes (0.0%). Normalized: 30/30 successes (100.0%).
contingency_table = [[0, 0], [30, 0]]
odds_ratio, fisher_p = stats.fisher_exact([[0, 30], [30, 0]])
```
The researcher extrapolated a single deterministic run to $N=30$ and hardcoded the array `[[0, 30], [30, 0]]` into `scipy.stats.fisher_exact()`.

### E. Validity of Fisher's Exact Test
**COMPLETELY INVALID.** Fisher's exact test requires independent empirical observations. Fabricating an input matrix representing 30 theoretical trials creates a completely artificial p-value ($p = 1.69 \times 10^{-17}$) that has no mathematical or experimental validity.

---

## 5. Cluster Reconciliation

### A. Ground Truth vs Standardized DBSCAN Cross-Tabulation
Evaluated on `controlled_experiment_dataset.csv` ($N = 100$ events, $eps = 0.5, min\_samples = 5$):

| Ground-Truth Campaign | True Cluster ID | True Count | Predicted Noise (-1) | Predicted Cluster 0 | Predicted Cluster 1 | Recovery Verdict |
|---|---:|---:|---:|---:|---:|---|
| **CAMPAIGN-SSH-BRUTE** | 0 | 25 | 20 (80.0%) | 5 (20.0%) | 0 (0.0%) | **FAILED (False Merge with Web SQLi)** |
| **CAMPAIGN-WEB-SQLI** | 1 | 20 | 16 (80.0%) | 4 (20.0%) | 0 (0.0%) | **FAILED (False Merge with SSH Brute)** |
| **CAMPAIGN-PORT-SCAN** | 2 | 20 | 20 (100.0%) | 0 (0.0%) | 0 (0.0%) | **COMPLETELY LOST (100% Noise)** |
| **CAMPAIGN-FTP-EXFIL** | 3 | 15 | 15 (100.0%) | 0 (0.0%) | 0 (0.0%) | **COMPLETELY LOST (100% Noise)** |
| **BENIGN_NOISE** | -1 | 20 | 0 (0.0%) | 0 (0.0%) | 20 (100.0%) | **CRITICAL FLAW (Clustered as Attack Campaign)** |
| **TOTAL** | - | **100** | **71 (71.0%)** | **9 (9.0%)** | **20 (20.0%)** | **0 / 4 Campaigns Recovered** |

### B. Analysis of Predicted Clusters
1. **Cluster 0 ($N = 9$):**
   - Composed of 5 SSH Brute Force events and 4 Web SQLi events.
   - **Severe False Merge:** Two completely different attack types targeting different ports (2222 vs 8080) were grouped into a single cluster.
2. **Cluster 1 ($N = 20$):**
   - Composed entirely of **20 Benign Noise events** (`10.1.1.10` to `10.1.1.29`).
   - Zero benign events were labeled as noise. DBSCAN identified normal health checks as an attack campaign.
3. **Noise Points ($N = 71$):**
   - 71% of all traffic was discarded as noise, including 100% of port scans and 100% of FTP exfiltration.

### C. Contradiction in Documentation
In `dbscan_metrics_comparison.csv`, the text description column claims:
- Row 2: *"Normalized recovers all 4 true attack campaigns"* (**FALSE: It recovered 0 clean attack campaigns**).
- Row 7: *"Every predicted cluster contains strictly 1 true attack class"* (**FALSE: Cluster 0 contains both SSH and Web SQLi**).
- Row 10: *"Zero false merges in normalized clustering"* (**FALSE: Cluster 0 is an overt false merge**).

### D. Why the E2E SSH Scenario Produced 2 Campaigns
In `e2e_normalized_trace.json`, Stage 3 reported finding **2 campaigns** despite only injecting 1 SSH attack:
- **Root Cause: Database State Pollution.**
- Stage 3 queries all elevated records from the past hour:
  ```python
  cutoff = datetime.utcnow() - timedelta(hours=1)
  logs = db.query(PacketLog).filter(PacketLog.timestamp >= cutoff, ...).all()
  ```
- The test clean-up only purged `src_ip.like('198.51.100.%')`.
- An earlier test from 30 minutes prior (`11:08:53 UTC`) had inserted an elevated packet from `10.99.99.10`.
- DBSCAN clustered the newly injected SSH events and the residual historical records into two separate clusters (`campaign_0` and `campaign_1`).

---

## 6. Publication Recommendations

1. **Delete All ARI / NMI p-value Claims:**
   Remove `Significant partition gain ($p < 0.001$)` from `publication_table.md` and all paper drafts. Replace with honest reporting: *"ARI increased from 0.0000 to 0.2116 on the benchmark workload."*
2. **Remove the 30 E2E / Fisher's Exact Claims:**
   Excise `0.0% (0/30) vs 100.0% (30/30)` and `Fisher's Exact p < 0.001`. State factually: *"In single-run autonomous pipeline validation, baseline unscaled DBSCAN halted at Stage 3, whereas StandardScaler DBSCAN successfully completed all 5 stages through playbook generation."*
3. **Correct the W Statistic Discrepancy:**
   Align `publication_table.md` with `statistical_tests.csv` ($W = 817.5$) or remove the hardcoded string and dynamically populate it.
4. **Disclose the True Nature of the Clustering Result:**
   Do NOT claim that StandardScaler DBSCAN *"recovers all 4 true attack campaigns."* Honestly disclose that while standardization prevents total distance collapse and allows downstream playbook triggering, it still exhibited a 71% noise rate and false-merged SSH and Web attacks under un-tuned default hyperparameters ($eps=0.5$).
