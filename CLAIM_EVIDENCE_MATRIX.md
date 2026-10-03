# CLAIM → EVIDENCE TRACEABILITY MATRIX
**Project:** PhantomNet Autonomous Cyber Defense System  
**Audit Date:** 2026-10-01  
**Audit Standard:** Forensic Academic Artifact Traceability (Scientific Rule 29)  
**Dataset SHA-256:** `390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363`  
**Git Commit SHA:** `686e880a240a671390e68eb42f24ece21156c1f2`

---

## 1. Traceability Methodology

Every research claim made in documentation, paper drafts, and presentation materials is traced backwards through a formal chain of custody:
$$\text{Claim} \longrightarrow \text{Experiment Design} \longrightarrow \text{Raw Observations} \longrightarrow \text{Analysis Script} \longrightarrow \text{Statistical Metric} \longrightarrow \text{Persisted Artifact}$$

If any link in this chain is missing, hardcoded, or fabricated, the claim status is designated as **UNSUPPORTED** or **NOT REPRODUCED**.

---

## 2. Claim-to-Evidence Matrix

| # | Research Claim | Experiment | N | Raw Artifact | Analysis Script | Empirical Result | Status | Remediation Action |
| :-: | :--- | :--- | :-: | :--- | :--- | :--- | :-: | :--- |
| **C1** | *"Hybrid Ensemble achieves 99.4% accuracy across all attack types"* | EXP-STAT-N30 | 30 | Historical JSON (fabricated) | None (hardcoded) | Real Acc: **92.57% ± 0.76%** | **UNSUPPORTED** | **Downgraded Claim:** Real ensemble accuracy is 92.57% on overlapping flow traffic. |
| **C2** | *"Statistically significant FPR reduction via Hybrid Ensemble (0.85 RF + 0.15 IF)"* | EXP-STAT-N30-CLASSIFICATION | 30 | `runs/run_001.json` ... `run_030.json` | `reproduce_clean_paper.py` | Wilcoxon **$W = 0.0, p = 1.73 \times 10^{-6}$** (FPR drops 1.03% $\to$ 0.75%) | **SUPPORTED** | **Retained & Validated:** Hybrid ensemble provides statistically significant false-positive suppression. |
| **C3** | *"Hybrid Ensemble strictly outperforms Random Forest across ALL metrics (Recall, F1, Accuracy)"* | EXP-STAT-N30-CLASSIFICATION | 30 | `runs/run_001.json` ... `run_030.json` | `reproduce_clean_paper.py` | RF Recall: **79.83%** vs Ensemble Recall: **76.79%** ($p = 1.73 \times 10^{-6}$) | **REFUTED** | **Rewritten Claim:** Ensemble acts as precision filter; recall is penalized. Universal superiority claim retracted. |
| **C4** | *"DBSCAN achieves 100% campaign clustering accuracy with 0% noise"* | EXP-DBSCAN-BENCHMARK | 100 flows | Historical baseline (collapsed) | `validate_remediated_clustering.py` | Remediated Noise: **17.0%**, ARI: **0.6865**, Homogeneity: **0.9504** | **UNSUPPORTED** | **Rewritten Claim:** Standardized DBSCAN isolates 8 distinct campaigns with 95.0% purity; 17% noise is natural network jitter. |
| **C5** | *"Zero false merges between distinct attack campaigns"* | EXP-DBSCAN-BENCHMARK | 100 flows | `clustering_metrics.json` | `validate_remediated_clustering.py` | Cross-campaign false merges: **0 / 8** | **SUPPORTED** | **Retained:** SSH, SQLi, port scans, and FTP exfiltration map to separate clusters. |
| **C6** | *"Sub-millisecond real-time ML scoring latency (< 1ms)"* | EXP-LATENCY-WARM-100 | 100 | `latency_observations.csv` (520 rows) | `run_latency_benchmark.py` | In-memory ThreatScoring: **0.071 ms**, Feature Extractor: **0.065 ms** (Full RF: 28.3 ms) | **PARTIALLY SUPPORTED** | **Clarified Claim:** In-memory rule/scoring check is sub-millisecond (0.07 ms); full tree ensemble inference requires 28.3 ms. |
| **C7** | *"Autonomous End-to-End SOAR remediation with zero human intervention"* | EXP-E2E-AUTONOMOUS | 14 stages | `e2e_metrics.json`, `pipeline_evidence_report.json` | `test_full_pipeline_e2e.py` | 14/14 automated stages passed (Raw packet $\to$ STIX 2.1 & Sigma rules) | **SUPPORTED** | **Retained:** Fully autonomous pipeline confirmed with zero manual database overrides. |
| **C8** | *"Discordance contingency table [[0, 30], [30, 0]] with Fisher exact p=1.69e-17"* | Historical Paper Script | 1 | Fabricated script variable | `reproduce_clean_paper.py` | True Discordant Pairs on N=1,000: $b=32, c=1$ (McNemar $p = 7.15 \times 10^{-8}$) | **FABRICATED (PRE-AUDIT)** | **Purged & Replaced:** Replaced fabricated symmetric matrix with empirical paired discordance observations. |
| **C9** | *"SHAP tree explainer satisfies mathematical local additivity on production pipelines"* | EXP-SHAP-ADDITIVITY | 100 | Unit test run logs | `test_explainability.py` | Maximum local error $|\sum \phi_i + \phi_0 - f(x)| < 1.42 \times 10^{-6}$ | **SUPPORTED** | **Retained:** Mathematical efficiency rigorously confirmed on transformed pipelines. |

---

## 3. Machine-Readable Linkages

All claims cross-reference permanent machine-readable records:
- **Summary Evidence Table:** [`experiments/results/publication_table.md`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/publication_table.md)
- **Statistical Tests JSON:** [`experiments/results/statistical_tests.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/statistical_tests.json)
- **Model Metrics JSON:** [`experiments/results/model_metrics.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/model_metrics.json)
- **Ensemble Metrics JSON:** [`experiments/results/ensemble_metrics.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ensemble_metrics.json)
- **Clustering Metrics JSON:** [`experiments/results/clustering_metrics.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/clustering_metrics.json)
- **Latency Observations CSV:** [`experiments/results/latency_observations.csv`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/latency_observations.csv)
- **E2E Metrics JSON:** [`experiments/results/e2e_metrics.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/e2e_metrics.json)
- **Experiment Manifest:** [`experiments/results/EXPERIMENT_MANIFEST.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/EXPERIMENT_MANIFEST.json)
