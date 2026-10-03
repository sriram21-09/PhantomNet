# PAPER NUMERICAL RECONCILIATION & DISCREPANCY AUDIT
**Project:** PhantomNet Autonomous Cyber Defense System  
**Audit Date:** 2026-10-01  
**Audit Standard:** Academic Publication Integrity & Scientific Evidence Reconciliation (Rule 30)  
**Machine-Readable Target:** [`experiments/results/publication_table.md`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/publication_table.md)

---

## 1. Overview & Objective

This reconciliation report conducts a section-by-section comparison of historical academic paper drafts and documentation against the verified empirical evidence produced during the forensic audit. 

Prior to this audit, PhantomNet's publication drafts relied heavily on:
1. Synthetic datasets with artificial non-overlapping features that produced inflated $100\%$ and $99.4\%$ accuracy figures.
2. An unscaled DBSCAN clustering algorithm that actually collapsed to $100\%$ noise in reality, while paper text claimed $0\%$ noise.
3. A fabricated $2 \times 2$ contingency table (`[[0, 30], [30, 0]]`) manufactured to produce an astronomical $p$-value ($1.69 \times 10^{-17}$).
4. Hardcoded latency claims of $< 1$ ms for full tree ensemble inference.

Below is the definitive reconciliation table specifying exact section-by-section required amendments.

---

## 2. Section-by-Section Reconciliation Table

| Paper Section | Historical Text / Metric Claim | Remediated Empirical Metric | Discrepancy & Root Cause | Required Scientific Amendment |
| :--- | :--- | :--- | :--- | :--- |
| **Abstract** | *"Achieves 99.4% detection accuracy across complex network intrusion attacks."* | **92.57% ± 0.76% (Ensemble)**<br>**93.27% ± 0.61% (Random Forest)** | Historical metric was obtained on leaked or separable data (`labeled_events_v2_enhanced`). | **Rewrite Abstract:** State true accuracy of 92.57%–93.27% on realistic, overlapping continuous network flow traffic. |
| **Abstract** | *"Reduces false positive alarm rates to absolute zero."* | **FPR: 0.75% ± 0.34% (Ensemble)**<br>**FPR: 1.03% ± 0.40% (RF)** | Absolute zero FPR was an artifact of artificial synthetic thresholds. | **Update Abstract:** Highlight statistically significant 27% relative FPR reduction ($p = 1.73 \times 10^{-6}$), dropping FPR to 0.75%. |
| **Methodology: Features** | *"15-dimensional multi-modal feature vector including threat score and cluster metrics."* | **Canonical 12-dimensional feature schema** (`FEATURE_SPEC.md`) | Prior 15D vector included post-event outputs (`threat_score`, `cluster_id`) causing target leakage. | **Amend Feature Section:** Document the exact 12 pre-event streaming features. Remove all post-scoring fields. |
| **Methodology: Clustering**| *"Standard Euclidean DBSCAN automatically identifies incident campaigns."* | **Standardized DBSCAN with log1p feature scaling** ($\epsilon=0.80, \text{min\_samples}=4$) | Unscaled DBSCAN suffered from dimensional distance distortion, classifying 100% of points as noise. | **Update Methodology:** Detail feature standardization and log-transformation of skewed flow volumes. |
| **Results: Model Evaluation** | *"Hybrid ensemble strictly dominates standalone Random Forest in all metrics."* | **RF F1: 0.8760 ± 0.0126**<br>**Ensemble F1: 0.8604 ± 0.0145**<br>**RF Recall: 0.7983** vs **Ensemble: 0.7679** | The unsupervised Isolation Forest acts as an anomaly filter that boosts precision (97.8% vs 97.1%) but penalizes recall. | **Amend Results & Discussion:** Refute universal dominance. Reframe ensemble as a false-positive mitigation filter for SOC environments. |
| **Results: Statistical Tests** | *"Fisher exact test p=1.69e-17 and Wilcoxon W=794.0."* | **McNemar p = 7.15e-08**<br>**Fisher p = 1.000**<br>**Wilcoxon FPR W = 0.0 (p = 1.73e-06)** | Historical script hardcoded a symmetric matrix `[[0, 30], [30, 0]]` with an arbitrary W stat. | **Replace Statistical Table:** Insert verified paired statistics from 30 independent runs (`statistical_tests.json`). |
| **Results: Clustering** | *"0% noise and perfect 1.000 Adjusted Rand Index across all attack campaigns."* | **Clusters: 8**<br>**Noise: 17.00%**<br>**ARI: 0.6865**<br>**Homogeneity: 0.9504** | Real network clustering naturally exhibits noise and border jitter. | **Replace Table 3:** Report 8 discovered campaigns, 95.0% cluster homogeneity, and 17.0% natural noise. Emphasize zero cross-campaign false merges. |
| **Results: Latency** | *"Real-time end-to-end ML inference latency under 0.8 ms."* | **ThreatScoringService: 0.071 ms**<br>**Feature Extraction: 0.065 ms**<br>**Random Forest Model: 28.32 ms** | Historical benchmark only measured cache lookup, ignoring tree ensemble traversal. | **Update Latency Breakdown:** Differentiate fast-path rule scoring (0.07 ms) from deep tree inference (28.3 ms). Total warm pipeline latency is ~34 ms. |
| **Results: E2E SOAR** | *"Autonomous pipeline verified across 30 simulated production runs."* | **14 / 14 Automated Stages Verified** | Historical runs relied on manual SQL insertions and overrides in test scripts. | **Update E2E Section:** Reference automated integration harness (`test_full_pipeline_e2e.py`) verifying true autonomous raw ingestion to STIX 2.1. |

---

## 3. Discrepancy Impact Analysis

### 3.1 Scientific Integrity Impact
Removing fabricated numbers and synthetic artifacts lowers raw metric values (e.g., accuracy from $99.4\%$ to $92.6\%$, noise from $0\%$ to $17\%$), but transforms PhantomNet from an indefensible, fabricated demo into a **scientifically grounded, peer-review defensible cyber defense research system**.

### 3.2 Value Proposition Alignment
The true value proposition of the Hybrid Ensemble is **not** magic universal superiority, but rather **extreme precision (97.8%) and false-positive suppression (0.75% FPR)** in high-volume enterprise networks where false alarms overwhelm security analysts. This is an empirically proven, statistically sound finding ($p < 10^{-5}$).
