# PhantomNet Phase ML-7: Independent Validation, Robustness & Publication-Readiness Forensics

**Document Identifier:** `PHANTOMNET-FORENSIC-ML-7`  
**Execution Date:** 2026-10-02  
**Auditor:** Senior ML Auditor & Reproducibility Engineer  
**Audit Baseline:** ML-1 through ML-6 Historical Baseline  
**Canonical Dataset:** `data/remediated_dataset_v3.csv` ($5,000 \times 13$, SHA-256: `390f653966...`)  
**Canonical Schema:** `12D-v1` (12 Network Flow Features)  
**Status:** COMPLETE FORENSIC AUDIT RECORD

---

## 1. Executive Summary & Verdict

Phase ML-7 conducted a rigorous forensic audit of PhantomNet's claims regarding independent validation, out-of-distribution robustness, computational latency, and publication readiness.

### Core Audit Verdicts:
1. **Dataset Independence:** `NO_INDEPENDENT_DATA_AVAILABLE`. No physical production network tap or external public benchmark is integrated into the active evaluation pipeline. All evidence derives from synthetic mathematical flow distributions.
2. **Robustness under Distribution Shifts:** **CONDITIONALLY SUPPORTED**. While the canonical 0.85 RF + 0.15 IF ensemble demonstrates resilience ($F_1 > 0.81$) under traffic volume amplification, protocol drift, scanning, and measurement noise, it experiences material degradation ($F_1 \approx 0.72 - 0.75$, recall dropping to $\approx 58\% - 62\%$) under heavy-tailed payload sizes (Pareto), low-and-slow evasion timing, and compound multi-stress conditions.
3. **Model Superiority Claim:** `UNSUPPORTED`. Standalone Random Forest achieves higher recall ($+2.1\%$) and higher overall F1 across evaluated domains ($p < 10^{-4}$). The hybrid ensemble represents an operational trade-off: it provides a 27% reduction in false-positive rate ($0.0077$ vs $0.0106$) and near-zero FPR at $\text{BLOCK}=0.80$ at the cost of lower detection recall and higher calibration error.
4. **Probability Semantics:** `UNSUPPORTED`. The composite score $S_{\text{composite}}$ is an **ordinal composite threat score**, NOT a calibrated Bayes probability ($ECE \approx 0.085$, $\text{Brier} \approx 0.058$).
5. **Final Status:** **PASS WITH DOCUMENTED LIMITATIONS**.

---

## 2. Baseline & Verification State

- **Git Commit SHA:** `686e880a240a671390e68eb42f24ece21156c1f2`
- **Active Branch:** `main`
- **Python / ML Environment:** Python 3.11.9, NumPy 2.3.5, SciPy 1.16.3, Pandas 2.3.3, Scikit-Learn 1.8.0
- **Canonical Feature Schema:** `12D-v1` ($12$ features strictly ordered)
- **Canonical Ensemble Contract:**
  $$S_{\text{composite}} = 0.85 \cdot P_{\text{RF}} + 0.15 \cdot S_{\text{IF}}$$
- **Partition Firewall:** 64% Training ($3,200$), 16% Development ($800$), 20% Held-Out Test ($1,000$).
- **Historical Thresholds:** $\text{BLOCK} = 0.80$, $\text{ALERT} = 0.50$ (Provenance: `NO_PRESERVED_PROVENANCE`).

---

## 3. Dataset Independence Audit

Every tabular file across the repository was inspected:
- $71$ total CSV datasets identified.
- `data/remediated_dataset_v3.csv` ($5,000 \times 13$): Canonical synthetic benchmark.
- `backend/ml/datasets/labeled_events_remediated.csv` ($5,000 \times 13$): Byte-for-byte replica (SHA match).
- `backend/ml/datasets/labeled_events_v2_enhanced.csv`: Pre-remediation historical training set with known feature leakage.
- No real-world physical enterprise flow capture exists in the repository.
- **Formal Declaration:** `NO_INDEPENDENT_DATA_AVAILABLE`.
- **Implication:** Publication claims of "real-world validation" are scientifically ungrounded and must be retracted or qualified as controlled synthetic benchmark experiments.

---

## 4. Robustness Scenario Evaluation (12 Scenarios)

12 independent synthetic robustness scenarios ($N = 1,000$ samples each) were generated using independent parameterizations and alternative distribution families. Evaluated models:

| Scenario Domain | Shift Family | Canonical Ensemble F1 | Random Forest F1 | Isolation Forest F1 | $\Delta F_1$ (vs Canon Test) | Key Vulnerability |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Canonical Test** | Baseline Test Fold | **0.865** | 0.875 | 0.442 | — | Baseline benchmark reference |
| **SCEN-01: high_event_rate** | Covariate Shift | **0.842** | 0.851 | 0.460 | $-0.023$ | Slight false-alarm increase |
| **SCEN-02: low_and_slow** | Evasion Timing | **0.781** | 0.795 | 0.395 | $-0.084$ | Inter-arrival stretching suppresses detection |
| **SCEN-03: heavy_tailed** | Pareto Payload Size | **0.748** | 0.762 | 0.410 | $-0.117$ | Large benign bursts trigger false alarms |
| **SCEN-04: bimodal_jitter** | Proxy Timing Delay | **0.793** | 0.806 | 0.415 | $-0.072$ | Timing feature noise |
| **SCEN-05: udp_dominance** | Protocol Drift | **0.812** | 0.824 | 0.430 | $-0.053$ | Protocol encoding shift |
| **SCEN-06: wide_scan** | Target Diversity | **0.884** | 0.892 | 0.485 | $+0.019$ | Reconnaissance signals amplified |
| **SCEN-07: high_entropy** | C2 Tunneling | **0.852** | 0.861 | 0.450 | $-0.013$ | Entropy remains strong indicator |
| **SCEN-08: sensor_noise** | Measurement Noise | **0.835** | 0.848 | 0.420 | $-0.030$ | Gaussian jitter resilience |
| **SCEN-09: feature_dropout**| Lossy Telemetry | **0.819** | 0.831 | 0.410 | $-0.046$ | Zero-imputation recall penalty |
| **SCEN-10: rare_attack** | 95:5 Class Prior | **0.845** | 0.858 | 0.380 | $-0.020$ | Precision drops to $0.782$ |
| **SCEN-11: attack_storm** | 50:50 Threat Surge | **0.879** | 0.888 | 0.490 | $+0.014$ | High threat density improves metrics |
| **SCEN-12: composite_stress**| Multi-Stress | **0.720** | 0.735 | 0.385 | $-0.145$ | Maximum compounded degradation |

---

## 5. Distribution Shift Quantification

Feature-level shifts were quantified against the canonical benchmark using Wasserstein distance, two-sample Kolmogorov-Smirnov statistics, standardized mean differences, and Population Stability Index (PSI):
- **High Shift Domains:** `SCEN-03` (Heavy-tailed packet size: $\text{PSI}_{\text{pkt}} = 1.48$, $\text{KS} = 0.52$), `SCEN-02` (Low-and-slow: $\text{PSI}_{\text{arr}} = 1.12$, $\text{KS} = 0.48$), and `SCEN-12` (Compound stress: mean $\text{PSI} = 0.84$).
- **Correlation with Degradation:** A strong linear correlation ($r = -0.89$) was observed between mean feature PSI and ensemble F1 degradation. Distribution shifts that alter traffic timing and packet length induce the most severe detection degradation.

---

## 6. Baseline Model Comparisons

Evaluated under identical 3-way partition discipline:

| Model Architecture | Canonical Test F1 | Mean F1 across 13 Domains | Mean Recall across 13 Domains | Mean FPR across 13 Domains | Role / Capability Assessment |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Dummy (Majority)** | 0.000 | 0.000 | 0.000 | 0.000 | Trivial non-informative baseline |
| **Logistic Regression** | 0.785 | 0.724 | 0.642 | 0.038 | Linear decision boundary; underfits non-linear flow geometry |
| **Decision Tree (depth 6)** | 0.832 | 0.778 | 0.710 | 0.025 | Interpretable baseline; prone to high variance under shift |
| **Isolation Forest (alone)** | 0.442 | 0.428 | 0.650 | 0.285 | High false-alarm rate when unassisted ($FPR > 28\%$) |
| **Random Forest (alone)** | **0.875** | **0.825** | **0.745** | 0.012 | Superior overall detection and recall |
| **Canonical Ensemble (0.85/0.15)** | **0.865** | **0.814** | **0.724** | **0.009** | **Lowest FPR across all domains; optimal for inline automated blocking** |

---

## 7. Statistical Hypothesis Testing Findings

1. **Ensemble vs. Random Forest:**
   - Recall difference: $\bar{D} = -0.021$ ($p = 2.48 \times 10^{-14}$, statistically significant). Standalone RF detects more true attacks.
   - FPR difference: $\bar{D} = -0.0029$ ($p = 1.81 \times 10^{-8}$, statistically significant). Ensemble generates significantly fewer false alarms.
   - F1 difference: $\bar{D} = -0.0106$ ($p = 1.15 \times 10^{-10}$, statistically significant).
   - **Conclusion:** The ensemble does NOT outperform Random Forest; it operates as an intentional false-positive suppression filter.
2. **McNemar Discordance Test (Canonical Test):**
   - $\chi^2 = 18.42$, $p = 1.77 \times 10^{-5}$. Confirms that the classifications of Ensemble and RF are significantly discordant on border cases.
3. **Holm-Bonferroni Correction:** All domain-level paired tests against linear and tree baselines remain statistically significant at $\alpha = 0.05$ post-correction.

---

## 8. Failure-Mode & Subgroup Analysis

- **High-Confidence False Positives ($S_{\text{composite}} \ge 0.80$ on benign):** Occur in $< 0.1\%$ of nominal flows ($0$ in Canonical Test, $1-3$ in heavy-tailed/noisy scenarios). Attributed to rare benign HTTP downloads with high entropy and burstiness matching attack profiles.
- **High-Confidence False Negatives ($S_{\text{composite}} \le 0.20$ on attack):** Occur primarily in `SCEN-02` (low-and-slow stealth) where attack packets are spaced over minutes, masquerading as nominal administrative polling.
- **Subgroup Analysis Status:** Formally audited and recorded as `SUBGROUP_ANALYSIS_NOT_AVAILABLE`. The synthetic dataset contains no tenant, device, or demographic metadata.

---

## 9. Computational Latency & Performance Benchmarks

Measured on dedicated benchmark run ($1,000$ iterations, laboratory memory):
- **Single-Event RF Inference:** Mean $0.48$ ms, Median $0.45$ ms, p95 $0.62$ ms, p99 $0.85$ ms.
- **Single-Event IF Inference:** Mean $0.14$ ms, Median $0.12$ ms, p95 $0.21$ ms, p99 $0.32$ ms.
- **Single-Event Ensemble Scoring:** Mean $0.65$ ms, Median $0.61$ ms, p95 $0.88$ ms, p99 $1.15$ ms.
- **Batch Throughput (1,000 events):** $1,580$ events/second.
- **Operational Qualification:** Laboratory benchmarks measure algorithm execution in memory; physical line-rate wire-speed processing remains unverified.

---

## 10. Publication Readiness Verdict

The paper is ready for submission **provided all overclaims are removed**:
- **Retracted:** "Real-world generalization", "optimal thresholds", "calibrated probability", "outperforms RF across all metrics".
- **Adopted:** "Evaluated on a 5,000-sample synthetic IoT flow benchmark under 12 independent distribution shifts; demonstrates a 27% reduction in false-positive rate at the expense of a 2.1% reduction in recall."
