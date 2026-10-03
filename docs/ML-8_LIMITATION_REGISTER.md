# PhantomNet Phase ML-8: Scientific Limitation Register

## 1. Overview and Extension Protocol

Phase ML-8 formally extends the Scientific Limitation Register established in Phase ML-7 (LIM-01 to LIM-15) with five new critical limitations (LIM-16 to LIM-20) arising from external benchmark validation and feature mapping audits.

---

## 2. Complete Scientific Limitation Register (LIM-01 to LIM-20)

| ID | Title | Severity | Empirical Evidence (ML-8 Audit) | Operational Consequence | Mitigation / Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **LIM-01** | Synthetic Benchmark Constraint | HIGH | Initial evaluation was conducted solely on synthetic IoT flow data (`remediated_dataset_v3.csv`). | Performance on live physical networks cannot be inferred from synthetic data alone. | **MITIGATED IN ML-8 VIA EXTERNAL BENCHMARKING** |
| **LIM-02** | Absence of External Validation Data | HIGH | Prior to ML-8, zero external datasets existed in the active evaluation pipeline. | Generalization claims were bounded to synthetic distribution shifts. | **RESOLVED IN ML-8** (CIC-IDS2017, NF-ToN-IoT-v2, and UNSW-NB15 evaluated). |
| **LIM-03** | Domain & Covariate Shift Degradation | CRITICAL | Frozen canonical models exhibit $ROC\text{-}AUC \in [0.2629, 0.3870]$ and $F1 < 0.20$ on external datasets. | Out-of-the-box deployment on external networks without adaptation will fail catastrophically. | **EMPIRICALLY CONFIRMED IN ML-8** |
| **LIM-04** | Class-Prior Sensitivity | MEDIUM | In high-volume production networks with low attack prevalence, relative false alarm volume increases. | Increased analyst fatigue unless automated blocking is restricted to high-confidence thresholds. | **DOCUMENTED** |
| **LIM-05** | Non-Probabilistic Score Semantics | MEDIUM | Blending IF anomaly scores destroys probabilistic calibration ($ECE > 0.30$ externally). | Scores cannot be used as Bayesian posterior probabilities of compromise. | **RECLASSIFIED AS ORDINAL COMPOSITE SCORE** |
| **LIM-06** | Absence of Historical Threshold Provenance | MEDIUM | $BLOCK=0.80$ and $ALERT=0.50$ lack historical derivation logs (`NO_PRESERVED_PROVENANCE`). | Thresholds represent heuristic policy choices rather than cost-minimized empirical points. | **DOCUMENTED** |
| **LIM-07** | Frozen Ensemble Weight Formulation | LOW | Canonical weights are frozen at $0.85 \times P_{\text{RF}} + 0.15 \times S_{\text{IF}}$ by contract. | Dynamic weighting conditioned on traffic regime is precluded. | **DOCUMENTED FOR REPRODUCIBILITY** |
| **LIM-08** | Training Size Reduction from 3-Way Partitioning | LOW | Allocating 16% to Development partition reduced training samples from 4,000 to 3,200. | Minor loss in sample size; necessary trade-off for test isolation. | **MITIGATED** |
| **LIM-09** | Absence of Subgroup / Demographic Metadata | LOW | Network flow records lack demographic, device hardware, or tenant metadata. | Algorithmic fairness and subgroup disparity analysis cannot be performed. | **DOCUMENTED (`SUBGROUP_ANALYSIS_NOT_AVAILABLE`)** |
| **LIM-10** | Feature Space Dimensionality & Granularity | LOW | Feature contract is restricted to 12 aggregate transport-layer statistics (`12D-v1`). | Deep packet payloads, encrypted TLS handshakes, and SNI are unobserved. | **BY DESIGN (Privacy-preserving, lightweight)** |
| **LIM-11** | Potential Synthetic Generator Artifacts | HIGH | Synthetic traffic was generated via parametric mathematical distributions (Gamma, Poisson). | Decision trees learn artifactual split points that do not generalize to empirical traffic. | **CONFIRMED IN ML-8** |
| **LIM-12** | Statistical Power on Extreme Tail Outliers | LOW | High-confidence prediction errors occur in small sub-sample sizes. | Subgroup failure-mode decomposition has limited sample size. | **DOCUMENTED** |
| **LIM-13** | Inference Latency Metric Generalizability | LOW | Latency was measured strictly in Python memory on a local CPU. | Cannot be extrapolated to 10/40/100 Gbps wire-speed hardware switches. | **DOCUMENTED** |
| **LIM-14** | Static Model Drift over Time | HIGH | Checkpoints are static and lack streaming concept-drift detection. | Zero-day threat variants or seasonal network pattern shifts degrade model accuracy over time. | **CONFIRMED** |
| **LIM-15** | Dependence on Transport-Layer Integrity | MEDIUM | Features rely on packet sizing, inter-arrival timing, and port metadata. | Adversarial transport-layer obfuscation (packet padding, timing jitter) degrades detection. | **CONFIRMED** |
| **LIM-16** | External Feature Telemetry Mismatch | CRITICAL | NetFlow v2, Argus, and CICFlowMeter CSVs lack native payload entropy and sliding-window multi-host state. | Required mapping approximations that introduce information loss during external evaluation. | **DOCUMENTED IN ML-8** |
| **LIM-17** | Approximation of Missing Payload Entropy | HIGH | Public flow datasets omit raw payloads; payload entropy was imputed with median ($3.724$). | Eliminates the discriminative contribution of application-layer complexity. | **QUANTIFIED IN ML-8** |
| **LIM-18** | Label Definition Incommensurability | MEDIUM | Attack ground-truth definitions differ across benchmarks (e.g. CIC-IDS2017 PortScan vs NF-ToN-IoT-v2 Scanning). | Binary attack categorization groups disparate attack mechanisms under a single label. | **DOCUMENTED IN ML-8** |
| **LIM-19** | Dataset Vintage & Testbed Biases | MEDIUM | Ingested public datasets originate from 2015-2020 laboratory testbeds. | Testbed artifacts may not reflect modern containerized and encrypted cloud workloads. | **DOCUMENTED IN ML-8** |
| **LIM-20** | Operational Misalignment of Frozen Policy Thresholds | HIGH | Operating at $BLOCK=0.80$ on shifted external distributions yields $<4\%$ recall. | Production deployments cannot use hardcoded thresholds without local empirical calibration. | **CONFIRMED IN ML-8** |

---

## 3. Register Summary

- **Total Formal Limitations**: 20
- **Critical Severity**: 2 (LIM-03, LIM-16)
- **High Severity**: 6 (LIM-01, LIM-02, LIM-11, LIM-14, LIM-17, LIM-20)
- **Medium Severity**: 6 (LIM-04, LIM-05, LIM-06, LIM-15, LIM-18, LIM-19)
- **Low / Design Constraints**: 6 (LIM-07, LIM-08, LIM-09, LIM-10, LIM-12, LIM-13)
