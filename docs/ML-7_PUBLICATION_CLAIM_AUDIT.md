# PhantomNet Phase ML-7: Publication Claim Forensic Audit

## 1. Executive Summary

This forensic audit evaluates every quantitative and performance claim made in historical documentation, technical notes, READMEs, and draft manuscripts regarding PhantomNet's machine learning capabilities. In accordance with strict scientific integrity guidelines, all numerical claims were programmatically audited against verified Phase ML-7 artifacts, empirical distribution-shift evaluations, and paired statistical significance tests.

Each audited claim is classified into one of five rigorous scientific integrity categories:
- **`VERIFIED`**: Supported by reproducible, leakage-free empirical evidence.
- **`PARTIALLY_SUPPORTED`**: Supported under specific constraints, but requires narrower qualification.
- **`UNSUPPORTED`**: Contradicted by empirical findings or lacking valid methodological provenance.
- **`OUTDATED`**: Superseded by Phase ML-6/ML-7 remediation protocols.
- **`REQUIRES_QUALIFICATION`**: Directionally valid but overgeneralized in scope or operational semantics.

---

## 2. Publication Claim Matrix

| Claim ID | Audited Claim Text | Historical Source | Relevant Metric / Scope | Phase ML-7 Empirical Evidence | Integrity Classification | Mandatory Manuscript / Documentation Correction |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **CLM-ML7-01** | *"The hybrid ensemble outperforms standalone Random Forest."* | Manuscripts, Technical README | Overall Accuracy, F1-Score, Recall | In paired bootstrap testing over 13 evaluation domains (1,000 resamples), RF achieves significantly higher recall ($\Delta = +0.0210, p = 2.48 \times 10^{-14}$) and F1 ($\Delta = +0.0106, p = 1.15 \times 10^{-10}$). The ensemble is an operational false-positive suppression trade-off, not an all-around superior classifier. | **UNSUPPORTED** | Reframe claim: *"The hybrid ensemble achieves superior false-positive suppression (FPR 0.0077 vs 0.0106, p < 1e-7) at the expense of a modest 2.1% reduction in attack recall."* |
| **CLM-ML7-02** | *"The composite score represents a well-calibrated probability of attack."* | Technical Summaries, Docstrings | Expected Calibration Error (ECE), Brier Score | IF anomaly scores are non-probabilistic. Injecting IF degrades ECE from $0.0531$ (RF alone) to $0.0850$ (Ensemble) and increases Brier loss from $0.0215$ to $0.0583$. Ensemble scores violate probability axioms. | **UNSUPPORTED** | Redefine strictly: *"An ordinal composite threat score reflecting combined supervised pattern-matching and unsupervised anomaly evidence, not a calibrated Bayesian probability."* |
| **CLM-ML7-03** | *"Thresholds BLOCK=0.80 and ALERT=0.50 are mathematically optimal decision boundaries."* | Architecture Notes, ML Config | Threshold Grid Sweep, ROC/PR Curves | Audit confirmed historical provenance gap (`NO_PRESERVED_PROVENANCE`). F1-optimal threshold on Development partition is $T=0.380$. $T=0.80$ is a high-precision, low-false-alarm operational heuristic. | **UNSUPPORTED** | Disclose as: *"Heuristically established operational policy thresholds chosen to minimize production interruption risk, with documented precision-recall trade-offs."* |
| **CLM-ML7-04** | *"The system demonstrates proven real-world generalization across enterprise networks."* | Abstract & Conclusion Drafts | External Network Validation | Audit of all 71 CSV files in repository confirmed `NO_INDEPENDENT_DATA_AVAILABLE`. Validated exclusively on a 5,000-sample synthetic IoT flow benchmark under simulated distribution shifts. | **UNSUPPORTED** | Qualify claim: *"Demonstrated on a 5,000-sample synthetic IoT flow benchmark under simulated distribution shifts; physical enterprise validation remains future work."* |
| **CLM-ML7-05** | *"The system autonomously detects novel zero-day attacks."* | Architecture Whitepapers | Novel Attack Class Outlier Detection | Unsupervised Isolation Forest flags statistical anomalies, but standalone IF exhibits poor precision ($\approx 0.45$) on unstructured noise. It acts as an auxiliary anomaly alert, not an autonomous oracle. | **REQUIRES_QUALIFICATION** | State: *"Unsupervised anomaly detection provides auxiliary detection of novel structural deviations, subject to increased false-positive rates if unassisted by supervised rules."* |
| **CLM-ML7-06** | *"Sub-millisecond inference enables wire-speed line-rate packet blocking."* | Benchmark Reports, Marketing Notes | Inference Latency Benchmarks | Single-event model inference takes 0.65 ms in Python memory. This excludes OS network stack traversal, pcap capture, flow table reassembly, and feature extraction latencies. | **REQUIRES_QUALIFICATION** | Clarify: *"Measured sub-millisecond latency reflects laboratory model inference in memory, distinct from end-to-end wire-speed packet processing in hardware."* |
| **CLM-ML7-07** | *"Model evaluation is strictly leakage-free under a 3-way partition protocol."* | ML-6 & ML-7 Specifications | Partition Independence & Firewall Tests | Verified. 3-way partition (Train 64% / Dev 16% / Test 20%) is strictly enforced with automated test suites verifying firewall integrity against test leakage. | **VERIFIED** | None. Statement is empirically supported. |
| **CLM-ML7-08** | *"The 12D canonical network flow feature contract is strictly enforced."* | ML-3 Specification & Schema Contract | Feature Schema Contract Tests | Verified. All 12 features and exact ordering are strictly validated across backend and experiment pipelines (`backend/ml/config/feature_schema.py`). | **VERIFIED** | None. Statement is empirically supported. |

---

## 3. Detailed Forensic Analysis by Scientific Domain

### 3.1 Superiority Claims (CLM-ML7-01)
- **Historical Claim**: Standalone RF is inferior to the ensemble.
- **Forensic Findings**: The 0.85 RF + 0.15 IF ensemble yields a lower overall F1-score across all 12 perturbation scenarios ($0.8858$ vs $0.8964$). The primary statistical advantage of the ensemble is risk mitigation against false positives ($FPR = 0.0077$ for Ensemble vs $0.0106$ for RF alone, a 27.4% reduction). In high-throughput network environments, suppressing false block actions is critical; however, framing this as "general classifier superiority" is factually false.

### 3.2 Calibration and Probability Semantics (CLM-ML7-02)
- **Historical Claim**: Composite scores are probabilities of compromise.
- **Forensic Findings**: The Isolation Forest anomaly score is derived from tree path lengths and min-max scaled into $[0, 1]$ using historical training distributions. Linearly blending this value with calibrated RF probabilities destroys the probabilistic calibration. The resulting score is purely ordinal. Any downstream Bayesian decision-making framework relying on this value as a true posterior probability will compute erroneous risk expectations.

### 3.3 Decision Thresholds (CLM-ML7-03)
- **Historical Claim**: $0.80$ is an empirically optimal threshold.
- **Forensic Findings**: Threshold sweeps on the Development partition reveal that maximum F1 ($0.978$) occurs at $T = 0.380$. Operating at $T = 0.80$ yields an F1 of $0.875$ with $Recall = 0.778$, but guarantees $Precision = 1.000$ and $FPR = 0.0000$. Thus, $T = 0.80$ is a high-confidence, zero-tolerance blocking policy threshold, not an F1-optimal threshold.

### 3.4 Generalization and External Evidence (CLM-ML7-04)
- **Historical Claim**: Demonstrated robustness across diverse production enterprise environments.
- **Forensic Findings**: An exhaustive audit of the 71 data files in the repository identified zero independent physical production captures. Every dataset is either a synthetic generation, an experimental subset, or a transformed replay. While the model is resilient to several simulated mathematical shifts, claiming enterprise-grade real-world validation without physical tap traces constitutes a serious scientific overstatement.

---

## 4. Remediation Directives for Publication Manuscript

1. **Abstract**:
   - Replace any mention of "probabilistic attack confidence" with "composite threat scoring".
   - Replace "proven enterprise generalization" with "evaluated across 12 synthetic distribution-shift scenarios simulating adversarial and environmental variations".
2. **Introduction & Architecture**:
   - Clarify that the $0.85/0.15$ ensemble is designed for **precision-oriented false-positive dampening**, not maximize raw recall.
   - Explicitly cite the 3-way partition protocol (64% Train / 16% Dev / 20% Test) and the complete isolation of test data during calibration and threshold setting.
3. **Evaluation Section**:
   - Present Table of paired statistical comparisons showing both RF and Ensemble metrics side-by-side, acknowledging RF's recall advantage and the Ensemble's FPR suppression advantage.
   - Include the ECE and Brier calibration degradation metrics to justify the designation of composite threat scores as ordinal rather than Bayesian probabilities.
4. **Limitations Section**:
   - Prominently disclose the 15 items in the scientific limitation register, particularly the synthetic benchmark constraint, lack of subgroup metadata, and heuristic threshold provenance.
