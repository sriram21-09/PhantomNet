# PhantomNet Phase ML-8: Publication Claim Forensic Audit

## 1. Overview and Scientific Integrity Framework

Phase ML-8 conducts a forensic audit of publication claims in light of empirical evidence obtained from three public network intrusion datasets. In accordance with scientific integrity standards, historical claims are classified into:
- **`VERIFIED`**: Directly supported by reproducible empirical evidence.
- **`VERIFIED WITH QUALIFICATION`**: Supported under specific constraints, requiring explicit qualification.
- **`UNSUPPORTED`**: Contradicted by empirical results.
- **`NOT TESTABLE`**: Lacking verifiable ground-truth evidence.

---

## 2. Publication Claim Matrix

| Claim ID | Audited Claim Text | Relevant Scope | Empirical Finding (Phase ML-8) | Integrity Status | Mandatory Publication / Manuscript Correction |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CLM-ML8-01** | *"The frozen PhantomNet canonical model demonstrates useful out-of-the-box generalization on independent external network data."* | Zero-Shot Cross-Dataset Generalization | Across CIC-IDS2017, NF-ToN-IoT-v2, and UNSW-NB15, the frozen model achieves $ROC\text{-}AUC \in [0.2629, 0.3870]$ and $F1 < 0.20$ due to severe covariate shift. | **UNSUPPORTED** | Disclose explicitly: *"The frozen canonical model trained solely on synthetic flows fails to generalize out of the box to external network datasets without domain adaptation."* |
| **CLM-ML8-02** | *"The 12D-v1 feature contract is sufficiently expressive to detect intrusions when adapted to external domains."* | Feature Representation Expressiveness | Track B adaptation on NF-ToN-IoT-v2 achieves $ROC\text{-}AUC = 0.9746$ and $F1 = 0.9138$ on held-out external test data. | **VERIFIED WITH QUALIFICATION** | Qualify claim: *"The 12D feature representation provides high discriminative capacity when fitted on domain-specific network traffic."* |
| **CLM-ML8-03** | *"The hybrid ensemble outperforms standalone Random Forest across external datasets."* | Ensemble Superiority | Standalone RF achieves higher recall across external datasets ($\Delta = +0.0382, p < 1e-4$); the ensemble functions primarily as a false-positive suppressor ($\Delta \text{FPR} = -0.0148$). | **UNSUPPORTED** | Reframe claim: *"The hybrid ensemble provides false-positive suppression rather than global classification superiority."* |
| **CLM-ML8-04** | *"The composite threat score represents a calibrated probability of attack."* | Calibration Semantics | Expected Calibration Error ($ECE$) reaches $0.312$ to $0.428$ on external datasets. The score violates probability axioms. | **UNSUPPORTED** | Reclassify strictly: *"An ordinal composite threat score reflecting combined supervised and unsupervised anomaly signals, not a calibrated Bayesian probability."* |
| **CLM-ML8-05** | *"Frozen operational thresholds BLOCK=0.80 and ALERT=0.50 are optimal for external networks."* | Operational Thresholds | Due to covariate shift, operating at $BLOCK=0.80$ yields $<4\%$ recall on external data. F1-optimal operating points shift substantially. | **UNSUPPORTED** | Disclose as: *"Heuristic operational policy thresholds with documented trade-offs requiring local calibration per network deployment."* |
| **CLM-ML8-06** | *"PhantomNet autonomously detects zero-day attacks across unseen networks."* | Zero-Day Detection | Unsupervised Isolation Forest flags non-targeted outliers but exhibits false alarm rates $>25\%$ when unassisted by supervised rules. | **UNSUPPORTED** | Qualify as: *"Unsupervised anomaly detection provides auxiliary outlier indicators, subject to increased false-positive rates on unseen traffic."* |
| **CLM-ML8-07** | *"The 12D representation is robust to domain shift without retraining."* | Domain Robustness | $PSI > 0.65$ across timing and packet size features induces catastrophic classification degradation. | **UNSUPPORTED** | Disclose as: *"The 12D representation exhibits substantial sensitivity to transport-layer covariate shift, necessitating adaptation."* |
| **CLM-ML8-08** | *"External benchmark validation was conducted with zero test-set leakage."* | Experimental Integrity | Track A strictly utilized frozen models, frozen scalers, and isolated partitions without external test fitting. | **VERIFIED** | None. Statement is empirically supported. |

---

## 3. Mandatory Manuscript Revision Directives

1. **Title & Abstract**:
   - Strike any phrase asserting "universal zero-shot intrusion detection".
   - Replace with: *"Evaluation of Lightweight Flow-Based Anomaly Detection Across Synthetic and Empirical Network Benchmarks: Opportunities and Limits of Zero-Shot Generalization"*.
2. **Results Section**:
   - Report Track A and Track B side-by-side with full transparency.
   - Emphasize the +0.8510 F1 gain from Track B adaptation to demonstrate that the feature representation is sound, while warning practitioners against unadapted synthetic transfer.
