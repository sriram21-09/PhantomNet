# Phase ML-9: Publication Claim Traceability & Scientific Verification

## 1. Executive Summary

Phase ML-9 provides an exhaustive audit of all manuscript and repository claims across the PhantomNet codebase, classifying each claim into formal evidence categories:
- **`VERIFIED`**: Directly demonstrated with rigorous empirical and statistical evidence.
- **`VERIFIED WITH QUALIFICATION`**: Demonstrated under explicitly stated domain and adaptation boundaries.
- **`UNSUPPORTED`**: Lacks empirical evidence or contradicted by experimental findings.
- **`OUTDATED`**: Historical assertion superseded by Phase ML-1 through ML-9 audits.

---

## 2. Claim Verification Matrix

| Claim ID | Category | Claim Statement | Final Status | Empirical & Statistical Evidence |
| :--- | :--- | :--- | :---: | :--- |
| **CLM-ML9-01** | Generalization | Frozen synthetic model generalizes zero-shot to external network domains. | **UNSUPPORTED** | Zero-shot ROC-AUC drops to $0.29 \dots 0.35$ under severe distribution shift ($\text{PSI} > 1.6$). Contradicted by transfer matrix. |
| **CLM-ML9-02** | Representation | 12D-v1 canonical feature contract provides discriminative representation under local retraining. | **VERIFIED WITH QUALIFICATION** | Retrained RF achieves $\text{ROC-AUC} \ge 0.974$ and $\text{F1} \ge 0.914$ across all external domains. Requires local training data. |
| **CLM-ML9-03** | Calibration | Composite threat score $S_{\text{composite}} = 0.85 P_{\text{RF}} + 0.15 S_{\text{IF}}$ is a calibrated posterior probability. | **UNSUPPORTED** | Score is a linear combination of tree votes and heuristic anomaly distance. Designated `ORDINAL_COMPOSITE_THREAT_SCORE`. |
| **CLM-ML9-04** | Thresholds | Thresholds $\text{ALERT}=0.50$ and $\text{BLOCK}=0.80$ are empirically optimal values. | **UNSUPPORTED** | Optimal F1 thresholds vary by domain ($0.48 \dots 0.54$). Constants designated as `NO_PRESERVED_PROVENANCE` heuristic defaults. |
| **CLM-ML9-05** | Ensemble | The 0.85/0.15 ensemble is universally superior to standalone Random Forest. | **UNSUPPORTED** | Paired tests show standalone RF achieves identical or slightly higher F1 on adapted benchmarks ($\text{F1} = 0.914 \text{ vs } 0.914$). |
| **CLM-ML9-06** | Adaptation | Local domain adaptation is highly sample-efficient ($\ge 5\% \dots 10\%$ local data). | **VERIFIED** | 10-seed learning curves demonstrate $\text{ROC-AUC} > 0.96$ with only $320$ local samples ($10\%$ training split). |
| **CLM-ML9-07** | Distribution Shift | Feature distribution divergence (PSI/Wasserstein) is positively associated with transfer degradation. | **VERIFIED** | Spearman correlation $r_s = 0.812$ ($p < 0.01$) between mean PSI and cross-domain ROC-AUC degradation. |
| **CLM-ML9-08** | Deployment | Turnkey zero-shot production deployment is supported across arbitrary networks. | **UNSUPPORTED** | Prohibited. Production deployment requires mandatory local adaptation, continuous drift monitoring, and dynamic thresholding. |

---

## 3. Publication Guidance for Authors

- **Allowed Claims**: Rapid local adaptation sample efficiency; high discriminative capacity of 12D representation under local training; correlation between feature drift and performance drop.
- **Prohibited Claims**: "Zero-shot real-world generalization", "Bayesian calibrated posterior threat score", "universally superior ensemble", "production-ready without adaptation".
