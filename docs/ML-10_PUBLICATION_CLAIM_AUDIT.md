# ML-10: Master Publication Claim Audit & Traceability Matrix

---

## 1. Executive Summary

Phase ML-10 audits all manuscript-facing scientific claims across the PhantomNet repository, classifying each claim as `VERIFIED`, `VERIFIED_WITH_QUALIFICATION`, or `UNSUPPORTED` based on immutable empirical artifacts.

---

## 2. Claim Classification Matrix

| Claim ID | Topic | Status | Evidence Artifact | Allowed Manuscript Wording | Forbidden Manuscript Wording |
| :---: | :--- | :---: | :--- | :--- | :--- |
| **CLM-01** | 12D Feature Representation Validity | `VERIFIED` | `ml9_ablation.json` | The 12D representation provides sufficient discriminative signal across benchmark flow distributions under supervised local adaptation ($\text{ROC-AUC} \ge 0.974$). | The 12D representation is universally invariant across all protocols without adaptation. |
| **CLM-02** | Zero-Shot Cross-Domain Generalization | `UNSUPPORTED` | `ml9_transfer_matrix.json` | Frozen zero-shot cross-domain generalization fails severely ($\text{ROC-AUC} = 0.29 \dots 0.35$); static deployment without site adaptation is unsupported. | The model achieves robust zero-shot cross-network generalization. |
| **CLM-03** | Distribution Drift Monitoring | `VERIFIED_WITH_QUALIFICATION` | `ml10_drift_detection.json` | Drift monitoring ($\text{PSI} \ge 0.50$) reliably identifies severe distribution shift and strongly correlates with model degradation ($r = -0.985$). | PSI > 0.25 is a universal mathematical threshold for all possible cyber telemetry. |
| **CLM-04** | Bayesian Threat Score Semantics | `UNSUPPORTED` | `ml10_calibration_governance.json` | Composite threat score is an ordinal ranking; calibrated probabilities require dedicated post-hoc calibration layers. | The composite threat score is a calibrated Bayesian posterior probability. |
| **CLM-05** | Adaptation Safety under Contamination | `VERIFIED_WITH_QUALIFICATION` | `ml10_adaptation_safety.json` | Local adaptation tolerates up to 10% label poisoning ($\text{F1} \ge 0.90$) but degrades severely at 30% ($\text{F1} \le 0.87$), requiring human curation. | Autonomous self-training on live traffic is safe. |
| **CLM-06** | Deterministic Rollback | `VERIFIED` | `ml10_model_governance.json` | Rollback to validated canonical checkpoints is verified with exact 100% SHA-256 hash restoration. | Continual online learning operates without human oversight. |
| **CLM-07** | Hardware Wire-Speed Enforcement | `UNSUPPORTED` | `ml10_latency.json` | Software governance pipeline achieves ~14-20 req/s in sequential Python evaluation; hardware ASIC/FPGA line-rate has not been validated. | The system achieves hardware wire-speed line-rate enforcement. |

---

## 3. Publication Guidance

Authors must strictly adhere to the allowed wording and eliminate all forbidden phrases from draft manuscripts prior to conference or journal submission.
