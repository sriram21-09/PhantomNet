# Phase ML-9: Deployment Readiness & Operational Architecture

## 1. Executive Summary

Phase ML-9 evaluates the readiness of the PhantomNet machine learning architecture across four standardized deployment tiers.

---

## 2. Four-Tier Deployment Readiness Evaluation

| Deployment Tier | Evaluation Status | Mandatory Operational Prerequisites |
| :--- | :---: | :--- |
| **Tier 1: Offline Research Use** | **APPROVED** | Pinned deterministic random seeds; 12D-v1 schema contract enforcement; standard Python scientific environment. |
| **Tier 2: Laboratory Prototype** | **APPROVED WITH CONSTRAINTS** | Isolated laboratory testbed network; sub-50 $\mu$s inference latency verified; known traffic distributions. |
| **Tier 3: Controlled Testbed** | **CONDITIONALLY APPROVED** | Mandatory local calibration dataset ($N \ge 250$ records); baseline PSI distribution shift establishment. |
| **Tier 4: Turnkey Production Deployment** | **NOT APPROVED FOR ZERO-SHOT** | **Prohibited from zero-shot deployment.** Requires automated local adaptation pipeline, continuous PSI drift monitoring, dynamic threshold optimization on development traffic, automated quarantine mechanisms, and post-hoc probability calibration. |

---

## 3. Mandatory Production Operational Safeguards

1. **Local Domain Adaptation Pipeline**: Ingest local network flows and fit local classifier weights before routing live traffic.
2. **Distribution Shift Monitoring**: Continuous calculation of Population Stability Index (PSI); trigger automated quarantine on `SEVERE` shift ($\text{PSI} > 0.25$).
3. **Dynamic Threshold Tuning**: Optimize alert/block decision thresholds on local development partition rather than relying on uncalibrated historical constants.
4. **Post-Hoc Probability Calibration**: Use Platt scaling or Isotonic regression to convert tree voting fractions into calibrated probabilities for automated blocking.
5. **Contract Validation**: Reject any flow record that violates the canonical 12D-v1 schema.
