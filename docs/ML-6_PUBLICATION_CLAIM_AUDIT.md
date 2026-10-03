# PhantomNet Phase ML-6: Publication Claim Forensic Audit

**Audit Phase:** ML-6 (Threshold, Calibration & Decision-Boundary Forensics)  
**Date:** 2026-10-02  
**Auditor:** Senior ML Auditor & Reproducibility Engineer  
**Status:** COMPLETE AUDIT RECORD

---

## 1. Executive Summary

This document audits the historical research claims, paper drafts, and technical summaries in the PhantomNet repository regarding model probability calibration, decision thresholds, and comparative performance. Claims are classified strictly on empirical evidence generated across $N = 30$ independent runs, test-set firewall isolation, and formal statistical testing.

---

## 2. Claim Classification Matrix

| Claim ID | Paper / Documentation Statement | Historical Characterization | Empirical Reality (Phase ML-6) | Forensic Classification | Remediation Requirement |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CLM-PUB-01** | *"The hybrid score provides a well-calibrated attack probability."* | Interpreted composite score as a Bayes probability. | Ensemble ECE is $0.074 \pm 0.005$ and Brier is $0.054 \pm 0.003$. Adding IF anomaly scores degrades calibration compared to RF ($ECE \approx 0.039$). | **UNSUPPORTED** | Redefine as *"ordinal composite threat score"*, never *"calibrated probability"*. |
| **CLM-PUB-02** | *"The decision thresholds (0.80 Block, 0.50 Alert) are optimal."* | Implied empirically derived decision boundaries. | No preserved optimization record exists. Derived heuristically in early rule development. ROC sweep in Week 11 failed with `AUC: nan`. | **UNSUPPORTED / HISTORICAL_ONLY** | Disclose as *"heuristically established operational thresholds with documented trade-offs"*. |
| **CLM-PUB-03** | *"The hybrid ensemble outperforms standalone Random Forest."* | Claimed aggregate performance superiority. | In paired statistical testing across $N=30$ runs, RF achieves higher F1 ($0.871$ vs $0.865$, $p < 10^{-4}$) and lower Brier loss. Ensemble reduces FPR slightly ($0.004$ vs $0.006$) at the cost of lower recall ($0.771$ vs $0.785$). | **PARTIALLY_VERIFIED (TRADE-OFF ONLY)** | Replace claim of "superiority" with explicit characterization of the precision/recall and FPR/FNR trade-off. |
| **CLM-PUB-04** | *"Reduces false positives without compromising detection capability."* | Implied zero-cost trade-off. | Paired analysis shows a statistically significant decrease in recall ($1.4\%$ drop, $p < 10^{-4}$) when adding the IF component. | **REFUTED** | Explicitly report that false-positive suppression incurs a measurable false-negative penalty. |
| **CLM-PUB-05** | *"System demonstrates proven real-world generalization."* | Asserted operational readiness from synthetic benchmarks. | Validated strictly on synthetic IoT flow data (`remediated_dataset_v3.csv`). No real-world production network traffic was evaluated. | **UNSUPPORTED / OVERCLAIM** | Downgrade claim to *"demonstrated on synthetic benchmark flows under controlled experimental conditions"*. |
| **CLM-PUB-06** | *"Threshold selection is scientifically rigorous and leakage-free."* | Previously assumed clean separation. | Phase ML-6 discovered that historical IF calibration bounds were derived from the entire dataset, and ML-5 scripts used test-set bounds. | **CORRECTED IN ML-6** | Document the historical `TEST_SET_CALIBRATION_LEAKAGE` and report new results under the verified 3-way partition protocol. |

---

## 3. Normative Style Guidelines for Publication

1. **Terminology Mandate:**
   - Use: *"composite threat score"*, *"risk ranking"*, *"decision index"*.
   - Prohibited: *"calibrated probability of compromise"*, *"Bayesian posterior likelihood"*.
2. **Comparative Mandate:**
   - Report: *"The ensemble offers an operational operating point favoring lower false-positive rates at the expense of recall."*
   - Prohibited: *"The ensemble demonstrates superior detection performance."*
3. **Generalization Mandate:**
   - State clearly: *"All quantitative findings reflect the 5,000-sample synthetic IoT benchmark (`data/remediated_dataset_v3.csv`) and have not been externally validated on heterogeneous physical network taps."*
