# ML-10: Statistical Validation Methods & Multiplicity Control

---

## 1. Executive Summary

Phase ML-10 applies rigorous statistical hypothesis testing, Holm-Bonferroni multiplicity control, and 1,000-resample non-parametric bootstrap confidence intervals across all primary experimental comparisons.

---

## 2. Multiplicity Control (Holm-Bonferroni Procedure)

To guard against Family-Wise Error Rate (FWER) inflation across multiple related hypotheses, the Holm-Bonferroni step-down correction was applied:

$$\alpha_{\text{adjusted}, (i)} = \min\left(1.0, \, p_{(i)} \cdot (m - i + 1)\right)$$

| Test ID | Hypothesis | Raw $p$-value | Holm-Bonferroni Adj $p$-value | Significant at $\alpha = 0.05$ |
| :--- | :--- | :---: | :---: | :---: |
| **ST_02** | Isotonic Calibration ECE Reduction | $4.0 \times 10^{-5}$ | $2.4 \times 10^{-4}$ | **YES** |
| **ST_01** | Platt Calibration ECE Reduction | $1.2 \times 10^{-4}$ | $6.0 \times 10^{-4}$ | **YES** |
| **ST_04** | 30% Contamination Degradation | $2.1 \times 10^{-4}$ | $8.4 \times 10^{-4}$ | **YES** |
| **ST_05** | Drift vs ROC-AUC Correlation ($r = -0.985$) | $8.0 \times 10^{-4}$ | $2.4 \times 10^{-3}$ | **YES** |
| **ST_06** | Port Randomization Sensitivity | $1.1 \times 10^{-3}$ | $2.2 \times 10^{-3}$ | **YES** |
| **ST_03** | 10% Contamination Degradation | $1.42 \times 10^{-2}$ | $1.42 \times 10^{-2}$ | **YES** |

All 6 primary hypotheses remain statistically significant after rigorous multiplicity correction.

---

## 3. 95% Bootstrap Confidence Intervals

- **Pipeline Latency**: $70.19\text{ ms}$ (95% CI: $[45.12, 154.16]\text{ ms}$)
- **Clean Adaptation F1 (NF-ToN-IoT)**: $0.919$ (95% CI: $[0.901, 0.936]$)
- **Contaminated (30%) F1 (NF-ToN-IoT)**: $0.874$ (95% CI: $[0.852, 0.895]$)
- **Platt Calibrated ECE (NF-ToN-IoT)**: $0.0305$ (95% CI: $[0.0210, 0.0410]$)
