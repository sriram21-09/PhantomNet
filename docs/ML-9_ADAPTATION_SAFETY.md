# Phase ML-9: Adaptation Safety Boundaries & Failure Mode Forensics

## 1. Executive Summary

Phase ML-9 evaluates the failure modes and safety boundaries of local domain adaptation through extensive stress testing:
1. **Sample Size Degradation** ($N = 10 \dots 3,200$)
2. **Extreme Class Imbalance** (Attack prevalence $1\% \dots 90\%$)
3. **Label Noise Inversion** ($0\% \dots 40\%$ inverted training labels)
4. **Missing Dimension Tolerance** ($0 \dots 6$ unobserved/zeroed features)

---

## 2. Adaptation Safety Envelope

| Stress Dimension | Failure Threshold | Observed Effect | Recommended Safety Guardrail |
| :--- | :---: | :--- | :--- |
| **Minimum Training Sample Size** | $N < 100$ | High variance; F1 drops below $0.80$ | Require minimum $N = 250$ labeled local flow records prior to deployment. |
| **Minimum Attack Prevalence** | $< 2\%$ | High false negative rate ($\text{FNR} > 0.40$) | Require stratified local sampling with at least $5\%$ minority attack instances. |
| **Maximum Tolerable Label Noise** | $> 15\%$ | Degradation of decision boundaries ($\text{F1} < 0.85$) | Deploy label verification and automated outlier scrubbing before local model training. |
| **Maximum Missing Features** | $> 2$ dimensions | Degradation of tree split depth and ranking accuracy | Strictly validate 12D contract schema; quarantine traffic with missing flow dimensions. |

---

## 3. Automated Drift Response Protocol

When distribution shift is monitored in production pipelines via Population Stability Index (PSI):
- **`NORMAL` ($\text{PSI} < 0.10$)**: Standard operation using locally adapted models.
- **`WARNING` ($0.10 \le \text{PSI} \le 0.25$)**: Trigger operational alert; schedule supervised local dataset capture and retraining review.
- **`SEVERE` ($\text{PSI} > 0.25$)**: Automated model quarantine; fall back to conservative high-confidence alert policy ($\theta = 0.80$) and enforce mandatory local domain adaptation.
