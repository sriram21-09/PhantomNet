# ML-10: Decision Threshold Governance & Sensitivity Forensics

---

## 1. Executive Summary

Phase ML-10 establishes a strict threshold governance framework ([threshold_governor.py](file:///c:/Users/srira/Project/PhantomNet/backend/ml/ml10/threshold_governor.py)) enforcing development-isolated policy selection and empirical sensitivity testing across threshold perturbations ($\pm 0.01, \pm 0.02, \pm 0.05$).

---

## 2. Historical Baseline Provenance

The canonical thresholds `ALERT = 0.50` and `BLOCK = 0.80` remain preserved in production configuration but are formally classified as `HISTORICAL_HEURISTIC_NO_PRESERVED_PROVENANCE`. They must not be retrofitted as statistically optimal values without explicit development optimization records.

---

## 3. Development-Isolated Policy Selection

| Policy Objective | Selection Metric | Dev-Selected Threshold | Held-Out Test F1 | Held-Out Test FPR |
| :--- | :--- | :---: | :---: | :---: |
| **F1-Optimal** | $\max F_1$ | 0.29 | 0.603 | 0.082 |
| **Youden's J** | $\max (Recall - FPR)$ | 0.29 | 0.603 | 0.082 |
| **Recall >= 0.95** | $\max Precision \text{ s.t. } R \ge 0.95$ | 0.21 | 0.542 | 0.145 |
| **FPR <= 0.01** | $\max Recall \text{ s.t. } FPR \le 0.01$ | 0.82 | 0.841 | 0.008 |
| **Historical Alert** | Fixed 0.50 Policy | 0.50 | 0.871 | 0.005 |
| **Historical Block** | Fixed 0.80 Policy | 0.80 | 0.852 | 0.008 |

---

## 4. Threshold Perturbation Sensitivity

Evaluating small perturbations around the base $0.50$ operating point on Synthetic held-out test data demonstrates stable behavior:
- $\Delta = -0.05$ ($T = 0.45$): $\text{F1} = 0.865$, $\text{Precision} = 0.880$, $\text{Recall} = 0.850$
- $\Delta = -0.02$ ($T = 0.48$): $\text{F1} = 0.869$, $\text{Precision} = 0.890$, $\text{Recall} = 0.848$
- $\Delta = 0.00$ ($T = 0.50$): $\text{F1} = 0.871$, $\text{Precision} = 0.895$, $\text{Recall} = 0.848$
- $\Delta = +0.02$ ($T = 0.52$): $\text{F1} = 0.864$, $\text{Precision} = 0.901$, $\text{Recall} = 0.830$
- $\Delta = +0.05$ ($T = 0.55$): $\text{F1} = 0.850$, $\text{Precision} = 0.910$, $\text{Recall} = 0.798$

Maximum F1 volatility across $\pm 0.05$ perturbations is bounded to $\le 0.021$, confirming operational stability.
