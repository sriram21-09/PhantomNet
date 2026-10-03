# Phase ML-9: Threshold Forensics & Policy Provenance

## 1. Executive Summary

Phase ML-9 resolves the historical provenance and empirical validity of operational decision thresholds:
- **ALERT Threshold**: Default $\theta = 0.50$
- **BLOCK Threshold**: Default $\theta = 0.80$

### Scientific Protocol
All candidate operational thresholds are selected **exclusively on the 16% development partition** ($N = 800$), and subsequently evaluated **exactly once on the held-out 20% test partition** ($N = 1,000$). No test set data was used for threshold optimization.

---

## 2. Threshold Sweep & Objective Comparison

| Domain | Policy Objective | Dev Selected $\theta$ | Test Precision | Test Recall | Test F1 | Test FPR | Test FNR | Provenance Status |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **NF-ToN-IoT-v2** | F1-Optimal (Dev) | 0.48 | 0.913 | 0.917 | **0.915** | 0.037 | 0.083 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Youden's J (Dev) | 0.44 | 0.902 | 0.930 | 0.916 | 0.043 | 0.070 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Min FPR (Recall $\ge 0.95$) | 0.35 | 0.865 | 0.953 | 0.907 | 0.063 | 0.047 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Min FNR (FPR $\le 0.05$) | 0.52 | 0.917 | 0.903 | 0.910 | 0.034 | 0.097 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Fixed ALERT (0.50) | 0.50 | 0.916 | 0.913 | 0.914 | 0.036 | 0.087 | `NO_PRESERVED_PROVENANCE` |
| | Fixed BLOCK (0.80) | 0.80 | 0.963 | 0.773 | 0.858 | 0.013 | 0.227 | `NO_PRESERVED_PROVENANCE` |
| **CIC-IDS2017** | F1-Optimal (Dev) | 0.52 | 0.987 | 0.990 | **0.988** | 0.006 | 0.010 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Youden's J (Dev) | 0.48 | 0.987 | 0.990 | 0.988 | 0.006 | 0.010 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Min FPR (Recall $\ge 0.95$) | 0.60 | 0.987 | 0.987 | 0.987 | 0.006 | 0.013 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Min FNR (FPR $\le 0.05$) | 0.40 | 0.984 | 0.993 | 0.988 | 0.007 | 0.007 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Fixed ALERT (0.50) | 0.50 | 0.987 | 0.990 | 0.988 | 0.006 | 0.010 | `NO_PRESERVED_PROVENANCE` |
| | Fixed BLOCK (0.80) | 0.80 | 0.993 | 0.953 | 0.973 | 0.003 | 0.047 | `NO_PRESERVED_PROVENANCE` |
| **UNSW-NB15** | F1-Optimal (Dev) | 0.54 | 0.966 | 0.953 | **0.960** | 0.014 | 0.047 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Youden's J (Dev) | 0.46 | 0.957 | 0.963 | 0.960 | 0.019 | 0.037 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Min FPR (Recall $\ge 0.95$) | 0.52 | 0.963 | 0.957 | 0.960 | 0.016 | 0.043 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Min FNR (FPR $\le 0.05$) | 0.42 | 0.951 | 0.967 | 0.959 | 0.021 | 0.033 | `EMPIRICALLY_OPTIMIZED_ON_DEV` |
| | Fixed ALERT (0.50) | 0.50 | 0.963 | 0.957 | 0.960 | 0.016 | 0.043 | `NO_PRESERVED_PROVENANCE` |
| | Fixed BLOCK (0.80) | 0.80 | 0.985 | 0.877 | 0.928 | 0.006 | 0.123 | `NO_PRESERVED_PROVENANCE` |

---

## 3. Provenance Audit Verdict

1. **Classification of Fixed 0.50 and 0.80**: The values $\text{ALERT}=0.50$ and $\text{BLOCK}=0.80$ represent **heuristic operational trade-off defaults** rather than mathematically optimal values derived from statistical optimization. They are officially designated with **`NO_PRESERVED_PROVENANCE`**.
2. **Operational Recommendation**: Production deployments should dynamically optimize decision thresholds on a local development split targeting specific organization cost ratios between false alarms (FPR) and missed attacks (FNR).
