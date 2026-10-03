# Phase ML-9: Representation Validity & Frozen vs Retrained Decomposition

## 1. Executive Summary

Phase ML-9 explicitly separates **representation validity** (the informational sufficiency of the 12D-v1 feature space) from **frozen classifier validity** (the hypothesis that weights learned on synthetic honeynet traffic generalize zero-shot).

### Causal-Free Decomposition Matrix

To isolate the source of performance gains during adaptation, we evaluate six configurations across all external benchmarks:
- **C1**: Canonical synthetic-trained RF applied directly (zero-shot)
- **C2**: External-domain RF trained on unscaled 12D-v1
- **C3**: External-domain RF trained with local StandardScaler (fit on train only)
- **C4**: External-domain RF trained with fixed canonical synthetic scaler
- **C5**: External-domain Logistic Regression (linear baseline with local scaling)
- **C6**: External-domain Decision Tree (depth=8, unscaled)

---

## 2. Decomposition Results

| Domain | Config | ROC-AUC | F1 Score | Accuracy | FPR | FNR |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **NF-ToN-IoT-v2** | C1: Frozen Synthetic RF (Zero-Shot) | 0.296 | 0.442 | 0.470 | 0.690 | 0.157 |
| | C2: Retrained RF (Unscaled) | **0.975** | **0.914** | **0.949** | 0.036 | 0.087 |
| | C3: Retrained RF (Local Scaler) | 0.974 | 0.913 | 0.948 | 0.037 | 0.087 |
| | C4: Retrained RF (Canonical Scaler) | 0.975 | 0.914 | 0.949 | 0.036 | 0.087 |
| | C5: Retrained Logistic Regression | 0.884 | 0.681 | 0.824 | 0.093 | 0.370 |
| | C6: Retrained Decision Tree | 0.948 | 0.886 | 0.932 | 0.046 | 0.120 |
| **CIC-IDS2017** | C1: Frozen Synthetic RF (Zero-Shot) | 0.298 | 0.063 | 0.692 | 0.009 | 0.990 |
| | C2: Retrained RF (Unscaled) | **0.996** | **0.988** | **0.993** | 0.006 | 0.010 |
| | C3: Retrained RF (Local Scaler) | 0.996 | 0.988 | 0.993 | 0.006 | 0.010 |
| | C4: Retrained RF (Canonical Scaler) | 0.996 | 0.988 | 0.993 | 0.006 | 0.010 |
| | C5: Retrained Logistic Regression | 0.978 | 0.901 | 0.941 | 0.037 | 0.110 |
| | C6: Retrained Decision Tree | 0.988 | 0.982 | 0.989 | 0.009 | 0.017 |
| **UNSW-NB15** | C1: Frozen Synthetic RF (Zero-Shot) | 0.350 | 0.418 | 0.510 | 0.610 | 0.220 |
| | C2: Retrained RF (Unscaled) | **0.996** | **0.960** | **0.976** | 0.016 | 0.043 |
| | C3: Retrained RF (Local Scaler) | 0.996 | 0.959 | 0.975 | 0.017 | 0.043 |
| | C4: Retrained RF (Canonical Scaler) | 0.996 | 0.960 | 0.976 | 0.016 | 0.043 |
| | C5: Retrained Logistic Regression | 0.942 | 0.817 | 0.892 | 0.063 | 0.207 |
| | C6: Retrained Decision Tree | 0.972 | 0.942 | 0.965 | 0.023 | 0.063 |

---

## 3. Scientific Inferences & Causal-Free Findings

1. **Retraining Effect**: Performance improvements are **consistent with classifier retraining and domain-specific decision boundary estimation**, showing $\Delta \text{F1} > +0.47$ over frozen zero-shot deployment.
2. **Normalization Invariance**: Feature scaling (C2 unscaled vs C3 local vs C4 canonical) has negligible effect on tree-based architectures ($\Delta \text{F1} < 0.001$), demonstrating that tree splits are robust to monotonic transformations.
3. **Non-Linear Representation Value**: Retrained Random Forest consistently outperforms linear Logistic Regression across all domains ($\Delta \text{F1} = +0.087 \dots +0.233$), establishing that non-linear feature interactions within the 12D schema are essential for attack discrimination.
