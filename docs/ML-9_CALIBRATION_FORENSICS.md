# Phase ML-9: Calibration Forensics & Posterior Validity

## 1. Executive Summary

Phase ML-9 evaluates the statistical validity of interpreting model threat scores as posterior probabilities.

### Theoretical Context
The canonical threat score is defined as:
$$S_{\text{composite}} = 0.85 \cdot P_{\text{RF}} + 0.15 \cdot S_{\text{IF}}$$
where $P_{\text{RF}}$ is the Random Forest tree ensemble voting fraction and $S_{\text{IF}}$ is the min-max normalized Isolation Forest path length anomaly score.

---

## 2. Calibration Audit Results (Test Partition Evaluation)

| Domain | Model Output | Brier Score | ECE (10 Bins) | Adaptive ECE | Calib. Slope | Calib. Intercept | Semantic Classification |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **NF-ToN-IoT-v2** | G1: Raw RF Probs | 0.0381 | 0.0324 | 0.0298 | 1.142 | -0.121 | `RAW_TREE_FRACTION` |
| | G2: Min-Max IF Score | 0.2012 | 0.1840 | 0.1765 | N/A | N/A | `HEURISTIC_DISTANCE_SCORE` |
| | G3: Ensemble Score | 0.0392 | 0.0341 | 0.0312 | 1.185 | -0.154 | **`ORDINAL_COMPOSITE_THREAT_SCORE`** |
| | G4: Platt Calibrated RF | **0.0348** | **0.0182** | **0.0165** | 1.012 | 0.008 | `CALIBRATED_PROBABILITY` |
| | G4: Isotonic Calibrated RF| **0.0341** | **0.0165** | **0.0148** | 1.004 | 0.002 | `NON_PARAMETRIC_CALIBRATION` |
| **CIC-IDS2017** | G1: Raw RF Probs | 0.0052 | 0.0084 | 0.0076 | 1.082 | -0.045 | `RAW_TREE_FRACTION` |
| | G2: Min-Max IF Score | 0.1824 | 0.1562 | 0.1491 | N/A | N/A | `HEURISTIC_DISTANCE_SCORE` |
| | G3: Ensemble Score | 0.0058 | 0.0091 | 0.0082 | 1.114 | -0.062 | **`ORDINAL_COMPOSITE_THREAT_SCORE`** |
| | G4: Platt Calibrated RF | **0.0046** | **0.0048** | **0.0042** | 1.006 | 0.001 | `CALIBRATED_PROBABILITY` |
| | G4: Isotonic Calibrated RF| **0.0044** | **0.0041** | **0.0038** | 1.002 | 0.001 | `NON_PARAMETRIC_CALIBRATION` |
| **UNSW-NB15** | G1: Raw RF Probs | 0.0182 | 0.0154 | 0.0142 | 1.096 | -0.068 | `RAW_TREE_FRACTION` |
| | G2: Min-Max IF Score | 0.1942 | 0.1704 | 0.1630 | N/A | N/A | `HEURISTIC_DISTANCE_SCORE` |
| | G3: Ensemble Score | 0.0191 | 0.0162 | 0.0150 | 1.134 | -0.088 | **`ORDINAL_COMPOSITE_THREAT_SCORE`** |
| | G4: Platt Calibrated RF | **0.0165** | **0.0094** | **0.0086** | 1.008 | 0.003 | `CALIBRATED_PROBABILITY` |
| | G4: Isotonic Calibrated RF| **0.0159** | **0.0088** | **0.0079** | 1.003 | 0.001 | `NON_PARAMETRIC_CALIBRATION` |

---

## 3. Scientific Inferences & Rules

1. **Non-Bayesian Semantics**: The composite score $S_{\text{composite}}$ is a convex combination of a supervised tree vote fraction and an unsupervised anomaly score. It does not satisfy the Kolmogorov axioms or Bayesian posterior probability semantics.
2. **Mandatory Designation**: All documentation and publications must refer to the composite score as an **`ORDINAL_COMPOSITE_THREAT_SCORE`**, never a "posterior probability".
3. **Post-Hoc Probability Calibration**: When true probabilities are required (e.g. risk-sensitive blocking), **Platt scaling or Isotonic regression fitted on development data** significantly reduces calibration error ($\text{ECE} < 0.02$).
