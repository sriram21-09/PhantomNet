# PhantomNet ML-5: Model Statistical Forensics

## 1. Purpose

This document presents the complete forensic audit of PhantomNet's supervised
and unsupervised model training, statistical evaluation, uncertainty estimation,
performance claims, and comparative analysis.

**Goal:** Establish whether the reported model-performance claims are
statistically valid, reproducible, appropriately compared, and supported by
executable evidence.

**Benchmark:** Synthetic dataset `data/remediated_dataset_v3.csv` (N=5,000,
12D, SHA-256 `390f653...bb363`).

---

## 2. Model Inventory

| Model ID | Type | Dims | Status | Producing Script |
|:---|:---|:---:|:---:|:---|
| RF-canonical-12D | RandomForestClassifier | 12 | **Active** | `experiments/reproduce_clean_paper.py` |
| IF-canonical-12D | IsolationForest | 12 | **Active** | `experiments/reproduce_clean_paper.py` |
| ENSEMBLE-canonical-hybrid | 0.85·RF + 0.15·IF | 12 | **Active** | `experiments/reproduce_clean_paper.py` |
| RF-legacy-6D | RandomForestClassifier | 6 | Quarantined (ML-3) | — |
| DBSCAN-legacy | DBSCAN | varies | Quarantined (ML-3) | — |
| Ensemble-0.70/0.30 | Linear combination | 12 | Quarantined (ML-2) | — |

Quarantine enforcement: `EnsemblePredictor.__init__` forcibly overrides
obsolete 0.70/0.30 weights to canonical 0.85/0.15. Unit tests verify this
(`test_obsolete_weight_rejection_and_override`).

---

## 3. Random Forest Forensic Audit

| Parameter | Value |
|:---|:---|
| n_estimators | 100 |
| max_depth | 12 |
| min_samples_split | 5 |
| min_samples_leaf | 2 |
| random_state | Per-run seed (100–129) |
| n_jobs | 1 (deterministic) |
| Preprocessing | StandardScaler, fit on X_train only |
| Class handling | Stratified split (70% benign / 30% malicious preserved) |
| Feature ordering | Canonical 12D-v1 tuple |
| Target leakage | None (verified ML-4) |
| Deterministic | Bitwise identical with n_jobs=1 |
| Probability output | Vote fractions (not calibrated probabilities) |

---

## 4. Isolation Forest Forensic Audit

| Parameter | Value |
|:---|:---|
| n_estimators | 100 |
| contamination | 0.10 |
| random_state | Per-run seed (100–129) |
| n_jobs | 1 (deterministic) |
| Raw scoring | `−score_samples(X)` (higher = more anomalous) |
| Calibration | Min-max: `S_IF = (raw − min) / (max − min + 1e-9)` |
| Range | S_IF ∈ [0, 1] — verified |
| Directionality | Mean S_IF for malicious > mean S_IF for benign — verified |

**Calibration limitation:** Min-max bounds are computed from the *test set*
within each run. This means the calibration is not independent of evaluation
data. This is an inherent limitation of the per-run normalization approach,
documented rather than silently corrected.

---

## 5. Ensemble Forensics

**Formula:** `S = 0.85 × P_RF + 0.15 × S_IF`

Verified:
- ✅ Numerical correctness (independent recomputation)
- ✅ Bounds: S ∈ [0, 1] for all 30 runs
- ✅ Determinism: bitwise identical across Run A / Run B
- ✅ RF dominant contribution (~85%)
- ✅ Batch vs single-event consistency
- ✅ Edge cases: S(0,0)=0, S(1,1)=1

---

## 6. N=30 Performance Summary

| Metric | Random Forest | Isolation Forest | Hybrid Ensemble |
|:---|:---:|:---:|:---:|
| Accuracy | 0.9327 ± 0.0061 | 0.7332 ± 0.0109 | **0.9273 ± 0.0062** |
| Precision | 0.9711 ± 0.0108 | 0.6699 ± 0.0607 | **0.9782 ± 0.0095** |
| Recall | 0.7996 ± 0.0220 | 0.2204 ± 0.0273 | 0.7750 ± 0.0230 |
| F1 | 0.8768 ± 0.0126 | 0.3308 ± 0.0343 | 0.8646 ± 0.0132 |
| Specificity | 0.9897 ± 0.0040 | 0.9530 ± 0.0114 | **0.9925 ± 0.0034** |
| FPR | 0.0103 ± 0.0040 | 0.0470 ± 0.0114 | **0.0075 ± 0.0034** |
| FNR | 0.2004 ± 0.0220 | 0.7796 ± 0.0273 | 0.2250 ± 0.0230 |
| ROC-AUC | 0.9827 ± 0.0024 | 0.6465 ± 0.0204 | 0.9808 ± 0.0029 |
| PR-AUC | 0.9687 ± 0.0039 | 0.5058 ± 0.0278 | 0.9668 ± 0.0042 |

---

## 7. Confidence Intervals (95%, t-distribution, df=29)

| Metric | RF 95% CI | Ensemble 95% CI |
|:---|:---|:---|
| Accuracy | [0.9304, 0.9350] | [0.9249, 0.9296] |
| Precision | [0.9670, 0.9751] | [0.9746, 0.9818] |
| Recall | [0.7913, 0.8078] | [0.7664, 0.7836] |
| F1 | [0.8721, 0.8815] | [0.8596, 0.8695] |
| FPR | [0.0088, 0.0118] | [0.0062, 0.0088] |

**Distinction:** These CIs quantify inter-run variability (across 30 Monte
Carlo splits), NOT per-observation uncertainty within a single test set.

---

## 8. Paired Statistical Comparisons (Ensemble vs RF)

| Metric | Mean Δ | Direction | Wilcoxon p | Cohen's d | Interpretation |
|:---|:---:|:---|:---:|:---:|:---|
| Accuracy | −0.0054 | Ens < RF | 2.07e-06 | −1.66 | Large negative |
| Precision | +0.0071 | Ens > RF | 9.31e-09 | +1.36 | Large positive |
| Recall | −0.0246 | Ens < RF | 1.66e-06 | −2.71 | Large negative |
| F1 | −0.0122 | Ens < RF | 3.73e-09 | −1.90 | Large negative |
| FPR | −0.0028 | Ens < RF | 3.39e-06 | −1.48 | Large (favorable) |
| FNR | +0.0246 | Ens > RF | 1.69e-06 | +2.71 | Large (unfavorable) |
| ROC-AUC | −0.0019 | Ens < RF | 1.86e-09 | −2.10 | Large negative |

**Key finding:** The ensemble provides a statistically significant FPR
reduction (−0.28 percentage points, d=−1.48) at the cost of statistically
significant recall loss (−2.46 percentage points, d=−2.71). The trade-off is
real and large.

---

## 9. McNemar Analysis

| Cell | Count |
|:---|:---:|
| Both correct (a) | 927 |
| RF only correct (b) | 5 |
| Ensemble only correct (c) | 1 |
| Both incorrect (d) | 67 |

- **McNemar exact p-value:** 0.2188 (NOT significant at α=0.05)
- **Interpretation:** With only 6 discordant pairs (b+c=6), there is
  insufficient evidence to conclude the models differ in overall error rate
  on this single held-out split.

---

## 10. Multiple Comparison Correction (Holm-Bonferroni)

8 tests in family. All 7 paired metric comparisons remain significant after
correction (adjusted p < 0.05). McNemar remains non-significant (adjusted
p = 0.2188).

---

## 11. Class Imbalance Analysis

Distribution: 3500 benign (70%) / 1500 malicious (30%).

Accuracy alone is **potentially misleading** — a naive "always predict benign"
classifier achieves 70% accuracy. The ensemble's 92.7% accuracy represents
a +22.7pp improvement over the majority-class baseline. However, the 22.5%
false negative rate means approximately 1 in 4.4 malicious events goes
undetected. For security applications, recall and FNR deserve more weight
than accuracy.

---

## 12. Threshold Provenance

| Threshold | Value | Source |
|:---|:---:|:---|
| BLOCK | ≥ 0.80 | `backend/ml/config/thresholds.py` |
| ALERT | ≥ 0.50 | `backend/ml/config/thresholds.py` |
| ALLOW | < 0.50 | `backend/ml/config/thresholds.py` |
| CRITICAL | ≥ 0.80 | `backend/ml/config/thresholds.py` |
| HIGH | 0.60–0.79 | `backend/ml/config/thresholds.py` |
| MEDIUM | 0.40–0.59 | `backend/ml/config/thresholds.py` |
| LOW | < 0.40 | `backend/ml/config/thresholds.py` |

**Provenance limitation:** These thresholds are defined as constants in the
code. The commit history and `REMEDIATION_REPORT.md` reference "grid search on
held-out validation data" but the specific validation experiment that selected
0.80/0.50 is not preserved as a reproducible script. This is a documented
limitation. The thresholds were NOT changed during ML-5.

---

## 13. Calibration Analysis

| Model | Brier Score | ECE |
|:---|:---:|:---:|
| Random Forest | 0.0485 | 0.131 |
| Isolation Forest | 0.198 | N/A |
| Hybrid Ensemble | 0.0558 | 0.172 |

- RF Brier score (0.0485) indicates reasonable overall calibration, but
  ECE=0.131 reveals systematic miscalibration in mid-range bins.
- RF `predict_proba` outputs are vote fractions, NOT calibrated probabilities.
- IF scores are min-max normalized anomaly scores, NOT probabilities.
- The ensemble composite is NOT a calibrated probability.

---

## 14. Ablation Summary

| Component | Accuracy | Precision | Recall | F1 | FPR |
|:---|:---:|:---:|:---:|:---:|:---:|
| RF Alone | 0.9327 | 0.9711 | 0.7996 | 0.8768 | 0.0103 |
| IF Alone | 0.7332 | 0.6699 | 0.2204 | 0.3308 | 0.0470 |
| Hybrid | 0.9273 | 0.9782 | 0.7750 | 0.8646 | 0.0075 |

The IF component alone is a weak classifier. Its contribution to the
ensemble is marginal precision improvement (+0.7pp) at the cost of recall
(−2.5pp). The 0.15 IF weight acts primarily as a conservative regularizer.

---

## 15. Feature Importance

Top features by impurity-based importance (RF, seed=100):

| Feature | Gini Importance | Permutation Importance |
|:---|:---:|:---:|
| inter_arrival_std | Highest | Highest |
| packet_size_variance | High | High |
| payload_entropy | High | Medium |
| event_rate_1m | Medium | Medium |

> **Warning:** Feature importance measures predictive utility, NOT causal effect.

---

## 16. Error Analysis (First Run, seed=100)

- False Positives: 5 (benign events scored ≥ 0.50)
- False Negatives: 67 (malicious events scored < 0.50)
- FP ensemble scores clustered near the 0.50 threshold
- FN ensemble scores distributed broadly below 0.50

No systematic RF-vs-IF disagreement pattern identified in false positives.

---

## 17. Subgroup Analysis

**Unavailable.** The canonical dataset contains only 12 continuous features
and a binary label. No traffic category, protocol type, or attack-type
metadata exists for defensible subgroup analysis. Manufacturing categories
from continuous features would be post-hoc and scientifically unsound.

---

## 18. Reproducibility

| Property | Result |
|:---|:---|
| Classification | **BITWISE_DETERMINISTIC** |
| Seeds compared | 100, 101, 102 |
| Accuracy diff | 0.0 (all seeds) |
| F1 diff | 0.0 (all seeds) |
| ROC-AUC diff | 0.0 (all seeds) |
| n_jobs | 1 (forced for determinism) |
| Python | 3.11.9 |
| scikit-learn | 1.8.0 |
| NumPy | 2.3.5 |
| SciPy | 1.16.3 |
