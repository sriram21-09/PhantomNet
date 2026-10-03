# PhantomNet Master Audit: Phase ML-5 Completion Report
## Model Training, Statistical Validation & Performance Forensics

**Audit Phase:** ML-5
**Execution Date:** 2026-10-02
**Git Baseline:** `686e880a240a671390e68eb42f24ece21156c1f2`
**Branch:** `fix/full-codebase-audit-remediation`

---

### 1. Git Baseline

* **Git Commit SHA:** `686e880a240a671390e68eb42f24ece21156c1f2`
* **Prior Phases:** ML-1 (PASS), ML-2 (PASS), ML-3 (PASS), ML-4 (PASS)
* **Working Tree:** No architectural changes, ensemble weights, or thresholds were modified during ML-5.

---

### 2. ML-5 Scope

Complete forensic audit of:
1. Model inventory and quarantine enforcement
2. Random Forest pipeline configuration and behavior
3. Isolation Forest configuration, calibration, and directionality
4. Canonical ensemble formula verification
5. N=30 Monte Carlo performance reproduction
6. 95% confidence intervals with documented methodology
7. Paired statistical comparisons (Wilcoxon, t-test, Cohen's d)
8. McNemar discordance analysis
9. Multiple comparison correction (Holm-Bonferroni)
10. Class imbalance impact analysis
11. Threshold provenance audit
12. Probability calibration forensics (Brier score, ECE)
13. Controlled ablation analysis (RF alone / IF alone / Ensemble)
14. Feature importance (impurity + permutation)
15. Error analysis (FP/FN distributions)
16. Subgroup analysis (documented unavailability)
17. Reproducibility (Run A vs Run B, bitwise deterministic)
18. Publication claim audit

---

### 3. Model Inventory

| Model | Status | Quarantine Enforcement |
|:---|:---|:---|
| RF-canonical-12D | Active | — |
| IF-canonical-12D | Active | — |
| ENSEMBLE (0.85/0.15) | Active | — |
| RF-legacy-6D | Quarantined | ML-3, incompatible schema |
| DBSCAN-legacy | Quarantined | ML-3, not classification |
| Ensemble-0.70/0.30 | Quarantined | ML-2, EnsemblePredictor override |

Quarantined models **cannot** accidentally participate: `EnsemblePredictor.__init__` forcibly overrides obsolete weights, and static search (ML-4) confirmed zero active references.

---

### 4. RF Audit Summary

* Estimator: `RandomForestClassifier(n_estimators=100, max_depth=12, min_samples_split=5, min_samples_leaf=2)`
* Preprocessing: `StandardScaler` fit on X_train only
* Deterministic: Yes (n_jobs=1, bitwise identical across runs)
* Target leakage: None (verified ML-4)
* Probability: Vote fractions, not calibrated probabilities

---

### 5. IF Audit Summary

* Estimator: `IsolationForest(n_estimators=100, contamination=0.10)`
* Raw scoring: `−score_samples(X)` (higher = more anomalous) ✅
* Calibration: Per-run min-max on test set scores (**documented limitation**)
* S_IF ∈ [0, 1] ✅
* Directionality: malicious mean > benign mean ✅

---

### 6. Ensemble Audit

* Formula: `S = 0.85 × P_RF + 0.15 × S_IF` ✅
* Bounds: S ∈ [0, 1] for all 30 runs ✅
* Deterministic ✅
* Batch/single consistency ✅
* Weights unchanged ✅

---

### 7. Per-Run Metrics (N=30)

| Metric | RF (mean ± SD) | IF (mean ± SD) | Ensemble (mean ± SD) |
|:---|:---:|:---:|:---:|
| Accuracy | 0.9327 ± 0.0061 | 0.7332 ± 0.0109 | 0.9273 ± 0.0062 |
| Precision | 0.9711 ± 0.0108 | 0.6699 ± 0.0607 | 0.9782 ± 0.0095 |
| Recall | 0.7996 ± 0.0220 | 0.2204 ± 0.0273 | 0.7750 ± 0.0230 |
| F1 | 0.8768 ± 0.0126 | 0.3308 ± 0.0343 | 0.8646 ± 0.0132 |
| FPR | 0.0103 ± 0.0040 | 0.0470 ± 0.0114 | 0.0075 ± 0.0034 |
| FNR | 0.2004 ± 0.0220 | 0.7796 ± 0.0273 | 0.2250 ± 0.0230 |
| ROC-AUC | 0.9827 ± 0.0024 | 0.6465 ± 0.0204 | 0.9808 ± 0.0029 |
| PR-AUC | 0.9687 ± 0.0039 | 0.5058 ± 0.0278 | 0.9668 ± 0.0042 |

All 30 individual run results preserved in `experiments/results/ml5_per_run_metrics.json`.

---

### 8. Confidence Intervals (95%, t-dist, df=29)

| Metric | Ensemble 95% CI |
|:---|:---|
| Accuracy | [0.9249, 0.9296] |
| Precision | [0.9746, 0.9818] |
| Recall | [0.7664, 0.7836] |
| F1 | [0.8596, 0.8695] |
| FPR | [0.0062, 0.0088] |
| ROC-AUC | [0.9797, 0.9819] |

Methodology clearly distinguishes inter-run variability (SD), standard error (SE=SD/√N), and confidence interval (mean ± t·SE).

---

### 9. Paired Statistical Comparisons (Ensemble vs RF)

| Metric | Δ | Direction | Wilcoxon p | Cohen's d | Significant (α=0.05) |
|:---|:---:|:---|:---:|:---:|:---:|
| Accuracy | −0.0054 | Ens < RF | 2.07e-06 | −1.66 | **Yes** |
| Precision | +0.0071 | Ens > RF | 9.31e-09 | +1.36 | **Yes** |
| Recall | −0.0246 | Ens < RF | 1.66e-06 | −2.71 | **Yes** |
| F1 | −0.0122 | Ens < RF | 3.73e-09 | −1.90 | **Yes** |
| FPR | −0.0028 | Ens < RF | 3.39e-06 | −1.48 | **Yes** |
| FNR | +0.0246 | Ens > RF | 1.69e-06 | +2.71 | **Yes** |
| ROC-AUC | −0.0019 | Ens < RF | 1.86e-09 | −2.10 | **Yes** |

All effects are statistically significant with large effect sizes. The ensemble trades recall/accuracy for precision/FPR.

---

### 10. McNemar Analysis

| Cell | Count |
|:---|:---:|
| Both correct (a) | 927 |
| RF only correct (b) | 5 |
| Ensemble only correct (c) | 1 |
| Both incorrect (d) | 67 |

* **McNemar p = 0.2188** — NOT significant at α = 0.05
* Only 6 discordant pairs → insufficient power to detect difference
* **This is the genuine empirical table, not the historically fabricated [[0,30],[30,0]]**

---

### 11. Multiple Comparison Analysis

Holm-Bonferroni correction applied to family of 8 tests.
All 7 paired comparisons remain significant after correction.
McNemar remains non-significant (adjusted p = 0.2188).

---

### 12. Class Imbalance Analysis

* 70/30 distribution (3500 benign / 1500 malicious)
* Majority-class baseline: 70% accuracy
* Ensemble accuracy (92.7%) represents +22.7pp above baseline
* However, 22.5% FNR means ~1 in 4.4 attacks is missed
* Accuracy alone is insufficient for security applications; FPR and recall are critical

---

### 13. Threshold Provenance

All thresholds defined in `backend/ml/config/thresholds.py`:
* BLOCK ≥ 0.80, ALERT ≥ 0.50, ALLOW < 0.50
* CRITICAL ≥ 0.80, HIGH 0.60–0.79, MEDIUM 0.40–0.59, LOW < 0.40

**Limitation:** The specific validation experiment that selected 0.80/0.50 thresholds is not preserved as a reproducible script. Thresholds were NOT changed during ML-5.

---

### 14. Calibration Analysis

| Model | Brier Score | ECE | Interpretation |
|:---|:---:|:---:|:---|
| RF | 0.0485 | 0.131 | Reasonable but not perfectly calibrated |
| IF | 0.198 | N/A | Not a probability; min-max scaled |
| Ensemble | 0.0558 | 0.172 | Not a calibrated probability |

RF `predict_proba` outputs are vote fractions, not calibrated probabilities.
ECE of 0.131 reveals systematic miscalibration in mid-range bins.

---

### 15. Ablation Analysis

| Component | Accuracy | Precision | Recall | F1 | FPR |
|:---|:---:|:---:|:---:|:---:|:---:|
| RF Alone | 0.9327 | 0.9711 | 0.7996 | 0.8768 | 0.0103 |
| IF Alone | 0.7332 | 0.6699 | 0.2204 | 0.3308 | 0.0470 |
| Hybrid | 0.9273 | 0.9782 | 0.7750 | 0.8646 | 0.0075 |

IF alone is a weak classifier. Its ensemble contribution is a marginal precision gain (+0.7pp) at the cost of recall (−2.5pp).

---

### 16. Feature Importance Analysis

Impurity-based and permutation importance computed for canonical RF (seed=100).
All 12 features contribute positively; importances sum to 1.0.
**No causal claims are made from feature importance.**

---

### 17. Error Analysis

First run (seed=100): 5 FP, 67 FN on 1000 test observations.
FP ensemble scores cluster near 0.50 threshold.
FN scores distributed broadly below 0.50.
No systematic RF-vs-IF disagreement pattern identified.

---

### 18. Reproducibility

| Property | Result |
|:---|:---|
| Classification | **BITWISE_DETERMINISTIC** |
| n_jobs | 1 (forced for determinism) |
| Python | 3.11.9 |
| scikit-learn | 1.8.0 |
| NumPy | 2.3.5 |
| SciPy | 1.16.3 |
| Pandas | 2.3.3 |
| SHAP | 0.51.0 |

---

### 19. Publication Claim Audit

| Claim | Status | Evidence |
|:---|:---|:---|
| "High accuracy" | **PARTIALLY VERIFIED** | 92.7% accuracy on synthetic benchmark; cannot claim real-world generalization |
| "Low false-positive rate" | **VERIFIED** | FPR = 0.75% ± 0.34%, CI [0.62%, 0.88%] |
| "Statistically significant FPR reduction" | **VERIFIED** | Wilcoxon p = 3.39e-06, Cohen's d = −1.48 |
| "Statistically significant improvement" (overall) | **PARTIALLY VERIFIED** | FPR improvement is significant but accuracy, recall, F1, ROC-AUC are significantly *worse* |
| "Large effect" | **VERIFIED** | All |d| > 0.8 (large effects in both directions) |
| "Deterministic" | **VERIFIED** | Bitwise identical with n_jobs=1 |
| "Robust" | **UNSUPPORTED** | No robustness testing (adversarial, distribution shift) performed on synthetic benchmark |
| "Generalizable" | **UNSUPPORTED** | Synthetic benchmark only; no real-world data |
| "Explainable" | **PARTIALLY VERIFIED** | Feature importance computed; SHAP available but not independently audited |
| "Real-time" | **OUTDATED** | Latency benchmarks exist but not re-audited in ML-5 |
| "Calibrated probability" | **UNSUPPORTED** | ECE=0.131 (RF), ECE=0.172 (ensemble); not well-calibrated |

---

### 20. Files Changed & Created

#### Files Created:
* [`scripts/generate_ml5_statistics.py`](file:///c:/Users/srira/Project/PhantomNet/scripts/generate_ml5_statistics.py)
* [`tests/experiments/test_ml5_model_statistics.py`](file:///c:/Users/srira/Project/PhantomNet/tests/experiments/test_ml5_model_statistics.py)
* [`docs/ML-5_MODEL_STATISTICAL_FORENSICS.md`](file:///c:/Users/srira/Project/PhantomNet/docs/ML-5_MODEL_STATISTICAL_FORENSICS.md)
* [`docs/ML-5_STATISTICAL_METHODS.md`](file:///c:/Users/srira/Project/PhantomNet/docs/ML-5_STATISTICAL_METHODS.md)
* [`docs/ML-5_PERFORMANCE_PROTOCOL.md`](file:///c:/Users/srira/Project/PhantomNet/docs/ML-5_PERFORMANCE_PROTOCOL.md)
* [`experiments/results/ml5_model_inventory.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml5_model_inventory.json)
* [`experiments/results/ml5_per_run_metrics.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml5_per_run_metrics.json)
* [`experiments/results/ml5_statistical_tests.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml5_statistical_tests.json)
* [`experiments/results/ml5_confidence_intervals.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml5_confidence_intervals.json)
* [`experiments/results/ml5_ablation.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml5_ablation.json)
* [`experiments/results/ml5_reproducibility.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml5_reproducibility.json)
* [`experiments/results/ml5_error_analysis.json`](file:///c:/Users/srira/Project/PhantomNet/experiments/results/ml5_error_analysis.json)
* [`ML-5_COMPLETION_REPORT.md`](file:///c:/Users/srira/Project/PhantomNet/ML-5_COMPLETION_REPORT.md)

#### Files Modified:
* None. ML-5 does not modify existing code, weights, thresholds, or datasets.

---

### 21. Tests Executed

| Suite | Command | Passed | Failed | Skipped |
|:---|:---|:---:|:---:|:---:|
| ML-5 Statistics | `pytest tests/experiments/test_ml5_model_statistics.py -v` | **90** | 0 | 0 |
| All Experiments | `pytest tests/experiments -v` | **116** | 0 | 0 |
| ML Tests | `pytest tests/ml -v` | **70** | 0 | 0 |
| Backend/Integration/E2E | `pytest tests/backend tests/integration tests/e2e -v` | **254** | 0 | 0 |
| **Total** | | **530** | **0** | **0** |

---

### 22. Unresolved Issues

1. **Threshold provenance gap:** The specific validation experiment that selected the BLOCK=0.80 / ALERT=0.50 thresholds is not preserved as a reproducible script.
2. **IF calibration dependency:** Min-max bounds are computed from test set scores, creating a dependency between calibration and evaluation.
3. **Subgroup analysis unavailable:** No metadata columns exist for defensible subgroup performance evaluation.
4. **SHAP not independently re-audited:** SHAP integration exists but was not independently reproduced in ML-5.

---

### 23. Scientific Limitations

1. **Synthetic benchmark only.** All results are from `remediated_dataset_v3.csv`, a parametric synthetic dataset. Results MUST NOT be described as proof of real-world generalization.
2. **Class imbalance.** The 70/30 distribution inflates accuracy. FNR of 22.5% may be unacceptable for production security.
3. **Ensemble trade-off.** The hybrid ensemble achieves lower FPR but sacrifices recall, accuracy, F1, and ROC-AUC relative to RF alone. The claim of "improvement" applies ONLY to FPR/precision.
4. **Calibration.** Neither RF vote fractions nor ensemble composite scores are calibrated probabilities (ECE = 0.131 and 0.172 respectively).
5. **No adversarial or robustness testing.** No evaluation of performance under distribution shift, adversarial perturbation, or concept drift.
6. **McNemar non-significance.** With only 6 discordant pairs on the held-out split, there is insufficient power to detect a difference in overall error rate.

---

### 24. Final Status

> **ML-5 PASS WITH DOCUMENTED LIMITATIONS**

All numerical artifacts are generated by executable code. All 530 tests pass.
Reproducibility is bitwise deterministic. Statistical methods are documented
and assumption-checked. The evidence base is defensible within the documented
constraints:

- The synthetic benchmark establishes internal validity but NOT external validity.
- The ensemble's advantage is narrowly scoped to FPR reduction, not general performance improvement.
- Calibration is empirically evaluated and found to be imperfect.
- Non-significant McNemar result is reported honestly.
- Feature importance is descriptive, not causal.
- All limitations are documented rather than concealed.
