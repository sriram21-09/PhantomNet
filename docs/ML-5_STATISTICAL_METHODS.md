# PhantomNet ML-5: Statistical Methods Specification

## 1. Overview

This document specifies every statistical method used in ML-5, including
hypotheses, assumptions, sample sizes, and interpretation guidelines.

---

## 2. Experimental Design

- **N=30 Monte Carlo Repeated Stratified Splits** (80/20)
- **Seeds:** 100–129 (deterministic schedule)
- **Stratification:** Preserves 70/30 class ratio in each split
- **Preprocessing:** StandardScaler fit exclusively on X_train per split

---

## 3. Paired Wilcoxon Signed-Rank Test

| Property | Value |
|:---|:---|
| Purpose | Compare Ensemble vs RF on paired runs |
| H₀ | Median difference in metric = 0 |
| H₁ | Median difference ≠ 0 (two-sided) |
| Structure | Paired — same test splits |
| N | 30 paired observations |
| Assumptions | Symmetric difference distribution |
| Rationale | Non-parametric, does not require normality |

---

## 4. Paired Student's t-Test

| Property | Value |
|:---|:---|
| Purpose | Complement to Wilcoxon for mean differences |
| H₀ | Mean difference = 0 |
| H₁ | Mean difference ≠ 0 (two-sided) |
| Structure | Paired |
| N | 30 |
| Assumptions | Differences approximately normal (CLT at N=30) |
| Rationale | Provides CI for mean difference and Cohen's d |

---

## 5. Cohen's d (Paired)

$$d = \frac{\bar{X}_{diff}}{s_{diff}}$$

| d | Interpretation |
|:---|:---|
| < 0.2 | Negligible |
| 0.2–0.5 | Small |
| 0.5–0.8 | Medium |
| ≥ 0.8 | Large |

---

## 6. McNemar's Exact Test

| Property | Value |
|:---|:---|
| Purpose | Compare model error rates on same observations |
| H₀ | P(RF only correct) = P(Ensemble only correct) |
| H₁ | P(b) ≠ P(c) (two-sided) |
| Method | Exact binomial test on min(b,c) given b+c |
| N | 1000 test observations (seed=100) |
| Assumptions | None (exact test) |

---

## 7. Confidence Intervals

**Method:** Student's t-distribution, df=N−1=29, α=0.05

$$CI = \bar{x} \pm t_{0.975, 29} \cdot \frac{s}{\sqrt{N}}$$

**Scope:** Quantifies inter-run variability across 30 Monte Carlo splits.
Does NOT quantify per-observation uncertainty within a single test set.

---

## 8. Multiple Comparison Correction

**Method:** Holm-Bonferroni step-down procedure

**Family:** 7 paired metric comparisons + 1 McNemar = 8 tests

**Procedure:**
1. Sort raw p-values ascending
2. For rank k (1-indexed): adjusted p = raw_p × (m − k + 1)
3. Enforce monotonicity

---

## 9. Calibration Diagnostics

| Metric | Formula | Interpretation |
|:---|:---|:---|
| Brier Score | $\frac{1}{N}\sum(p_i - y_i)^2$ | Lower is better; 0 = perfect |
| ECE | Mean |fraction_positive − mean_predicted| across bins | Lower is better |
| Calibration Curve | Binned fraction of positives vs predicted probability | Diagonal = perfect calibration |

---

## 10. Feature Importance

| Method | What it measures | Limitation |
|:---|:---|:---|
| Gini Impurity | Mean decrease in impurity from splits | Biased toward high-cardinality features |
| Permutation | Accuracy drop when feature shuffled | Measures predictive utility, NOT causality |

---

## 11. Effect Size Confidence Intervals

For each paired comparison, the 95% CI for the mean difference is:

$$CI_{\Delta} = \bar{\Delta} \pm t_{0.975, 29} \cdot \frac{s_\Delta}{\sqrt{30}}$$

This interval quantifies the plausible range of the true average performance
difference between models.
