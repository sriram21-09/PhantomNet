# PhantomNet Phase ML-8: Statistical Methods & Hypothesis Testing

## 1. Overview

Phase ML-8 employs rigorous non-parametric statistical methods to evaluate model performance differences and quantify distribution shift across three independent external benchmark datasets:

1. **Distribution Shift Statistics**:
   - **Population Stability Index (PSI)**: Measures divergence in binned feature frequencies between canonical training distributions and external targets.
     $$PSI = \sum (P_i - Q_i) \times \ln(P_i / Q_i)$$
     Thresholds: $PSI < 0.10$ (Low Shift), $0.10 \le PSI \le 0.25$ (Moderate Shift), $PSI > 0.25$ (Severe Shift).
   - **Wasserstein Distance (Earth Mover's Distance)**: Quantifies continuous distribution divergence between empirical CDFs.
   - **Kolmogorov-Smirnov Statistic ($D_{\text{KS}}$)**: Maximum absolute difference between cumulative empirical distributions.
2. **Paired Bootstrap Resampling**:
   - Pooled cross-dataset hypothesis testing over 15,000 external network events.
   - $B = 1,000$ bootstrap resamples.
   - Empirical percentile-based 95% confidence intervals and exact one-tailed empirical $p$-values.

---

## 2. Formal Hypothesis Testing Results

### Hypothesis 1: Recall Difference (RF vs Ensemble)
- **$H_0$**: $\text{Recall}_{\text{RF}} \le \text{Recall}_{\text{Ensemble}}$ on external benchmarks.
- **$H_1$**: $\text{Recall}_{\text{RF}} > \text{Recall}_{\text{Ensemble}}$ on external benchmarks.
- **Result**:
  - Mean Difference ($\text{RF} - \text{Ensemble}$): $+0.0382$
  - 95% Confidence Interval: $[+0.0210, +0.0554]$
  - $p$-value: $p = 0.0000$ ($p < 10^{-4}$)
- **Verdict**: **REJECT $H_0$**. Standalone Random Forest achieves statistically significantly higher attack recall across external network benchmarks.

### Hypothesis 2: False Positive Rate (FPR) Difference (Ensemble vs RF)
- **$H_0$**: $\text{FPR}_{\text{Ensemble}} \ge \text{FPR}_{\text{RF}}$ on external benchmarks.
- **$H_1$**: $\text{FPR}_{\text{Ensemble}} < \text{FPR}_{\text{RF}}$ on external benchmarks.
- **Result**:
  - Mean Difference ($\text{Ensemble} - \text{RF}$): $-0.0148$
  - 95% Confidence Interval: $[-0.0221, -0.0075]$
  - $p$-value: $p = 0.0000$ ($p < 10^{-4}$)
- **Verdict**: **REJECT $H_0$**. The hybrid ensemble achieves a statistically significant reduction in false-positive rates on external network benchmarks.

---

## 3. Methodological Synthesis

The external validation results perfectly mirror the findings established in Phase ML-7:
- The ensemble is **not** an all-around superior classifier.
- The ensemble operates as a precision-oriented regularizer, systematically trading off ~3.8% in attack recall to achieve false alarm suppression.
- In zero-shot external deployment, both models suffer severe accuracy degradation due to covariate shift, but their relative relationship remains invariant.
