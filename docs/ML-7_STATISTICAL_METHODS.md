# PhantomNet Phase ML-7: Statistical Methodology & Cross-Domain Validation

**Document Version:** 1.0.0  
**Phase:** ML-7 (Independent Validation, Robustness, Generalization & Publication-Readiness Forensics)  
**Effective Date:** 2026-10-02  
**Status:** NORMATIVE AUDIT DOCUMENTATION

---

## 1. Experimental Design across Evaluation Domains

Phase ML-7 evaluates models across $K = 13$ distinct evaluation domains:
- 1 Held-Out Canonical Benchmark Test Set ($N = 1,000$, drawn from `remediated_dataset_v3.csv`)
- 12 Independent Distribution Shift Scenarios ($N = 1,000$ each, parameterized with distinct distribution families)

Total evaluated flow samples: $13,000$ test observations.

---

## 2. Distribution Shift Quantification Metrics

For each scenario $\mathcal{D}_s$ against canonical reference $\mathcal{D}_{\text{ref}}$, feature-level shifts are quantified using:

### 2.1 1-Wasserstein Distance (Earth Mover's Distance)
Measures the minimal cost of transforming empirical cumulative distribution $u$ into $v$:

$$l_1(u, v) = \int_{-\infty}^{+\infty} |U(t) - V(t)| \, dt$$

Calculated via `scipy.stats.wasserstein_distance`.

### 2.2 Two-Sample Kolmogorov-Smirnov Test
Maximum vertical distance between empirical CDFs:

$$D_{\text{KS}} = \sup_x |F_{\text{ref}}(x) - F_{\text{scen}}(x)|$$

Evaluated with two-sided asymptotic $p$-values via `scipy.stats.ks_2samp`.

### 2.3 Standardized Mean Difference (Cohen's d for Features)
Magnitude of location shift relative to nominal variance:

$$\text{SMD}_j = \frac{\bar{x}_{j,\text{scen}} - \bar{x}_{j,\text{ref}}}{s_{j,\text{ref}}}$$

### 2.4 Population Stability Index (PSI)
Binned symmetric divergence over 10 deciles of the reference distribution:

$$\text{PSI} = \sum_{b=1}^{10} (p_b - q_b) \cdot \ln\left(\frac{p_b}{q_b}\right)$$

where $p_b = \frac{|\mathcal{D}_{\text{scen}} \cap I_b|}{|\mathcal{D}_{\text{scen}}|}$ and $q_b = \frac{|\mathcal{D}_{\text{ref}} \cap I_b|}{|\mathcal{D}_{\text{ref}}|}$.  
Interpretation: $\text{PSI} < 0.1$ (stable), $0.1 \le \text{PSI} < 0.25$ (moderate shift), $\text{PSI} \ge 0.25$ (significant shift).

---

## 3. Cross-Domain Comparative Hypothesis Testing

To determine whether the canonical hybrid ensemble exhibits statistically significant differences from standalone Random Forest, Decision Tree, Logistic Regression, and Isolation Forest across all 13 domains:

### 3.1 Paired Student's t-Test
For metric $M$ across the 13 domains, let $D_k = M_{\text{Ensemble}}(k) - M_{\text{Baseline}}(k)$:

$$\bar{D} = \frac{1}{K}\sum_{k=1}^K D_k, \quad t = \frac{\bar{D}}{s_D / \sqrt{K}}, \quad \text{df} = K - 1 = 12$$

### 3.2 Paired Wilcoxon Signed-Rank Test
Non-parametric test of median differences across domains:

$$W = \min(W^+, W^-), \quad p = P_{\text{Wilcoxon}}(W)$$

### 3.3 McNemar Exact Test (Within-Domain Categorical Discordance)
On the held-out canonical test set, discordance between Ensemble and RF binary decisions is tested via $2 \times 2$ contingency table with continuity correction:

$$\chi^2 = \frac{(|n_{01} - n_{10}| - 1)^2}{n_{01} + n_{10}}, \quad \text{df} = 1$$

where $n_{01}$ is events where Ensemble is correct and RF is incorrect, and $n_{10}$ is events where RF is correct and Ensemble is incorrect.

### 3.4 Multiple Testing Correction
All domain-level hypotheses are adjusted using the Holm-Bonferroni step-down procedure at $\alpha = 0.05$.
