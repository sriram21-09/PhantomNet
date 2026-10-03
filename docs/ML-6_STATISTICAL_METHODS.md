# PhantomNet Phase ML-6: Statistical Methodology & Validation Protocol

**Document Version:** 1.0.0  
**Effective Date:** 2026-10-02  
**Audit Baseline:** Phase ML-5 Preserved Baselines  
**Methodology Identifier:** `ML6-STAT-VAL-v1`  
**Status:** NORMATIVE AUDIT DOCUMENTATION

---

## 1. Experimental Design & Seed Schedule

To ensure scientific defensibility, reproducibility, and rigorous quantification of variance, Phase ML-6 employs repeated stratified evaluation across $N = 30$ independent runs using the canonical seed sequence established in Phase ML-5:

$$\mathcal{S} = \{100, 101, 102, \dots, 129\}$$

### 1.1 Three-Way Data Partitioning Firewall
Every run $i \in \{1, \dots, 30\}$ with seed $s_i \in \mathcal{S}$ strictly enforces three disjoint partitions of the canonical 5,000-sample dataset (`data/remediated_dataset_v3.csv`):

1. **Training Partition (64% — 3,200 samples):**
   - Class distribution: 2,240 Benign (70%), 960 Malicious (30%).
   - Permitted operations: Fitting `StandardScaler`, training supervised `RandomForestClassifier`, training unsupervised `IsolationForest`.
2. **Development / Calibration Partition (16% — 800 samples):**
   - Class distribution: 560 Benign (70%), 240 Malicious (30%).
   - Permitted operations: Deriving empirical IF calibration bounds ($s_{\min}, s_{\max}$), fitting Platt (sigmoid) and Isotonic probability calibrators, evaluating threshold sweep grid for decision boundary selection ($T^*$).
3. **Final Held-Out Test Partition (20% — 1,000 samples):**
   - Class distribution: 700 Benign (70%), 300 Malicious (30%).
   - Permitted operations: **Single post-freeze evaluation only.**
   - Absolute prohibition: Zero test features or labels are accessed during scaler fitting, model training, calibration parameter estimation, or threshold selection.

---

## 2. Confidence Interval Methodology

### 2.1 Estimator & Degrees of Freedom
For any evaluation metric $M$ across the $N=30$ runs with sample values $\{m_1, m_2, \dots, m_{30}\}$:

$$\bar{m} = \frac{1}{N}\sum_{i=1}^N m_i, \quad s_m = \sqrt{\frac{1}{N-1}\sum_{i=1}^N (m_i - \bar{m})^2}, \quad \text{SE}(\bar{m}) = \frac{s_m}{\sqrt{N}}$$

Two-sided 95% confidence intervals are computed using the Student's $t$-distribution with $\nu = N - 1 = 29$ degrees of freedom:

$$\text{CI}_{95\%} = \left[ \bar{m} - t_{0.975, 29} \cdot \text{SE}(\bar{m}),\; \bar{m} + t_{0.975, 29} \cdot \text{SE}(\bar{m}) \right]$$

where $t_{0.975, 29} \approx 2.0452$.

### 2.2 Between-Run Variability vs. Within-Run Uncertainty
- **Between-Run Variability ($\sigma_{\text{between}}$):** Captures variation arising from stochastic dataset splitting and tree-growing randomness across seeds.
- **Within-Run Sampling Uncertainty ($\sigma_{\text{within}}$):** Evaluated at single test sets via binomial standard errors or bin-level confidence. Phase ML-6 reports between-run variability explicitly across all 30 seeds and does not conflate single-run sample size with repeated-trial variance.

---

## 3. Paired Comparative Hypothesis Testing

To assess the statistical impact of remediating test-set calibration leakage and optimizing decision thresholds, paired statistical comparisons are conducted across identical seeds ($s_i = 100 + i$):

### 3.1 Paired Differences
For models/protocols $A$ and $B$, the run-wise paired difference is:

$$D_i = M_A(s_i) - M_B(s_i), \quad i \in \{1, \dots, 30\}$$

Sample mean difference $\bar{D} = \frac{1}{N}\sum D_i$ and sample standard deviation $s_D = \sqrt{\frac{1}{N-1}\sum (D_i - \bar{D})^2}$.

### 3.2 Paired Student's t-Test
The null hypothesis $H_0: \mu_D = 0$ is tested against $H_1: \mu_D \neq 0$:

$$t = \frac{\bar{D}}{s_D / \sqrt{N}}, \quad p = 2 \cdot P(T_{29} > |t|)$$

### 3.3 Wilcoxon Signed-Rank Test
As a non-parametric confirmation that does not assume normal distribution of differences:

$$W = \min(W^+, W^-), \quad p = P_{\text{Wilcoxon}}(W)$$

### 3.4 Effect Size (Paired Cohen's d)
Standardized mean difference:

$$d = \frac{\bar{D}}{s_D}$$

Magnitude conventions: Small ($|d| \ge 0.2$), Medium ($|d| \ge 0.5$), Large ($|d| \ge 0.8$).

### 3.5 Multiple Comparisons Correction (Holm-Bonferroni)
For a family of $K$ simultaneous hypothesis tests ordered by ascending $p$-value ($p_{(1)} \le p_{(2)} \le \dots \le p_{(K)}$), hypothesis $j$ is rejected at family-wise error rate $\alpha = 0.05$ if:

$$p_{(j)} \le \frac{\alpha}{K - j + 1}$$

---

## 4. Calibration & Reliability Evaluation

### 4.1 Expected Calibration Error (ECE)
Scores $S \in [0.0, 1.0]$ are partitioned into $B = 10$ uniform bins $I_b = (\frac{b-1}{B}, \frac{b}{B}]$:

$$\text{ECE} = \sum_{b=1}^B \frac{|B_b|}{N} \left| \text{acc}(B_b) - \text{conf}(B_b) \right|$$

where $\text{acc}(B_b) = \frac{1}{|B_b|}\sum_{i \in B_b} y_i$ and $\text{conf}(B_b) = \frac{1}{|B_b|}\sum_{i \in B_b} S_i$.

### 4.2 Brier Score Loss
Strict proper scoring rule measuring mean squared error between score and true binary label:

$$\text{BS} = \frac{1}{N} \sum_{i=1}^N (S_i - y_i)^2$$
