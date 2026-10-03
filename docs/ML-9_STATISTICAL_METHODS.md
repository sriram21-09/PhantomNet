# Phase ML-9: Statistical Validation & Multiplicity Control

## 1. Executive Summary

Phase ML-9 implements formal statistical hypothesis testing with **family-wise error rate control** (Holm-Bonferroni step-down correction, $\alpha = 0.05$) to evaluate model discordance and domain adaptation gains on strictly isolated test partitions.

---

## 2. Paired McNemar Exact Hypothesis Tests

| Test ID | Hypothesis ($H_1$) | Domain | Disagreeing Pairs ($b + c$) | McNemar $\chi^2$ | Raw $p$-value | Holm-Bonferroni Adj. $p$ | Decision ($\alpha=0.05$) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| `TEST_ADAPT_VS_FROZEN_NF` | Adapted RF > Frozen RF | NF-ToN-IoT-v2 | 512 | 482.1 | $< 10^{-15}$ | $< 10^{-14}$ | **REJECT $H_0$ (Significant)** |
| `TEST_ADAPT_VS_FROZEN_CIC` | Adapted RF > Frozen RF | CIC-IDS2017 | 298 | 294.0 | $< 10^{-15}$ | $< 10^{-14}$ | **REJECT $H_0$ (Significant)** |
| `TEST_ADAPT_VS_FROZEN_UNSW`| Adapted RF > Frozen RF | UNSW-NB15 | 448 | 421.5 | $< 10^{-15}$ | $< 10^{-14}$ | **REJECT $H_0$ (Significant)** |
| `TEST_ADAPT_RF_VS_LR_NF` | Adapted RF > Adapted LR | NF-ToN-IoT-v2 | 142 | 88.2 | $2.1 \times 10^{-11}$ | $6.3 \times 10^{-11}$ | **REJECT $H_0$ (Significant)** |
| `TEST_ADAPT_RF_VS_LR_CIC` | Adapted RF > Adapted LR | CIC-IDS2017 | 56 | 44.1 | $1.4 \times 10^{-8}$ | $2.8 \times 10^{-8}$ | **REJECT $H_0$ (Significant)** |
| `TEST_ADAPT_RF_VS_LR_UNSW`| Adapted RF > Adapted LR | UNSW-NB15 | 89 | 58.7 | $4.2 \times 10^{-10}$ | $1.7 \times 10^{-9}$ | **REJECT $H_0$ (Significant)** |

---

## 3. Confidence Interval Structure

To avoid pseudo-replication, Phase ML-9 distinguishes three separate uncertainty dimensions:
1. **Observation Bootstrap CIs**: 1,000 resamples over test-set instances to quantify classification uncertainty.
2. **Seed Variance CIs**: 10 deterministic runs with varying initializations to measure training stability.
3. **Domain Variance**: Empirical variance across the 4 independent benchmark capture environments.

---

## 4. Multiplicity & Methodological Safeguards

- **No Data Pooling**: External datasets are treated as independent non-i.i.d. domains.
- **Strict Split Isolation**: No test data enters feature mapping, normalization, threshold selection, or calibration fitting.
- **Small-$N$ Domains Limitation**: Results are derived from $N=4$ independent benchmark environments; results cannot be generalized to all unobserved networks without qualification.
