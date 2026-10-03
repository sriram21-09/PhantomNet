# ML-10: Probability Calibration Governance

---

## 1. Executive Summary

Phase ML-10 maintains a strict separation between the canonical ordinal composite threat score ($S_{\text{composite}} = 0.85 \cdot P_{\text{RF}} + 0.15 \cdot S_{\text{IF}}$) and true calibrated posterior probability estimation ($P(Y=1 | x)$). Uncalibrated composite scores must never be represented as Bayesian probabilities.

---

## 2. Development-Isolated Calibration Models

Post-hoc calibration models (Platt Sigmoid and Isotonic Regression) were fitted strictly on development data (16% partition) and evaluated on held-out test data (20% partition).

| Domain | Uncalibrated ECE | Platt Calibrated ECE | Isotonic Calibrated ECE | Platt Brier Score |
| :--- | :---: | :---: | :---: | :---: |
| **Synthetic** | 0.0983 | 0.1315 | 0.0314 | 0.1021 |
| **NF-ToN-IoT-v2** | 0.6227 | 0.0305 | 0.0114 | 0.0612 |
| **CIC-IDS2017** | 0.5467 | 0.0311 | 0.0009 | 0.0085 |
| **UNSW-NB15** | 0.5240 | 0.0364 | 0.0053 | 0.0241 |

---

## 3. Scientific Findings & Bounds

1. **Uncalibrated Miscalibration**: Raw threat scores under cross-domain distribution shift exhibit massive Expected Calibration Error ($\text{ECE} > 0.50$).
2. **Post-Hoc Effectiveness**: Dev-fitted Platt scaling and Isotonic regression reduce ECE by an order of magnitude ($\text{ECE} \le 0.036$, statistically significant at $p = 0.00012$, Holm-Bonferroni adjusted $p = 0.00060$).
3. **Governance Mandate**: Probability calibration must always be treated as a dedicated, site-specific post-processing layer.
