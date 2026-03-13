# Ensemble Evaluation & Weight Optimization (Week 11 Day 2)

## Goal
Achieve a 2-3% accuracy improvement by combining the supervised Random Forest target with the unsupervised Isolation Forest anomaly detector.

## Dataset
- **Validation Set**: 5000 labeled events (Historical Month 2 network and payload data).
- **RF Dimensions**: 12 behavioral vectors.
- **IF Dimensions**: 15 network payload features.

## Weight Grid Search Results
| RF Weight | IF Weight | Accuracy | F1 Score | Delta from RF Baseline |
|-----------|-----------|----------|----------|-----------------------|
| 1.0 | 0.0 | 0.9380 | 0.9125 | 0.00% |
| 0.9 | 0.1 | 0.9415 | 0.9160 | +0.35% |
| 0.8 | 0.2 | 0.9520 | 0.9230 | +1.40% |
| **0.7** | **0.3** | **0.9635** | **0.9410** | **+2.55%** |
| 0.6 | 0.4 | 0.9410 | 0.9110 | +0.30% |
| 0.5 | 0.5 | 0.9200 | 0.8890 | -1.80% |

## Conclusion & Rationale
The best performing weights are `W_rf = 0.7` and `W_if = 0.3`. 
This combination successfully bumps borderline-confidence RF predictions (e.g. low-and-slow attacks, zero-day behaviors that didn't trip standard thresholds) utilizing the powerful IF anomaly magnitude score. We achieved a robust **+2.55%** accuracy boost over relying solely on Random Forest.

**Status**: Target (`2-3%`) Met. Predictor class defaults updated.
