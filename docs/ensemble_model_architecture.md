# Ensemble Model Architecture

**Objective**: Improve detection accuracy by 2-3% by combining supervised and unsupervised machine learning models.

## Concept

The PhantomNet ensemble model integrates:
1. **Supervised Learning**: Random Forest Classifier (`attack_classifier_v2_optimized.pkl`). Captures known patterns of attacks, trained on labeled datasets.
2. **Unsupervised Learning**: Isolation Forest (`models/isolation_forest_v1.pkl` or similar). Detects novel anomalies and zero-day deviations that the Random Forest might miss.

## Weighting Strategy

The ensemble uses a weighted soft-voting / thresholding mechanism.

1. **Random Forest (RF)** outputs a probability of maliciousness: `P_rf(Malicious)`.
2. **Isolation Forest (IF)** outputs an anomaly score: `S_if` (normalized to [0, 1] where 1 is highly anomalous).

**Final Score Calculation**:
`Ensemble_Score = (W_rf * P_rf(Malicious)) + (W_if * S_if)`

Where `W_rf + W_if = 1.0`.

**Decision Threshold**:
If `Ensemble_Score >= 0.5`, the event is classified as `Malicious` (1), otherwise `Benign` (0).

## Initial Weights
- **W_rf = 0.7**: High confidence in known attack signatures.
- **W_if = 0.3**: Allows the anomaly detector to push borderline cases over the threshold, acting as an amplifier for novel threats.

These weights will be experimentally tuned to maximize the F1-score and hit the 2-3% accuracy improvement target on the validation set.

## Implementation Details
- **Module**: `ml/models/ensemble_predictor.py`
- **Class**: `EnsemblePredictor`
  - Loads both models upon initialization.
  - Implements `predict(features)` for single inference.
  - Implements `predict_batch(features_df)` for high-throughput vectorized operations.
