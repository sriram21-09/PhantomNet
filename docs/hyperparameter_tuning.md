# Isolation Forest Hyperparameter Tuning Report

**Date:** 2026-02-13
**Author:** AI Assistant

## Overview
This document details the hyperparameter tuning process for the Isolation Forest model used in the PhantomNet project. The goal was to optimize the model for F1-score to balance precision and recall in anomaly detection.

## Methodology
We used a grid search approach to explore combinations of the following hyperparameters:
- **`n_estimators`**: Number of base estimators in the ensemble. Values tested: `[50, 100, 200]`
- **`max_samples`**: The number of samples to draw from X to train each base estimator. Values tested: `['auto', 0.5, 0.8]`
- **`contamination`**: The amount of contamination of the data set, i.e., the proportion of outliers in the data set. Values tested: `['auto', 0.01, 0.05, 0.1, 0.2]`

Metric for selection: **F1-Score**

## Results

### Best Model Performance
The best performing model achieved the following metrics:
- **F1 Score**: 0.5409
- **Precision**: 0.8776
- **Recall**: 0.3909

### Optimized Hyperparameters
- **`n_estimators`**: 50
- **`max_samples`**: 0.5
- **`contamination`**: 'auto'

### finding Summary
- **Contamination**: The `auto` setting consistently outperformed fixed low contamination rates (0.01, 0.05) which often resulted in 0.0 F1 scores (failing to detect anomalies). Higher fixed contamination (0.2) improved recall but significantly hurt precision.
- **Max Samples**: Limiting samples to `0.5` (50% of data) generally performed better than `auto` (all samples) or `0.8`, likely preventing overfitting to the specific training noise.
- **N Estimators**: 50 estimators provided the highest F1 score, though differences between 50, 100, and 200 were less drastic than other parameters.

## Artifacts
- **Optimized Model**: `models/isolation_forest_optimized.pkl`
- **Full Results Log**: `models/hyperparameter_results.json`

## Conclusion
The optimized parameters suggest a model that is relatively conservative (high precision) but effective at capturing a core set of anomalies (moderate recall). The `contamination='auto'` setting is crucial for this dataset structure.
