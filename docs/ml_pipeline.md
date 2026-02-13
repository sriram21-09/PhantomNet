# PhantomNet ML Pipeline Documentation

**Last Updated:** 2026-02-13

## Overview
This document outlines the end-to-end Machine Learning pipeline for the PhantomNet Active Defense System. The pipeline includes data ingestion, preprocessing, model training, hyperparameter tuning, evaluation, and deployment.

## 1. Data Ingestion
- **Source:** HoneyPot logs (SSH, HTTP, FTP, SMTP) and network traffic captures.
- **Processing:** Raw logs are parsed and aggregated into a structured CSV format.
- **Location:** `data/training_dataset.csv`
- **Script:** `backend/ai_engine/data_ingestion.py` (or relevant script)

## 2. Preprocessing
- **Features:** 15 extracted features including `packet_length`, `threat_score`, `time_of_day_deviation`, etc.
- **Scaling:** Data is scaled using `StandardScaler`.
- **Handling Missing Values:** Missing values are imputed with 0.
- **Script:** Included in `ai-ml-dev/train_isolation_forest.py`.

## 3. Model Training
- **Model:** Isolation Forest (Unsupervised Anomaly Detection).
- **Script:** `ai-ml-dev/train_isolation_forest.py`
- **Process:** Loads data, scales it, fits the model, and saves artifacts.

## 4. Hyperparameter Tuning
- **Method:** Grid Search over `n_estimators`, `max_samples`, and `contamination`.
- **Script:** `ai-ml-dev/tune_isolation_forest.py`
- **Output:**
    - Best Model: `models/isolation_forest_optimized.pkl`
    - Results: `models/hyperparameter_results.json`
    - Report: `docs/hyperparameter_tuning.md`

## 5. Evaluation & Visualization
- **Metrics:** Precision, Recall, F1-Score, ROC-AUC.
- **Visualization Script:** `ai-ml-dev/generate_plots.py`
- **Outputs:**
    - Confusion Matrix: `reports/model_performance/confusion_matrix.png`
    - ROC Curve: `reports/model_performance/roc_curve.png`

## 6. Model Management
- **Versioning:** Tracked in `models/versions.json`.
- **API Endpoint:** `/api/v1/model/metrics` serves current model performance stats.
- **Artifacts:**
    - Model: `models/isolation_forest_optimized.pkl`
    - Scaler: `models/scaler_v1.pkl`
    - Config: `models/training_config.json`

## 7. Deployment
- The backend loads the optimized model and scaler on startup.
- Real-time traffic is passed through the scaler and then the model.
- Predictions (Normal/Anomaly) and Anomaly Scores are used for threat scoring and active defense responses.
