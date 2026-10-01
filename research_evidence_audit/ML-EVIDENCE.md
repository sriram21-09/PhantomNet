# PhantomNet Machine Learning Evidence

## 1. Implemented Models & Parameters
- **Random Forest Classifier (Primary):**
  - Checkpoint: ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl (500 estimators, max_depth=20, 12 features).
  - Retrain script: xperiments/reproduce_paper.py (100 estimators, max_depth=15).
  - Task: Binary attack classification (Benign vs Malicious).
- **Isolation Forest (Anomaly Detector):**
  - Checkpoint: ml_models/registry/IsolationForest_Anomaly_v1.0.0.pkl (100 estimators, contamination=0.10).
  - Task: Unsupervised outlier scoring.
- **Hybrid RF+IF Ensemble:**
  - Logic: Composite Score = 0.7 * RF_Prob + 0.3 * NormScore(IF).
  - Alert Threshold: Composite Score >= 0.5.
- **DBSCAN Campaign Clusterer:**
  - Logic: Spatial-temporal clustering of threat events. Parameters: ps=0.5, min_samples=3.
  - Finding: Fails when features are unscaled; achieves ARI=0.2116 and Silhouette=0.9895 when StandardScaler is prepended.
- **LSTM Sequence Predictor:**
  - Status: Placeholder stub in ackend/ml/lstm_attack_predictor.py; no trained weights or neural network graphs exist.

## 2. Quantitative Evaluation Table (labeled_events_v2_enhanced.csv)

| Model Architecture | Accuracy | Balanced Acc | Precision | Recall | F1 Score | ROC-AUC | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|
| Standalone Random Forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Standalone Isolation Forest | 0.8770 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.9759 | 0.0000 |
| Hybrid RF+IF Ensemble (0.7/0.3) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| Original Pickled Checkpoint | 0.6976 | 0.5000 | 0.0000 | 0.0000 | 0.0000 | 0.5000 | 0.0000 |

## 3. Single-Feature Separability Breakdown
- vg_command_length: Benign = 24.0 (zero variance); Malicious != 24.0 (Separation Acc: 100.0%)
- payload_entropy: Benign = 3.7317 (zero variance); Malicious != 3.7317 (Separation Acc: 100.0%)
- payload_to_cmd_ratio: Benign = 1.0000 (zero variance); Malicious != 1.0000 (Separation Acc: 100.0%)
- Conclusion: The 100% metrics across all supervised models are direct mathematical consequences of zero benign feature variance in the generation script.
