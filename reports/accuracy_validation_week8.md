# Accuracy Validation Report - Week 8

**Date**: 2026-02-12
**Model Ver**: Isolation Forest v1
**Dataset**: 200 Synthetic Events (Benign: 131, Malicious: 69)

## 1. Executive Summary
The anomaly detection model was validated against a ground truth dataset of 200 events.
- **Overall Accuracy**: **85.00%**
- **Threat Detection Rate (Recall)**: **100.00%** (All threats caught)
- **False Alarm Rate**: **~23%** (30 False Positives out of 131 Benign events)

> [!WARNING]
> The model is currently **too aggressive**. While it catches all attacks, it generates significantly high false positives, which may cause alert fatigue for SOC analysts.

## 2. Detailed Metrics

### Confusion Matrix
| | Predicted Benign | Predicted Malicious |
| :--- | :---: | :---: |
| **Actual Benign** | **101** (TN) | **30** (FP) |
| **Actual Malicious** | **0** (FN) | **69** (TP) |

### Classification Report
| Class | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: |
| **BENIGN** | 1.00 | 0.77 | 0.87 | 131 |
| **MALICIOUS** | 0.70 | 1.00 | 0.82 | 69 |
| **Accuracy** | | | **0.85** | 200 |

## 3. Performance Analysis
- **Strengths**: Perfect Recall. The features `threat_score`, `attack_type_frequency`, and `packet_size_variance` are effectively separating attack vectors from normal traffic.
- **Weaknesses**: High False Positive Rate. The `drift` in normal traffic (e.g., occasional large packets or slight bursts) is pushing benign events across the decision boundary.

## 4. Remediation Plan
To improve Precision without sacrificing Recall:
1. **Tuning**: Lower `contamination` parameter in `AnomalyDetector` from `0.1` to `auto` or `0.05`.
2. **Training Data**: Expand the "normal" training baseline to include more high-variance but benign traffic (e.g., large file transfers, video streams).
3. **Post-Processing**: Implement a secondary filter where low-confidence anomalies (scores near -0.01) are downgraded to "Warnings" instead of "Critical Alerts".

## 5. Metadata
- **Script**: `scripts/validate_model.py`
- **Data**: `data/ground_truth.csv`
- **Artifacts**: `data/predictions.csv`, `docs/false_positive_analysis.md`
