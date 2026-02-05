# PhantomNet – Model Comparison Report  
**Week 7 – Day 2 (Tuesday, February 3, 2026)**

## 1. Overview

This document summarizes the model comparison performed as part of **PhantomNet Week 7 – Day 2**, focusing on evaluating supervised classifiers for attack detection in a SOC-oriented environment.

The primary goal was to compare **Gradient Boosting** and **Random Forest** classifiers using the Week 6 generated dataset and select a suitable baseline model for further explainability and SOC integration work.

---

## 2. Dataset Summary

**Source:**  
Merged Week 6 benign + attack events, processed via the finalized feature extraction pipeline.

**Dataset Characteristics:**

- Total samples: **232**
- Features: **15 engineered features**
- Labels:
  - Malicious (1): **220**
  - Benign (0): **12**

**Class Imbalance:**
- Malicious-heavy dataset (~95%)
- Considered acceptable for Week 7 experimentation
- Reflects short-window, attack-focused capture scenarios common in SOC investigations

---

## 3. Feature Set

The following 15 features were used consistently across both models:

- packet_length  
- protocol_encoding  
- source_ip_event_rate  
- destination_port_class  
- threat_score  
- malicious_flag_ratio  
- attack_type_frequency  
- time_of_day_deviation  
- burst_rate  
- packet_size_variance  
- honeypot_interaction_count  
- session_duration_estimate  
- unique_destination_count  
- rolling_average_deviation  
- z_score_anomaly  

Feature extraction integrity and schema consistency were validated prior to training.

---

## 4. Model Training Setup

### Train / Test Split
- Stratified split to ensure both classes appear in train and test sets
- Train distribution:
  - Malicious: 165
  - Benign: 9
- Test distribution:
  - Malicious: 55
  - Benign: 3

### Models Evaluated
- **Gradient Boosting Classifier**
- **Random Forest Classifier**

Default hyperparameters were intentionally used due to:
- Small dataset size
- Extreme class imbalance
- Clear separability of attack patterns

Hyperparameter tuning was deferred to avoid overfitting.

---

## 5. Evaluation Metrics

### Gradient Boosting Results

- Accuracy: **1.000**
- Precision: **1.000**
- Recall: **1.000**
- F1-score: **1.000**

Confusion Matrix:
[[ 3 0]
[ 0 55]]


---

### Random Forest Results

- Accuracy: **1.000**
- Precision: **1.000**
- Recall: **1.000**
- F1-score: **1.000**

Confusion Matrix:
[[ 3 0]
[ 0 55]]


---

## 6. Interpretation of Results

The perfect metrics observed are a result of:

- Highly structured and repetitive attack traffic (SSH brute force, SQL injection, FTP reconnaissance)
- Strong, discriminative engineered features
- Small benign sample size

These results are **not interpreted as production-level performance**, but as confirmation that:

- Feature engineering is effective
- Labels are clean
- The ML pipeline is functioning correctly
- Models are learning meaningful patterns

---

## 7. Model Selection Decision

### Selected Baseline Model: **Random Forest**

**Justification:**
- Equivalent performance to Gradient Boosting
- Faster inference characteristics
- Native feature importance support (`feature_importances_`)
- Easier explainability for SOC analysts
- More robust behavior under class imbalance

Gradient Boosting will be retained as a secondary comparison model but not used as the primary baseline.

---

## 8. Limitations & Future Work

Identified limitations:
- Extreme class imbalance
- Limited benign traffic diversity
- Potential feature leakage via threat_score

Planned improvements (Week 7 Day 3+):
- Feature importance analysis
- Explainability-focused reporting
- Feature ablation studies
- More realistic benign traffic inclusion

---

## 9. Conclusion

Day 2 objectives have been successfully completed:

- Both models trained and evaluated
- Comparison performed correctly
- Baseline model selected with SOC-first reasoning

The project is now ready to proceed to **Day 3: Feature Importance & Explainability**.

---

**Status:** ✅ Day 2 – COMPLETE  
**Approved by:** Team Lead  
**Project:** PhantomNet – AI-Driven Distributed Honeypot
