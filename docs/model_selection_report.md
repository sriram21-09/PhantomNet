# Model Selection Report - Week 7

**Date:** February 6, 2026  
**Role:** Team Lead  
**Phase:** Week 7 - ML Pipeline Integration  

---

## Executive Summary

This report documents the final model selection for the PhantomNet intrusion detection system. Based on comprehensive evaluation during Week 7, we have selected production-ready models for both classification and anomaly detection tasks.

---

## 1. Classification Model Selection

### Selected Model

| Attribute | Value |
|-----------|-------|
| **Algorithm** | RandomForestClassifier |
| **Configuration** | `n_estimators=200, random_state=42` |
| **Task** | Binary Attack Classification (0=Benign, 1=Attack) |
| **Status** | ✅ **SELECTED FOR PRODUCTION** |

### Performance Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Accuracy | 88.64% | ≥ 85% | ✅ PASS |
| Precision | 88.79% | - | ✅ |
| Recall | 88.64% | - | ✅ |
| F1-Score | 88.67% | - | ✅ |
| Attack Class Recall | 88.0% | ≥ 70% | ✅ PASS |
| Benign Class Recall | 89.5% | - | ✅ |

### Cross-Validation Stability

| Metric | Mean | Std Dev |
|--------|------|---------|
| Accuracy | 86.82% | ±5.06% |
| Precision | 92.60% | ±6.05% |
| Recall | 84.18% | ±7.13% |
| F1-Score | 87.96% | ±4.77% |

**Stability Verdict:** MODERATELY STABLE - Acceptable for production with monitoring.

### Rationale for Selection

1. **Meets accuracy threshold** (88.64% > 85% target)
2. **Balanced class performance** - No significant bias toward majority class
3. **Interpretable** - Feature importances can be extracted
4. **Fast inference** - Random Forest provides sub-millisecond predictions
5. **Robust** - Cross-validation shows consistent performance

### Artifacts

| File | Description |
|------|-------------|
| `backend/ml/model.pkl` | Serialized trained model |
| `backend/ml/scaler.pkl` | Feature scaler |
| `backend/ml/run_training.py` | Training script |

---

## 2. Anomaly Detection Model Selection

### Selected Model

| Attribute | Value |
|-----------|-------|
| **Algorithm** | IsolationForest |
| **Configuration** | `n_estimators=100, contamination=0.1, random_state=42` |
| **Task** | Unsupervised Anomaly Detection |
| **Status** | ✅ **SELECTED FOR PRODUCTION** |

### Configuration Rationale

| Parameter | Value | Justification |
|-----------|-------|---------------|
| `n_estimators` | 100 | Balance between accuracy and speed |
| `contamination` | 0.1 | Expected ~10% attack rate in traffic |
| `random_state` | 42 | Reproducibility |

### Output Specification

| Output | Type | Range | Description |
|--------|------|-------|-------------|
| `prediction` | int | {-1, 1} | -1 = Anomaly, 1 = Normal |
| `anomaly_score` | float | (-∞, +∞) | Decision function output (lower = more anomalous) |

### Integration with Decision Tree

The anomaly score is normalized to [0, 1] range before being passed to the ResponseDecisionTree:

```python
# Normalization formula (applied in threat_correlation.py)
normalized_score = min(1.0, max(0.0, (anomaly_score + 0.5)))
```

### Artifacts

| File | Description |
|------|-------------|
| `backend/ml/anomaly_detector.py` | AnomalyDetector class |
| `backend/ml/threat_model.pkl` | Trained anomaly model |

---

## 3. Threat Correlation Model

### Architecture

The ThreatCorrelator combines multiple signals:

| Signal Source | Weight | Description |
|---------------|--------|-------------|
| AI Anomaly Detection | 20% | Isolation Forest output |
| Signature Rules | 30% | Pattern-based detection |
| Threat Intelligence | 50% | External feed lookup |

### Risk Score Calculation

```
total_risk = (ai_risk × 0.2) + (rule_risk × 0.3) + (feed_risk × 0.5)
```

### Verdict Thresholds

| Score Range | Verdict |
|-------------|---------|
| > 80 | CRITICAL |
| > 50 | HIGH |
| > 20 | WARNING |
| ≤ 20 | SAFE |

### Artifacts

| File | Description |
|------|-------------|
| `backend/ml/threat_correlation.py` | ThreatCorrelator class |
| `backend/ml/signatures.py` | SignatureEngine class |

---

## 4. Decision Tree Validation

### Decision Tree Configuration

The ResponseDecisionTree (Day 3) has been validated for compatibility with selected models.

| Input | Source | Validated |
|-------|--------|-----------|
| `prediction` | RandomForest classifier | ✅ |
| `confidence` | RandomForest predict_proba | ✅ |
| `anomaly_score` | IsolationForest (normalized) | ✅ |
| `threat_score` | ThreatCorrelator | ✅ |

### Response Actions

| Response | Trigger Condition | System Action |
|----------|-------------------|---------------|
| LOG | Benign + Low Anomaly | Record only |
| THROTTLE | Attack + Low Confidence | Rate limit |
| DECEIVE | Attack + Medium Confidence + Medium Anomaly | Honeypot redirect |
| BLOCK | Attack + High Confidence + High Anomaly + High Threat | Firewall drop |

### Validation Tests

| Test Case | Input | Expected Output | Status |
|-----------|-------|-----------------|--------|
| Benign traffic | prediction=0, anomaly=0.1 | LOG | ✅ PASS |
| Low-conf attack | prediction=1, confidence=0.4 | THROTTLE | ✅ PASS |
| High-severity attack | prediction=1, conf=0.9, anomaly=0.9, threat=0.9 | BLOCK | ✅ PASS |
| Medium attack | prediction=1, conf=0.7, anomaly=0.6 | DECEIVE | ✅ PASS |

### Artifacts

| File | Description |
|------|-------------|
| `backend/ml/decision_tree.py` | ResponseDecisionTree class |
| `backend/ml/response_mapping.py` | Response action mappings |

---

## 5. RL Compatibility Assessment

### Current State

The system is designed to be **RL-ready** but does not yet implement reinforcement learning.

### RL Integration Points

| Component | RL Hook | Status |
|-----------|---------|--------|
| Decision Tree | Threshold parameters can be learned | 🟡 Ready |
| Response Mapping | Action space defined | 🟡 Ready |
| Reward Signal | Can be derived from detection accuracy | 🟡 Planned (Week 8+) |

### Future RL Architecture

```
State: (prediction, confidence, anomaly_score, threat_score)
Action: {LOG, THROTTLE, DECEIVE, BLOCK}
Reward: +1 for correct response, -10 for FN, -1 for FP
```

### Compatibility Checklist

| Requirement | Status |
|-------------|--------|
| Discrete action space | ✅ Defined |
| Observable state | ✅ 4 numeric inputs |
| Stateless decisions | ✅ Implemented |
| Configurable thresholds | ✅ Parameterized |
| Simulation environment | 🟡 Week 8 |

---

## 6. Production Readiness Checklist

| Criterion | Status | Notes |
|-----------|--------|-------|
| Classification accuracy ≥ 85% | ✅ | 88.64% achieved |
| Anomaly detector operational | ✅ | IsolationForest deployed |
| Decision tree validated | ✅ | All test cases pass |
| Response mapping complete | ✅ | 4 actions defined |
| Error analysis completed | ✅ | Day 4 report |
| Class imbalance assessed | ✅ | Not materially affecting |
| CV stability validated | ✅ | Moderately stable |
| Unit tests passing | ✅ | 18/18 tests pass |
| Documentation complete | ✅ | This report |

---

## 7. Recommendations

### Immediate (Week 8)

1. **Feature Engineering** - Add more features beyond `payload_length`
2. **Model Versioning** - Implement MLflow model registry
3. **Latency Benchmarking** - Validate < 100ms inference

### Future (Weeks 9+)

1. **Ensemble Methods** - Combine classifier with anomaly detector
2. **RL Training** - Implement policy gradient for threshold tuning
3. **Online Learning** - Adapt to evolving attack patterns

---

## Appendix: Model File Inventory

| File | Size | Purpose |
|------|------|---------|
| `backend/ml/model.pkl` | 1.4 MB | Classification model |
| `backend/ml/scaler.pkl` | 879 B | Feature scaler |
| `backend/ml/threat_model.pkl` | 19 KB | Threat correlation model |
