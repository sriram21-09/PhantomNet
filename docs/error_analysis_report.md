# Error Analysis Report - Day 4

**Date:** February 6, 2026  
**Role:** Team Lead  
**Focus:** Model Quality Validation & Error Understanding  

---

## Overview

### Dataset Used
- **File:** `week6_test_events.csv`
- **Total Samples:** 220
- **Train/Test Split:** 80/20 (176 train, 44 test)
- **Stratified:** Yes

### Model Evaluated
- **Algorithm:** RandomForestClassifier
- **Configuration:** `n_estimators=200, random_state=42`
- **Features:** `payload_length` (single feature)
- **Label:** `is_attack` (binary: 0=benign, 1=attack)

### Overall Test Metrics
| Metric    | Value  |
|-----------|--------|
| Accuracy  | 88.64% |
| Precision | 88.79% |
| Recall    | 88.64% |
| F1-Score  | 88.67% |

✅ **Accuracy meets the ≥85% threshold.**

---

## 1. Misclassification Analysis

### Error Summary
| Metric | Value |
|--------|-------|
| Total Test Samples | 44 |
| Total Errors | 5 |
| Error Rate | 11.36% |
| False Positives (Benign → Attack) | 2 |
| False Negatives (Attack → Benign) | 3 |

### False Positive Analysis (2 samples)

**Definition:** Benign traffic incorrectly classified as attack.

| Feature | Mean | Std | Min | Max | Median |
|---------|------|-----|-----|-----|--------|
| `payload_length` | 113.0 | 0.0 | 113.0 | 113.0 | 113.0 |

**Confidence Statistics:**
| Metric | Value |
|--------|-------|
| Mean Confidence | 0.603 |
| Min Confidence | 0.603 |
| Max Confidence | 0.603 |
| Low-Confidence Count (<0.6) | 0 |
| High-Confidence Count (≥0.8) | 0 |

**Observations:**
- All FPs have identical `payload_length` = 113
- Confidence is borderline (0.603) - just above threshold
- These are **medium-confidence errors**, not high-confidence mistakes
- Suggests a specific payload length range creates ambiguity

### False Negative Analysis (3 samples)

**Definition:** Attack traffic incorrectly classified as benign.

| Feature | Mean | Std | Min | Max | Median |
|---------|------|-----|-----|-----|--------|
| `payload_length` | 73.3 | 60.9 | 3.0 | 109.0 | 108.0 |

**Confidence Statistics:**
| Metric | Value |
|--------|-------|
| Mean Confidence | 0.410 |
| Min Confidence | 0.251 |
| Max Confidence | 0.489 |
| Low-Confidence Count (<0.6) | 3 |
| High-Confidence Count (≥0.8) | 0 |

**Observations:**
- High variance in `payload_length` (3 to 109)
- **All FNs are low-confidence predictions** (mean = 0.41)
- Model was uncertain about these samples
- Short payload attacks (length=3) are being missed

### Key Findings - Error Patterns

| Question | Answer |
|----------|--------|
| Are errors clustered around specific feature ranges? | **Yes** - FPs cluster at payload_length=113, FNs show high variance |
| Are false negatives low-confidence predictions? | **Yes** - All 3 FNs have confidence < 0.6 |
| Are false positives anomaly-driven? | **Partially** - They occur at a specific payload length boundary |

---

## 2. Class Imbalance Assessment

### Class Distribution

| Split | Benign (0) | Attack (1) | Imbalance Ratio |
|-------|------------|------------|-----------------|
| Full Dataset | 93 (42.3%) | 127 (57.7%) | 1.37:1 |
| Train Split | 74 (42.0%) | 102 (58.0%) | 1.38:1 |
| Test Split | 19 (43.2%) | 25 (56.8%) | 1.32:1 |

### Per-Class Metrics

| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| Benign | 0.850 | 0.895 | 0.872 | 19 |
| Attack | 0.917 | 0.880 | 0.898 | 25 |

### Impact Assessment

| Indicator | Value | Status |
|-----------|-------|--------|
| Imbalance Ratio | 1.37:1 | ✅ Acceptable (<3:1) |
| Accuracy | 88.64% | ✅ Above majority baseline (57.7%) |
| Attack Class Recall | 88.0% | ✅ Above 70% threshold |
| Recall Gap (Attack - Benign) | -1.5% | ✅ Minimal (<20%) |

### Verdict

> **Class imbalance is NOT materially affecting model behavior.**

The dataset has a mild imbalance (1.37:1 ratio), but:
- Accuracy significantly exceeds the majority class baseline
- Attack recall is strong (88%)
- Both classes have similar performance metrics
- No precision/recall skew observed

---

## 3. Cross-Validation Stability

### Configuration
- **Strategy:** Stratified K-Fold
- **K:** 5
- **Shuffle:** Yes
- **Random State:** 42

### Fold-by-Fold Results

| Fold | Accuracy | Precision | Recall | F1 |
|------|----------|-----------|--------|-----|
| 1 | 0.9091 | 0.9565 | 0.8800 | 0.9167 |
| 2 | 0.7727 | 0.8261 | 0.7600 | 0.7917 |
| 3 | 0.8864 | 1.0000 | 0.8000 | 0.8889 |
| 4 | 0.8636 | 0.9545 | 0.8077 | 0.8750 |
| 5 | 0.9091 | 0.8929 | 0.9615 | 0.9259 |

### Aggregated Statistics

| Metric | Mean | Std Dev |
|--------|------|---------|
| Accuracy | 0.8682 | 0.0506 |
| Precision | 0.9260 | 0.0605 |
| Recall | 0.8418 | 0.0713 |
| F1-Score | 0.8796 | 0.0477 |

### Stability Analysis

| Indicator | Value | Interpretation |
|-----------|-------|----------------|
| Max Std Dev | 0.0713 (Recall) | Medium variance |
| Stability Rating | **MEDIUM** | Some fold-to-fold variance |

### Verdict

> **MODERATELY STABLE - Some variance observed**

- Fold 2 underperforms (accuracy = 77.3%) compared to others
- Recall varies most across folds (std = 0.071)
- This suggests some data sensitivity, but overall the model is reasonably stable
- No folds fall below 75% accuracy

---

## 4. Key Findings Summary

### Risks Identified

| Risk | Severity | Description |
|------|----------|-------------|
| **Short payload attacks missed** | Medium | Attacks with `payload_length` ≈ 3 are being missed (FN) |
| **Payload length boundary confusion** | Low | Payload length ≈ 113 creates ambiguity between classes |
| **Moderate CV variance** | Low | Some fold sensitivity (std = 0.05-0.07) |
| **Single feature limitation** | Medium | Model relies only on `payload_length`; may miss attacks with normal lengths |

### What Must Be Addressed Later

1. **Feature Engineering** - Add more features beyond `payload_length` to improve discrimination
2. **Threshold Tuning** - Consider adjusting classification threshold for low-confidence predictions
3. **Edge Case Handling** - Investigate short-payload attacks and why they're being missed
4. **Confidence-Based Routing** - Use confidence scores in the decision tree (already implemented in Day 3)

---

## 5. Acceptance Criteria Verification

| Criteria | Status |
|----------|--------|
| FP and FN explicitly analyzed | ✅ |
| Class imbalance quantified | ✅ |
| CV stability measured | ✅ |
| No retraining performed | ✅ |
| Code is analysis-only | ✅ |
| Report is clear and review-ready | ✅ |

---

## 6. Success Metrics Validation

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Accuracy | ≥ 85% | 88.64% | ✅ PASS |
| Attack Class Recall | Explicitly reported | 88.0% | ✅ PASS |
| CV Standard Deviation | Documented | Max 0.071 | ✅ PASS |
| Inference Latency | < 100ms | Not measured (analysis only) | N/A |

---

## Appendix: Generated Files

| File | Purpose |
|------|---------|
| `backend/ml/error_analysis.py` | Error analysis module |
| `backend/ml/class_imbalance.py` | Class imbalance analysis module |
| `scripts/run_day4_analysis.py` | Analysis runner script |
| `data/day4_analysis_results.json` | Raw analysis results (JSON) |
| `docs/error_analysis_report.md` | This report |
