# Week 7 – Day 2 Evaluation Report
## Project: PhantomNet

---

## 1. Objective
The objective of Week 7 – Day 2 is to evaluate trained ML models using a unified evaluation framework, benchmark inference latency, and validate performance against defined acceptance criteria.

---

## 2. Evaluation Setup

- Model Type: RandomForestClassifier
- Classification Type: Binary (Attack vs Benign)
- Feature Used: payload_length
- Dataset: Week 6 processed events
- Tracking: MLflow (local tracking backend)

---

## 3. Model Performance Metrics

| Metric     | Value |
|------------|-------|
| Accuracy   | 88.63% |
| Precision  | 88.78% |
| Recall     | 88.63% |
| F1-score   | 88.66% |

✅ Accuracy requirement (≥ 85%) **PASSED**

---

## 4. Inference Latency Benchmark

Latency was measured using repeated inference runs on the trained model.

| Metric | Value (ms) |
|------|------------|
| Average Latency | 15.68 |
| Minimum Latency | 14.44 |
| Maximum Latency | 17.66 |

✅ Latency requirement (< 100 ms) **PASSED**

---

## 5. Model Comparison Table

| Model Name | Accuracy | Precision | Recall | F1-score | Avg Latency (ms) |
|-----------|----------|-----------|--------|----------|------------------|
| RandomForest (Binary Attack) | 0.8863 | 0.8879 | 0.8864 | 0.8867 | 15.68 |

---

## 6. Validation Summary

| Acceptance Criterion | Status |
|---------------------|--------|
| Unified evaluation framework | Completed |
| Inference latency benchmark | Completed |
| Accuracy ≥ 85% | Passed |
| Latency < 100 ms | Passed |
| MLflow integration | Verified |
| Documentation | Completed |
| Ready for next phase | Yes |

---

## 7. Conclusion

Week 7 – Day 2 successfully validated the ML model using unified evaluation logic and performance benchmarking. All acceptance criteria and success metrics were met. The system is ready for advanced experimentation and model optimization in subsequent phases.

---

**Status:** APPROVED
