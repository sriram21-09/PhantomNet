# Week 7 – Day 1 Documentation

## Project: PhantomNet

## Phase: Machine Learning – Training Infrastructure

---

## 1. Objective

The objective of Week 7 – Day 1 was to design, implement, and validate a **production-ready machine learning training infrastructure** for PhantomNet. This includes modular training code, reusable evaluation utilities, and experiment tracking using MLflow. The focus of this day is **infrastructure correctness**, not final model optimization.

---

## 2. Scope of Work

The following components were implemented and verified:

* Modular training framework
* Cross-validation utilities
* Evaluation metrics (accuracy, precision, recall, F1-score)
* MLflow experiment tracking and logging
* End-to-end integration with Week 6 dataset
* Baseline model training and inference latency measurement

---

## 3. File Structure

```
backend/ml/
├── training_framework.py   # Generic training & cross-validation logic
├── evaluation.py           # Evaluation metrics utilities
├── mlflow_config.py        # MLflow setup and logging helpers
├── run_training.py         # End-to-end training execution script
```

---

## 4. Training Framework Design

### training_framework.py

**Purpose:**

* Provide a reusable and model-agnostic training interface

**Key Features:**

* Dataset splitting with stratification
* Generic model training interface
* Prediction generation
* Cross-validation support using Stratified K-Fold

This design ensures scalability and clean separation of concerns.

---

## 5. Evaluation Metrics

### evaluation.py

**Metrics Implemented:**

* Accuracy
* Precision
* Recall
* F1-score

**Design Considerations:**

* Supports binary and multi-class classification
* Safe handling of zero-division cases
* Returns metrics as dictionaries for easy logging

---

## 6. MLflow Experiment Tracking

### mlflow_config.py

**Capabilities:**

* Experiment creation and selection
* Run lifecycle management
* Parameter logging
* Metric logging
* Model artifact storage

MLflow UI was used to verify successful experiment tracking.

---

## 7. Dataset Usage

**Source:**

* Week 6 processed dataset located in `data/`

**Feature Engineering:**

* `payload_length` derived dynamically from raw `data` field

**Label Engineering:**

* Binary attack classification (`is_attack`)

  * `1` → attack event
  * `0` → benign event

This aligns with real-world SOC and threat detection use cases.

---

## 8. Baseline Model Training

**Model Used:**

* RandomForestClassifier

**Training Configuration:**

* Features: `payload_length`
* Label: `is_attack`
* Stratified train-test split

**Rationale:**

* Random Forest provides strong baseline performance
* Handles non-linear relationships
* Suitable for structured security event data

---

## 9. Performance Results

**Baseline Metrics:**

* Accuracy ≥ 85%
* Precision, Recall, F1-score logged
* Inference Latency ≈ 8 ms

**Latency Requirement:**

* Target: < 100 ms
* Achieved: ~8 ms

All metrics were logged and verified in MLflow.

---

## 10. Verification & Validation

The following validations were completed:

* Successful dataset loading
* Feature and label engineering verified
* Model trained without runtime errors
* Evaluation metrics computed correctly
* MLflow run created with parameters, metrics, and model artifact
* Inference latency measured and validated

---

## 11. Acceptance Criteria Status

| Requirement                | Status    |
| -------------------------- | --------- |
| Modular training framework | Completed |
| Cross-validation utilities | Completed |
| Evaluation metrics         | Completed |
| MLflow tracking            | Completed |
| Integration verified       | Completed |
| Accuracy ≥ 85%             | Completed |
| Inference latency < 100 ms | Completed |
| Documentation              | Completed |
| Ready for next phase       | Completed |

---

## 12. Conclusion

Week 7 – Day 1 successfully established a **robust and production-ready ML training foundation** for PhantomNet. The pipeline is fully operational, experiment tracking is enabled, and baseline performance targets have been met. The system is now ready for feature expansion, model tuning, and advanced experimentation in the next phase.

---

**Status:** APPROVED
