# Week 7 – Documentation

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




# Week 7 – Day 3: Model Lifecycle & Deployment (PhantomNet)

## 📌 Overview

This document describes the **complete ML model lifecycle** implemented for **PhantomNet** during **Week 7 – Day 3**. It covers model registration, versioning, metadata tracking, deployment readiness, and validation using automated tests.

The goal of this phase was to ensure the trained ML model can be **reliably tracked, versioned, deployed, and validated** using **MLflow**, following production-grade MLOps practices.

---

## 🎯 Objectives

* Register trained models in MLflow Model Registry
* Implement model versioning with lifecycle stages
* Track model metadata and lineage
* Validate deployment pipeline readiness

---

## 📦 Deliverables

* `backend/ml/model_registry.py`
* `backend/ml/model_versioning.py`
* `backend/ml/deployment_pipeline.py`
* MLflow Model Registry entries
* Automated test suite (`pytest`)

---

## 🔁 Model Lifecycle Flow

```
Dataset (Week 6)
   ↓
Feature Engineering
   ↓
Model Training (run_training.py)
   ↓
MLflow Experiment Tracking
   ↓
Model Registration (model_registry.py)
   ↓
Model Versioning & Staging (model_versioning.py)
   ↓
Deployment Validation (deployment_pipeline.py)
   ↓
Automated Tests (pytest)
```

---

## 🧠 Model Training Summary

* Algorithm: Random Forest Classifier
* Label: Binary attack detection
* Feature(s): payload_length

### 📊 Performance Metrics

| Metric            | Value  |
| ----------------- | ------ |
| Accuracy          | 88.6%  |
| Precision         | 88.7%  |
| Recall            | 88.6%  |
| F1 Score          | 88.66% |
| Inference Latency | ~15 ms |

✔ Meets all defined success metrics

---

## 📘 Model Registration

**Script:** `model_registry.py`

Actions performed:

* Connected to MLflow tracking server
* Detected latest successful training run
* Registered model as **PhantomNet_Attack_Detector**
* Created new model version when model already existed

### Registry Status

* Model Name: `PhantomNet_Attack_Detector`
* Latest Version: 2
* Registry Backend: MLflow filesystem store

---

## 🔖 Model Versioning

**Script:** `model_versioning.py`

Actions performed:

* Retrieved latest registered model version
* Transitioned model to **Staging** stage
* Applied metadata tags

### Version Metadata

* Stage: Staging
* Tags:

  * `lifecycle = pre-production`
  * `validated = true`

---

## 🚀 Deployment Pipeline

**Script:** `deployment_pipeline.py`

Deployment strategy:

* Load model directly from MLflow Registry
* Use SAFE MODE loading to avoid artifact path issues
* Perform inference sanity check

### Deployment Test

```json
Input  : [{"payload_length": 120}]
Output : [0]
```

✔ Model successfully loaded and executed

---

## 🧪 Automated Testing

**Framework:** pytest

### Tests Executed

* `test_training.py`
* `test_registry.py`
* `test_deployment.py`

### Final Test Results

```
3 passed, 0 failed
```

Warnings observed are related to MLflow filesystem deprecation and do not affect functionality.

✔ All tests passing

---

## ✨ Acceptance Criteria Validation

| Criteria                  | Status |
| ------------------------- | ------ |
| All tasks completed       | ✅      |
| Coding standards followed | ✅      |
| Integration verified      | ✅      |
| Documentation completed   | ✅      |
| Tests passing             | ✅      |
| Ready for next phase      | ✅      |

---

## 🔗 Dependencies

* Week 6 dataset and preprocessing pipeline
* PhantomNet backend infrastructure
* MLflow tracking server
* Local development environment

---

## ✅ Final Status

**Week 7 – Day 3: COMPLETED (100%)**

This phase establishes a **robust, test-validated, production-ready ML lifecycle** for PhantomNet, enabling seamless progression to the next deployment and monitoring stages.

---

*End of Document*
