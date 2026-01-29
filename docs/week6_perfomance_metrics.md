# PERFORMANCE METRICS – WEEK 6

## Project: PhantomNet

## Phase: Week 6 – Day 4 (Full Load Validation)

---

## Objective

Validate PhantomNet system performance under full load (220 events) and document baseline metrics for future comparison.

---

## Test Setup

* **Dataset**: `data/week6_test_events.csv`
* **Total Events**: 220
* **Pipeline**:

  * CSV ingestion
  * Feature extraction
  * Performance monitoring (latency, CPU, memory)
* **Execution Environment**:

  * OS: Windows
  * Language: Python 3.x
  * Libraries: pandas, psutil

---

## Performance Metrics

### 1. Event Processing

* Events Loaded: 220
* Events Processed Successfully: 220
* Processing Failures: 0

✅ All events processed successfully without errors.

---

### 2. Latency Metrics

* **Average Feature Extraction Latency**: ~0.05 ms per event
* **Total Pipeline Processing Time**: ~68 ms (for 220 events)
* **Average Pipeline Latency per Event**: ~0.31 ms

✅ Acceptance Criteria Met: Average latency well below 100 ms.

---

### 3. CPU Usage

* **Average CPU Usage**: ~2%
* **Observed Peak CPU Usage**: Instantaneous spikes up to 100%

Note: Peak spikes are due to instantaneous sampling and are acceptable. Average CPU usage remains low and stable.

---

### 4. Memory Usage

* **Memory at Start**: ~67 MB
* **Memory at End**: ~67.5 MB
* **Peak Memory Usage**: ~67.5 MB

✅ Memory usage stable with no signs of memory leak.

---

## Data Characteristics (Observed)

* Honeypot distribution is imbalanced (SMTP-heavy traffic).
* Event types include SMTP commands, FTP actions, and HTTP SQL injection attempts.
* Some events legitimately lack payload data.

This reflects realistic SOC data conditions.

---

## Validation Summary

| Requirement                    | Status |
| ------------------------------ | ------ |
| 220 events processed           | ✅      |
| Feature extraction completed   | ✅      |
| Total processing time measured | ✅      |
| Avg latency < 100 ms           | ✅      |
| CPU usage within limits        | ✅      |
| Memory usage stable            | ✅      |
| No processing failures         | ✅      |
| Baseline documented            | ✅      |

---

## Conclusion

PhantomNet successfully processes full-load traffic with excellent performance characteristics. The system operates well within defined limits for latency, CPU, and memory usage. This baseline will be used for future regression testing, scaling analysis, and ML pipeline validation.

---

**Baseline Status**: APPROVED
