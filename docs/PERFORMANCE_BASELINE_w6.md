# PERFORMANCE BASELINE – WEEK 6

Project: PhantomNet  
Phase: Week 6 – Day 4 (Full Load Validation)

## Objective

Validate PhantomNet performance under full load (220 events) and record baseline metrics before moving to the next phase.

## Test Setup

- Dataset: data/week6_test_events.csv
- Total Events: 220
- Pipeline:
  - Load events from CSV
  - Feature extraction
  - Performance measurement
- Environment:
  - OS: Windows
  - Language: Python 3.x

## Performance Metrics

### Event Processing
- Events Loaded: 220
- Events Processed Successfully: 220
- Processing Failures: 0

### Latency
- Total Processing Time (220 events): ~68 ms
- Average Latency per Event: ~0.31 ms
- Feature Extraction Latency (avg): ~0.05 ms

### CPU Usage
- Average CPU Usage: ~2%
- Peak CPU Usage: Observed instantaneous spikes (acceptable)

### Memory Usage
- Memory at Start: ~67 MB
- Memory at End: ~67.5 MB
- Peak Memory Usage: ~67.5 MB

## Validation

- All 220 events processed successfully: YES
- Average latency under 100 ms: YES
- CPU usage within acceptable limits: YES
- Memory usage stable (no leak): YES

## Conclusion

PhantomNet performs efficiently under full load with low latency, stable CPU usage, and stable memory consumption. This document serves as the baseline for future performance comparison.
