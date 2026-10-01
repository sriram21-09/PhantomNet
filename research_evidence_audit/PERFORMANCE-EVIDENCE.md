# PhantomNet Performance Evidence

## 1. SOAR Component Micro-benchmarks
Evaluated over 100 warm iterations per module in xperiments/run_publication_validation.py:

| Subsystem | Mean Latency (ms) | Median Latency (ms) | P95 Latency (ms) | Std Dev (ms) |
|---|---:|---:|---:|---:|
| Snort Rule Synthesis | 0.488 | 0.449 | 0.695 | 0.098 |
| STIX 2.1 Bundle Construction | 1.022 | 0.970 | 1.335 | 0.168 |
| Jinja2 Playbook Rendering | 1.098 | 0.348 | 0.484 | 7.329 |

## 2. ML Inference Latency
- Cold Start Latency: 337.39 ms (includes Python library and pickle deserialization)
- Warm Scoring Latency: 0.92 ms to 1.46 ms across protocol evaluation scenarios
- Average Warm Latency: 1.12 ms

## 3. End-to-End Latency Evaluation
- Individual components meet the sub-50ms latency objective with ample margin (< 5ms total combined execution time).
- However, full closed-loop pipeline execution requires StandardScaler in the DBSCAN step; when scaled, the entire E2E pipeline completes in approximately 22 ms.
