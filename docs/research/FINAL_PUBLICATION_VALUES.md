# PhantomNet Final Publication Values & Evidence Provenance

**Document Version:** 1.0.0  
**Status:** Authoritative Camera-Ready Evidence Specification  
**Date:** 2026-09-02  

---

# 1. AUTHORITATIVE PUBLICATION VALUES

The following quantitative values have complete experimental provenance and are approved for inclusion in the final IEEE research paper:

### ML Classification Performance (13-Dimensional Network Flow Evaluation)
* **Optimal Ensemble Weights:** $w_{RF} = 0.85, w_{IF} = 0.15$ (Supervised tuning) / $w_{RF} = 0.70, w_{IF} = 0.30$ (Operational baseline).
* **Test Classification Accuracy:** **96.90%** (Single 80/20 Stratified Split, $N=1,000$ test events).
* **5-Fold Cross-Validation Accuracy:** **96.56% ± 0.37%** (Mean ± Std Dev).
* **Test Precision:** **96.86%**.
* **Test Recall:** **92.67%**.
* **Test F1-Score:** **0.9472** (Single Split) / **0.9416 ± 0.0061** (5-Fold CV).
* **False Positive Rate (FPR):** **1.29%** (Test Split) / **1.43%** (Standalone RF).
* **Receiver Operating Characteristic (ROC-AUC):** **0.9569** (Single Split) / **0.9535 ± 0.0044** (5-Fold CV).
* **Matthews Correlation Coefficient (MCC):** **0.9257** (Single Split) / **0.9177 ± 0.0087** (5-Fold CV).
* **Confusion Matrix (Optimal Ensemble, Test $N=1,000$):**
  - True Negatives (TN): **691** (out of 700 benign)
  - False Positives (FP): **9**
  - False Negatives (FN): **22**
  - True Positives (TP): **278** (out of 300 malicious)
* **Dataset Characteristics:** 5,000 synthetic honeypot socket interaction events (3,500 benign, 1,500 malicious; 70:30 class balance).

---

### Campaign Clustering & Normalization (DBSCAN Benchmark)
* **Standardized DBSCAN Silhouette Score:** **0.9895** (StandardScaler + Euclidean DBSCAN).
* **Adjusted Rand Index (ARI):** **0.2116** (vs. 0.0000 baseline unscaled).
* **Normalized Mutual Information (NMI):** **0.4680** (vs. 0.0000 baseline unscaled).
* **Homogeneity:** **0.3486** (vs. 0.0000 baseline unscaled).
* **Completeness:** **0.7120** (vs. 1.0000 baseline single-cluster unscaled).
* **V-Measure:** **0.4680** (vs. 0.0000 baseline unscaled).
* **Pairwise Clustering F1:** **0.0317** (vs. 0.0000 baseline unscaled).
* **Noise Reduction Ratio:** **71.00%** under standardization (vs. 100.00% baseline unscaled).
* **Autonomous End-to-End Pipeline Completion:** **100.0% (30/30 runs)** under standardized DBSCAN vs. **0.0% (0/30 runs)** under baseline unscaled DBSCAN (Fisher's Exact Test $p < 0.001$).

---

### Subsystem Latencies & Throughput
* **Random Forest Inference Latency:** **15.68 ms** (Range: 14.44–17.66 ms, $N=44$ batch evaluation).
* **Snort Rule Generation Latency:** **0.488 ms** (Mean) / **0.449 ms** (Median) / **0.695 ms** (P95) ($N=100$).
* **STIX 2.1 Bundle Construction Latency:** **1.022 ms** (Mean) / **0.970 ms** (Median) / **1.335 ms** (P95) ($N=100$).
* **Jinja2 Playbook Rendering Latency:** **1.098 ms** (Mean) / **0.348 ms** (Median) / **0.484 ms** (P95) ($N=100$).
* **Standardized DBSCAN Clustering Latency:** **17.08 ± 7.62 ms** ($N=100$ events).
* **REST API Query Latency (P95):** **50.00 ms** under 500 concurrent Locust clients.
* **Maximum Peak Ingestion Throughput:** **3,225 events/second**.

---

### Threat Intelligence & Framework Coverage
* **MITRE ATT&CK Mapped Signatures:** Exactly **12 signature mappings** covering **10 unique technique IDs** across **8 tactical stages**.
* **STIX 2.1 Objects per Bundle:** Minimum **4–5 interconnected STIX domain objects** (AttackPattern, Indicator, Relationship, Identity, ObservedData).
* **Software Verification Suite:** **4,181 / 4,181 automated tests passing** (100% pass rate).

---

# 2. VALUES THAT MUST NOT APPEAR IN PAPER

The following values are obsolete, conflicting, or scientifically unsupported, and must be strictly excluded from the paper:

1. **"100% Classification Accuracy" / "Zero False Positives":** Contradicts honest empirical evaluation; actual test accuracy is 96.90% with 9 false positives on the held-out split.
2. **"23-Dimensional Feature Space":** Legacy conceptual design number from early planning; the actual operational feature extractor extracts exactly 15 dimensions (13 evaluated for supervised ML).
3. **"Active 3-Model Real-Time LSTM Inference":** The LSTM module is an offline architectural prototype; production operates in dual-model RF+IF fallback mode.
4. **"88.64% / 86.82% Accuracy":** Outdated Week 7 prototype metrics evaluated on legacy 6-feature prototypes.
5. **"Sub-1ms Full End-to-End Pipeline Latency":** Contradicts component measurement summation ($15.68\text{ ms ML} + 17.08\text{ ms DBSCAN} + 1.02\text{ ms STIX} + 1.10\text{ ms Playbook} \approx 35\text{ ms}$ complete autonomous cycle).

---

# 3. VALUES REQUIRING QUALIFICATION

The following metrics are scientifically valid but require specific contextual phrasing to maintain rigorous scientific integrity:

| Value | Required Contextual Phrasing | Rationale |
|---|---|---|
| **96.90% Accuracy / 0.9472 F1** | *"Evaluated on a 5,000-sample synthetic honeypot telemetry dataset with 70:30 benign-to-malicious balance using the 13-feature evaluation subset."* | Clarifies synthetic testbed origin and leak-prevention feature dropping. |
| **0/30 vs. 30/30 E2E Completion** | *"Under a controlled multi-campaign evaluation workload of 100 events across 4 attack types evaluated across 30 automated test pipeline runs."* | Explains that 30 represents repeated autonomous evaluation runs of the benchmark workload. |
| **15.68 ms RF Inference Latency** | *"Measured as single-event inference time on a dedicated evaluation host (AMD/Intel 8-core CPU, 16GB RAM) in Python 3.11."* | Prevents ambiguity regarding hardware and execution runtime. |
| **3,225 events/sec Throughput** | *"Achieved under asynchronous batch ingestion mode during Locust load testing with 500 concurrent worker connections."* | Distinguishes batch ingestion throughput from synchronous end-to-end processing. |
| **4,181 Tests Passing** | *"Demonstrates comprehensive software regression integrity and API contract adherence across the v3.0.0 codebase."* | Clarifies software test coverage versus statistical machine learning validation. |
