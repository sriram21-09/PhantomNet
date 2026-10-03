# Phase ML-9: Scientific Limitation Register (LIM-01 to LIM-25)

## 1. Executive Summary

The Phase ML-9 Scientific Limitation Register formally catalogs all known technical, empirical, and architectural boundaries of PhantomNet, preventing misleading or overstated claims in academic publications and deployment specifications.

---

## 2. Comprehensive Limitation Register

| ID | Limitation Title | Severity | Impact Description | Mandatory Mitigation / Boundary |
| :--- | :--- | :---: | :--- | :--- |
| **LIM-01** | Synthetic Base Distribution | HIGH | Baseline training data generated in software-defined sandbox. | Requires local empirical adaptation on physical network traffic. |
| **LIM-02** | 12D Feature Dimensionality | MEDIUM | 12 flow summary features omit deep packet payload inspection. | Qualify as flow-level behavioral detection rather than deep payload IDS. |
| **LIM-03** | Tree Interpretability Bound | LOW | Tree ensemble feature importance reflects association, not causality. | Avoid causal claims regarding feature importance. |
| **LIM-04** | Contamination Rate Assumption | MEDIUM | Isolation Forest contamination set to 0.30 heuristic. | Calibrate IF anomaly thresholds on domain-specific benign baselines. |
| **LIM-05** | NetFlow Sub-sampling Boundary | MEDIUM | Flow export aggregation smooths microsecond-level packet jitter. | Document flow-export granularity in deployment specs. |
| **LIM-06** | Simulated Topology Realism | HIGH | Honeynet topology lacks background enterprise service noise. | Evaluate on independent real-world captures before claiming broad utility. |
| **LIM-07** | Uncalibrated Anomaly Scores | HIGH | Isolation Forest decision function scores are not true probabilities. | Use post-hoc calibration or rank-order thresholding. |
| **LIM-08** | Single-Packet Flow Estimation | MEDIUM | Short flows ($N=1$ packet) produce degenerate variance and jitter. | Handle single-packet flows with dedicated default imputations. |
| **LIM-09** | Sliding Window Variance | LOW | Fixed 1-minute sliding rate windows create boundary quantization. | Document time window definitions across network interfaces. |
| **LIM-10** | High-Cardinality Port Mapping | MEDIUM | Ephemeral ports mapped to coarse binary/tier categories. | Document port tiering rules in feature specification. |
| **LIM-11** | Omission of Raw PCAP in CSVs | HIGH | External benchmark CSVs do not contain raw byte payloads. | Acknowledge dataset provider preprocessing limitations. |
| **LIM-12** | Attack Imbalance Sensitivity | HIGH | Performance degrades when local attack prevalence is $<2\%$. | Enforce minimum $5\%$ minority prevalence in adaptation sets. |
| **LIM-13** | Historical Threshold Provenance | HIGH | Historical $\text{ALERT}=0.50$ and $\text{BLOCK}=0.80$ lack derivation artifacts. | Designate as `NO_PRESERVED_PROVENANCE` heuristic defaults. |
| **LIM-14** | Tooling Feature Semantics | HIGH | NetFlow v2, CICFlowMeter, and Bro extract subtly different features. | Document dataset-specific feature extraction mappings. |
| **LIM-15** | Composite Score Non-Bayesian | HIGH | $S_{\text{composite}}$ is an ordinal score, not a posterior probability. | Classify formally as `ORDINAL_COMPOSITE_THREAT_SCORE`. |
| **LIM-16** | Frozen Zero-Shot Inoperability | CRITICAL | Frozen synthetic models suffer severe degradation on external domains. | Prohibit zero-shot deployment; require local adaptation. |
| **LIM-17** | Absence of Ensemble Dominance | MEDIUM | 0.85/0.15 ensemble does not universally outperform tuned RF. | Present ensemble as hybrid defense-in-depth, not metric superior. |
| **LIM-18** | Payload Entropy Imputation | HIGH | External flow datasets require median imputation for entropy. | Document payload entropy imputation; sensitivity is bounded ($\Delta \text{F1} < 0.002$). |
| **LIM-19** | Adaptation Label Noise Limit | HIGH | Local adaptation degrades when label noise exceeds $15\%$. | Enforce label auditing in local retraining workflows. |
| **LIM-20** | Small Benchmark Sample ($N=4$) | MEDIUM | Evaluation spans 4 benchmark environments. | Do not claim universality across all unobserved network topologies. |
| **LIM-21** | Domain Threat Baselines | HIGH | Threat score distributions vary across different network environments. | Re-estimate baseline score distributions upon deployment. |
| **LIM-22** | Lack of Contextual Payload Detections | HIGH | Cannot detect zero-day evasion in encrypted application payloads. | Pair PhantomNet with host-based and application-layer defenses. |
| **LIM-23** | Real-Time Drift Latency | MEDIUM | Windowed PSI computation incurs observation latency. | Set drift batch sizes to match network throughput requirements. |
| **LIM-24** | Heuristic Policy Trade-Offs | HIGH | Default operational cutoffs represent trade-offs between FPR and FNR. | Implement cost-sensitive threshold selection per deployment. |
| **LIM-25** | Continuous Model Maintenance | HIGH | Locally adapted models suffer concept drift over time without updates. | Establish scheduled retraining and automated drift response protocols. |
