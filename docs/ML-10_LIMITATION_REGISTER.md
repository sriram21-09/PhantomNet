# ML-10: Scientific Limitation Register

---

## 1. Executive Summary

This document maintains the cumulative scientific limitation register for the PhantomNet ML subsystem across Phases ML-1 through ML-10. No historical limitation has been erased or weakened.

---

## 2. Register of Documented Limitations

### LIM-ML10-01: Frozen Zero-Shot Cross-Domain Generalization Collapse
- **Severity**: `CRITICAL`
- **Empirical Evidence**: ROC-AUC collapses from $0.982$ on in-domain synthetic traffic to $0.296 \dots 0.350$ across NF-ToN-IoT, CIC-IDS2017, and UNSW-NB15 under severe distribution shift ($\text{PSI} = 1.58 \dots 2.62$).
- **Impact**: Deploying the frozen synthetic model out-of-the-box to external networks without local adaptation causes catastrophic false negatives.
- **Mitigation**: Automated drift monitoring triggers quarantine; mandatory supervised site-specific adaptation ($N = 160 \dots 320$).
- **Status**: `DOCUMENTED_AND_BOUNDED`

### LIM-ML10-02: Non-Bayesian Ordinality of Composite Threat Score
- **Severity**: `HIGH`
- **Empirical Evidence**: Composite score $S = 0.85 \cdot P_{\text{RF}} + 0.15 \cdot S_{\text{IF}}$ yields uncalibrated $\text{ECE} > 0.52$ under cross-domain shift.
- **Impact**: Treating $S$ as a Bayesian posterior probability leads to severe miscalibration in risk engines.
- **Mitigation**: Post-hoc Platt Sigmoid and Isotonic Regression layers fitted strictly on development data reduce $\text{ECE} \le 0.036$.
- **Status**: `RESOLVED_VIA_CALIBRATION_SERVICE`

### LIM-ML10-03: Historical Threshold Provenance Unrecoverability
- **Severity**: `MEDIUM`
- **Empirical Evidence**: Canonical thresholds `ALERT = 0.50` and `BLOCK = 0.80` lack historical optimization records in early prototype commits.
- **Impact**: Thresholds represent policy heuristics rather than empirical bayes-risk optimal values.
- **Mitigation**: Formally flagged with `NO_PRESERVED_PROVENANCE`; threshold governor provides site-specific dev optimization.
- **Status**: `FORMALLY_FLAGGED`

### LIM-ML10-04: Vulnerability to Unsupervised Poisoning
- **Severity**: `HIGH`
- **Empirical Evidence**: 30% label contamination in adaptation training degrades F1 by up to 9.1% ($p = 0.00021$).
- **Impact**: Unsupervised self-training on live traffic is vulnerable to adversarial manipulation.
- **Mitigation**: Autonomous self-training prohibited; local adaptation restricted to human-curated batches.
- **Status**: `GOVERNED_BY_POLICY`

### LIM-ML10-05: Software Throughput vs Physical Line-Rate Enforcement
- **Severity**: `MEDIUM`
- **Empirical Evidence**: Python deployment governance pipeline operates at ~14-20 req/s in software profiling.
- **Impact**: Cannot enforce inline wire-speed packet filtering on multi-gigabit interfaces without kernel/hardware acceleration.
- **Mitigation**: All wire-speed enforcement claims explicitly prohibited in publications.
- **Status**: `DOCUMENTED`
