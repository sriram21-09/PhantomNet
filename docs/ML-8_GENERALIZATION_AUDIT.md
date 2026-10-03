# PhantomNet Phase ML-8: Cross-Dataset Generalization Audit

## 1. Executive Scientific Verdict

The central scientific conclusion of Phase ML-8 is:
> **The frozen PhantomNet canonical model checkpoint does NOT generalize out-of-the-box to independently collected external network intrusion benchmarks.**

Across CIC-IDS2017, NF-ToN-IoT-v2, and UNSW-NB15, the frozen canonical model exhibits severe performance degradation ($ROC\text{-}AUC < 0.40, F1 < 0.20$), effectively collapsing to near-chance discrimination. 

However, this failure is attributable to **domain and covariate shift** rather than a failure of the **feature representation**:
- When the identical 12D schema (`12D-v1`) is retrained on legitimate external network traffic in Track B, discrimination rebounds to **$ROC\text{-}AUC = 0.9746$** and **$F1 = 0.9138$**.

---

## 2. Quantitative Root Causes of Zero-Shot Generalization Failure

### 2.1 Severe Covariate Shift ($PSI > 0.50$)
The Population Stability Index (PSI) computed against the canonical training distribution exceeds the severe shift threshold ($0.25$) across all three external benchmarks:
- **NF-ToN-IoT-v2**: Mean $PSI = 0.742$
- **CIC-IDS2017**: Mean $PSI = 0.814$
- **UNSW-NB15**: Mean $PSI = 0.685$

The greatest divergences occur in:
1. `event_rate_1m` and `burst_rate_10s`: Real-world volumetric flooding in CIC-IDS2017 DDoS generates thousands of packets per second, far exceeding the synthetic training range ($[1, 65]$ packets/minute).
2. `inter_arrival_mean`: Network testbed delays exhibit multi-modal distributions that confound decision trees trained on unimodal Poisson/Exponential arrivals.

### 2.2 Decision Boundary Overfitting on Synthetic Distributions
Synthetic flow generators use idealized parametric mathematical distributions (Gamma, Poisson, Lognormal). Supervised decision trees identify split thresholds that exploit narrow parametric density troughs. When exposed to empirical network traffic with non-stationary background noise and hardware latency jitters, these split criteria fail catastrophically.

### 2.3 Absence of External Payload Entropy Telemetry
Because public flow datasets omit raw packet payloads, `payload_entropy` had to be approximated using the empirical prior median ($3.724$). This zeroed out the discriminative contribution of a key feature, further degrading model confidence.

---

## 3. Implications for Academic Publication & Deployment

1. **Retraction of Broad Generalization Claims**: Any claim that PhantomNet's models "generalize across arbitrary enterprise or IoT networks without adaptation" is empirically false and must be formally retracted from publication manuscripts.
2. **Mandatory Domain Adaptation Directive**: PhantomNet cannot be deployed as a static plug-and-play binary for network taps. Operational deployment requires local baseline training or transfer adaptation to align feature scales with the target environment.
3. **Validation of the 12D Feature Contract**: The success of Track B ($ROC\text{-}AUC = 0.9746$) demonstrates that transport-layer flow summaries remain a highly effective, privacy-preserving representation for network intrusion detection when properly fitted.
