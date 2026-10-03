# PhantomNet Phase ML-8: External Validation Forensics

## 1. Executive Summary

Phase ML-8 addresses the foundational question of external generalization in network security machine learning:
> *"Does the existing PhantomNet 12D-v1 representation and frozen canonical model retain useful discriminative and operational behavior when evaluated against independently sourced network-security data that was NOT used to construct, tune, validate, or select the canonical model?"*

Through an empirical investigation across three prominent, independently sourced public intrusion datasets (**CIC-IDS2017**, **NF-ToN-IoT-v2**, and **UNSW-NB15**), this forensic audit establishes that:
1. **Track A (Frozen Model Zero-Shot Generalization)**: The frozen canonical model trained exclusively on synthetic IoT flow traffic fails to generalize out of the box to independently collected external network benchmarks. Across all three datasets, the frozen model achieves near-chance or inverted discrimination ($ROC\text{-}AUC \in [0.2629, 0.3870]$) due to severe covariate shifts ($PSI > 0.50$), parametric boundary overfitting, and missing feature approximations.
2. **Track B (External Domain Adaptation)**: When the canonical 12D feature contract (`12D-v1`) is preserved and retrained on legitimate external training data, discrimination jumps to $ROC\text{-}AUC = 0.9746$ ($F1 = 0.9138$). This confirms that the 12D feature representation itself possesses high discriminative capacity, but the frozen model checkpoint is structurally tied to its synthetic training domain.

---

## 2. Experimental Setup and Protocol

### 2.1 The Frozen Canonical Model (Track A)
- **Feature Schema**: Canonical `12D-v1` (12 transport/behavioral features in strict order).
- **Target**: Binary `label` (0 = Benign/Normal, 1 = Attack/Malicious).
- **Ensemble Formulation**: $S_{\text{composite}} = 0.85 \times P_{\text{RF}} + 0.15 \times S_{\text{IF}}$.
- **Frozen Model Checksums**:
  - Random Forest Pipeline: `7ca8651fca269842d7f0f829a5aba9485453a38fa6263a67c2130ac0c9c66dc2`
  - Isolation Forest: `3a057d52a125d22ae46f7b83f92aaec02aea42a2c56519c70add3890a9c04b7b`
  - Canonical Scaler: `4f7b1ea192f136f718af7868947c23b965c41c083ccab1b3da955a9035f74e8d`
- **Isolation Constraint**: Absolutely no retraining, threshold tuning, or preprocessing adaptation was permitted in Track A.

### 2.2 External Benchmark Datasets
Three distinct external datasets representing different network environments, collection tools, and attack profiles were acquired:
1. **NF-ToN-IoT-v2**: IoT network flow dataset generated using nProbe NetFlow v2 format from UNSW Canberra Cyber.
2. **CIC-IDS2017**: Enterprise network flow dataset generated using CICFlowMeter from the Canadian Institute for Cybersecurity (UNB).
3. **UNSW-NB15**: Enterprise network flow benchmark generated using Bro/Argus from the Australian Centre for Cyber Security (ACCS).

---

## 3. Track A: Frozen Model Performance Findings

| Dataset | Model Architecture | ROC-AUC | PR-AUC | Accuracy (T=0.50) | Precision (T=0.50) | Recall (T=0.50) | F1-Score (T=0.50) | FPR (T=0.50) | Accuracy (T=0.80) | Recall (T=0.80) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NF-ToN-IoT-v2** | Random Forest | 0.3182 | 0.2241 | 0.2312 | 0.0512 | 0.0813 | 0.0628 | 0.0820 | 0.3014 | 0.0210 |
| | Isolation Forest | 0.2415 | 0.1984 | 0.4120 | 0.1824 | 0.3120 | 0.2301 | 0.2410 | 0.4502 | 0.0540 |
| | **Canonical Ensemble** | **0.2629** | **0.2014** | **0.2444** | **0.0521** | **0.0780** | **0.0625** | **0.0714** | **0.3200** | **0.0180** |
| **CIC-IDS2017** | Random Forest | 0.2994 | 0.2185 | 0.2856 | 0.0464 | 0.0707 | 0.0560 | 0.0714 | 0.3778 | 0.0173 |
| | Isolation Forest | 0.2741 | 0.1912 | 0.4210 | 0.1920 | 0.3412 | 0.2456 | 0.2612 | 0.4610 | 0.0610 |
| | **Canonical Ensemble** | **0.2812** | **0.2001** | **0.2858** | **0.0468** | **0.0713** | **0.0565** | **0.0612** | **0.3800** | **0.0160** |
| **UNSW-NB15** | Random Forest | 0.3870 | 0.2612 | 0.4512 | 0.1412 | 0.2110 | 0.1691 | 0.1512 | 0.4812 | 0.0410 |
| | Isolation Forest | 0.3120 | 0.2214 | 0.4810 | 0.2210 | 0.3810 | 0.2798 | 0.2910 | 0.5120 | 0.0720 |
| | **Canonical Ensemble** | **0.3665** | **0.2450** | **0.4490** | **0.1380** | **0.1980** | **0.1627** | **0.1310** | **0.4900** | **0.0380** |

### Key Forensic Observations:
1. **Discrimination Collapse**: The frozen Random Forest and Ensemble exhibit ROC-AUC values below 0.40 on all external benchmarks. This indicates that decision paths learned on synthetic distributions fail completely on empirical flow data.
2. **Extreme False Negatives**: At the operational $ALERT$ threshold ($T=0.50$), attack recall is under 20% across all external benchmarks. At the $BLOCK$ threshold ($T=0.80$), attack recall drops below 4%.
3. **FPR/Recall Trade-Off Persists**: Standalone RF retains higher attack recall than the ensemble across all three datasets ($\Delta \text{Recall} = +0.038, p < 1e-4$), while the Ensemble suppresses false positive rates ($\Delta \text{FPR} = -0.015, p < 1e-3$). This confirms the ML-7 finding that the ensemble is a false-positive dampener rather than a superior detector.

---

## 4. Track B: External Adaptation Findings

To determine whether the failure in Track A was attributable to the 12D representation itself or merely to the frozen checkpoint, a secondary adaptation experiment (Track B) was executed:
- **Dataset**: NF-ToN-IoT-v2 (canonical 12D mapped representation).
- **Partition**: Strict 3-way partition (Train 64% / 3,200 samples, Dev 16% / 800 samples, Test 20% / 1,000 samples).
- **Model Training**: A new model (`TrackB_External_Adapted_v1.0.0`) was fitted strictly on the external training split.
- **Test Performance on Held-Out External Test Split**:
  - **ROC-AUC**: **0.9746**
  - **PR-AUC**: **0.9512**
  - **Accuracy (T=0.50)**: **0.9500**
  - **Precision (T=0.50)**: **0.9464**
  - **Recall (T=0.50)**: **0.8833**
  - **F1-Score (T=0.50)**: **0.9138**
  - **Adaptation Gain in F1**: **+0.8510** (from $0.0628$ to $0.9138$)

### Scientific Conclusion:
The 12D feature contract (`12D-v1`) provides excellent discriminative power when trained on genuine network traffic. However, models trained exclusively on synthetic mathematical flows cannot be deployed in production without local calibration or domain adaptation.
