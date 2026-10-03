# ML-10: Temporal Streaming & Adversarial Stress Forensics

---

## 1. Executive Summary

Phase ML-10 evaluates temporal stream segmentation and synthetic adversarial feature perturbations to characterize model degradation across non-stationary traffic regimes.

---

## 2. Streaming Window Partition Performance

| Window Partition | Sample Index Range | Pre-Adaptation AUC | Post-Adaptation AUC | Detection Delay (Samples) |
| :--- | :---: | :---: | :---: | :---: |
| **Early Window** | `[0 : 1000]` | 0.984 | 0.984 | 0 |
| **Middle Window** | `[1000 : 2000]` | 0.981 | 0.981 | 0 |
| **Late Window** | `[2000 : 3200]` | 0.979 | 0.979 | 0 |
| **Abrupt Domain Transition** | `[3200 : 4000]` | 0.312 | 0.974 | 18 |

---

## 3. Adversarial Feature Perturbations (SYNTHETIC ROBUSTNESS EVIDENCE ONLY)

Controlled perturbations of canonical features were evaluated against the synthetic test set:

| Perturbation Mode | Feature Targeted | Perturbation Details | Resulting ROC-AUC | AUC Drop ($\Delta$) |
| :--- | :--- | :--- | :---: | :---: |
| **Baseline Clean** | None | Pristine 12D telemetry | 0.8355 | 0.0000 |
| **Timing Dilation (10x)** | `inter_arrival_mean` | Duration scaled by 10x | 0.8355 | 0.0000 |
| **Timing Compression (0.1x)** | `inter_arrival_mean` | Duration scaled by 0.1x | 0.8355 | 0.0000 |
| **Packet Size Bloat (5x)** | `packet_length` | Packet length scaled by 5x | 0.8087 | -0.0269 |
| **Rate Throttling (0.1x)** | `event_rate_1m` | Event rate scaled by 0.1x | 0.8355 | 0.0000 |
| **Port Randomization** | `dst_port_class` | Randomize port assignment | 0.6721 | -0.1634 |
| **Multi-Feature Coordinated** | Timing + Size + Rate | Combined perturbation | 0.8096 | -0.0260 |

---

## 4. Key Limitations

1. **Port Sensitivity**: Port randomization causes the largest degradation ($\Delta = -0.1634$, $p = 0.0011$), demonstrating heavy reliance on port encodings for synthetic intrusion classification.
2. **Synthetic Boundary**: These results constitute synthetic perturbation evidence only; real-world polymorphic malware behavior may exploit unmodeled dimensions.
