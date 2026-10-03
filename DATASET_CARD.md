# PhantomNet Dataset Card & Forensic Integrity Audit

**Document:** Dataset Card & Provenance Integrity Audit  
**Author:** Lead ML & Reproducibility Auditor  
**Date:** 2026-10-01  
**Project:** PhantomNet Threat Intelligence & Deception Framework  
**Status:** FORENSIC AUDIT COMPLETE — REVISION REQUIRED  

---

## 1. Dataset Inventory & Provenance Overview

The PhantomNet repository houses five primary datasets across different directories, representing various development and experimental phases. Every dataset was audited, hashed via SHA-256, and analyzed for class balance, duplicate rows, missing values, and feature-label leakage.

| Dataset Identifier | File Path | SHA-256 Checksum | Dimensions (Rows × Cols) | Class Balance (Benign : Malicious) | Generator / Origin | Leakage Status |
|---|---|---|---|---|---|---|
| **DS-01 (Enhanced Behavioral)** | `backend/ml/datasets/labeled_events_v2_enhanced.csv` | `a2e22e7cbe8a5c6c36a14bcab8996e25e99f46dad445cc10afef5e68bc9a449e` | 5,000 × 13 | 3,488 (69.8%) : 1,512 (30.2%) | `backend/ml/update_dataset.py` | **CRITICAL LEAKAGE** (3 features with 100% separation) |
| **DS-02 (Unified 15D Socket)** | `backend/ml/evaluation_output/labeled_events_15d_unified.csv` | `432fb772ffc4ae6f1165bc04d60fcad7b4b73b53f6834d98a0cbe27ad15cce83` | 5,000 × 16 | 3,500 (70.0%) : 1,500 (30.0%) | `backend/scripts/unified_evaluation.py` | **CRITICAL LEAKAGE** (`malicious_flag_ratio` 100% separation) |
| **DS-03 (Legacy Training)** | `data/training_dataset.csv` | `6df5c68f2390beee32938a49ba3f64ef28972f3e84bf9a2e6df5b9e0f63b2dc9` | 232 × 16 | 12 (5.2%) : 220 (94.8%) | `backend/ml/feature_extractor.py` on raw logs | **CRITICAL LEAKAGE** (`threat_score`, `session_duration` 100% sep) |
| **DS-04 (Ground Truth Events)** | `data/ground_truth.csv` | `a3f5f3e9cbffbb56e729a8f4c227bfdd1082522c06900f089606eaae5ca0d8fb` | 200 × 10 | 131 (65.5%) : 69 (34.5%) | `scripts/generate_ground_truth.py` | **TARGET LEAKAGE** (Disjoint threat scores in generation) |
| **DS-05 (DBSCAN Benchmark)** | `experiments/results/dbscan_normalization/controlled_experiment_dataset.csv` | `f59972301c23a1a97db2fc78403d9d48b7beff92723c2a688b1fc5e6b1897e74` | 100 × 29 | Multiclass (4 campaigns + noise + benign) | `experiments/run_dbscan_normalization_experiment.py` | **BENIGN** (Clustering benchmark, unscaled issues) |

---

## 2. Forensic Leakage & Class Separability Deep-Dive

### 2.1 Dataset DS-01: `labeled_events_v2_enhanced.csv` (The "100% Accuracy" Dataset)
- **Generator Mechanics:** `backend/ml/update_dataset.py:L14-32`
  ```python
  is_attack = 1 if np.random.random() > 0.7 else 0
  if is_attack:
      raw_data = np.random.choice([
          "cat /etc/passwd",
          "../../etc/shadow",
          "admin' OR '1'='1",
          "rm -rf /",
          "ls -la; id; whoami"
      ])
      event_type = "login_failed" if np.random.random() > 0.5 else "command_execution"
  else:
      raw_data = "GET /index.html HTTP/1.1"
      event_type = "web_access"
  ```
- **Separation Analysis:**
  Because every single benign packet consists of the exact string `"GET /index.html HTTP/1.1"`:
  1. `avg_command_length`: Exactly `24.000` for all 3,488 benign samples ($\sigma = 0.0000$). Malicious samples have average command lengths ranging strictly between `4.667` and `16.000`. **Overlap: False.** Single-feature accuracy: **100.0%**.
  2. `payload_entropy`: Exactly `4.0535` for all 3,488 benign samples ($\sigma = 0.0000$). Malicious samples have entropies ranging strictly between `2.5000` and `3.4613`. **Overlap: False.** Single-feature accuracy: **100.0%**.
  3. `payload_to_cmd_ratio`: Exactly `12.000` for all 3,488 benign samples ($\sigma = 0.0000$). Malicious samples range from `4.000` to `8.000`. **Overlap: False.** Single-feature accuracy: **100.0%**.
- **Research Impact:** The reported 100.0% accuracy in `experiments/reproduce_paper.py` and `paper_metrics.json` is a direct result of zero variance in the benign class for these three features. It provides no proof of real-world intrusion detection capability.

### 2.2 Dataset DS-02: `labeled_events_15d_unified.csv` (The "96.9% Accuracy" Dataset)
- **Generator Mechanics:** `backend/scripts/unified_evaluation.py`
- **Leakage Analysis:**
  - `malicious_flag_ratio`: For benign samples, the value is strictly `0.000`. For malicious samples, the value is `1.000` (or $>0.0$).
  - Overlap: **False**. Single-feature accuracy: **100.0%**.
  - `threat_score`: Synthetically assigned based on the ground truth label.
- **Research Impact:** Evaluated in `MASTER_FINAL_PROJECT_REPORT.md` (Accuracy=96.90%, F1=0.9472). The classifier learned to identify whether the input dictionary contained `malicious_flag_ratio=1.0` and a pre-assigned high `threat_score`.

### 2.3 Dataset DS-03: `data/training_dataset.csv` (Legacy Training Dataset)
- **Sample Count:** 232 valid samples (after header).
- **Class Imbalance:** 220 malicious samples (94.8%) vs. 12 benign samples (5.2%).
- **Leakage Analysis:**
  - Rows 1–12 (the only benign samples) are sequential event count increments (`1.0, 2.0, ... 12.0`) with `threat_score=0.0`, `malicious_flag_ratio=0.0`, and `session_duration=0.001`.
  - Rows 13–232 (all malicious samples) suddenly exhibit `threat_score=0.6`, `time_of_day_deviation=1`, and `session_duration > 627,000`.
  - Single-feature accuracy on `threat_score`: **100.0%**. Single-feature accuracy on `time_of_day_deviation`: **100.0%**. Single-feature accuracy on `session_duration_estimate`: **100.0%**.

### 2.4 Dataset DS-04: `data/ground_truth.csv`
- **Generator Mechanics:** `scripts/generate_ground_truth.py:L28-64`
  - Benign generator: `threat_score = random.uniform(0.0, 0.3)`
  - Malicious generator: `threat_score = random.uniform(0.4, 1.0)`
- **Separation Analysis:** The minimum malicious threat score ($0.40$) is strictly greater than the maximum benign threat score ($0.30$). Single-feature thresholding at $0.35$ achieves **99.0%** classification accuracy.

---

## 3. Train/Test Contamination & Split Verification

1. **IP Contamination:** In `update_dataset.py`, attacker and benign IPs are sampled from small IP pools (`192.168.1.1` to `192.168.1.50`). A standard random split places the same IP address in both train and test splits, causing host-level memorization rather than generalized behavioral learning.
2. **Temporal Contamination:** `update_dataset.py` assigns random timestamps within a 10,000-minute window without enforcing a chronological train-before-test split.
3. **Feature Leakage Across Folds:** Feature extractors maintaining stateful accumulators (`self.ip_events`, `self.ip_malicious_flags`) retain state across the entire dataset without re-initializing between training and testing splits.

---

## 4. Remediation Specification for Benchmark Dataset (DS-REMED)

To support defensible, peer-reviewable research, a remediated benchmark dataset must satisfy the following scientific requirements:

1. **Zero Target / Label Leakage:**
   - Eliminate `threat_score`, `malicious_flag_ratio`, and explicit label feedback from the feature set.
   - All features must derive strictly from raw socket packet observables and historical telemetry known prior to prediction.
2. **Realistic Benign Traffic Distributions:**
   - Multi-path HTTP requests (`GET /`, `GET /api/v1/health`, `POST /login`, `GET /assets/style.css`, etc.) with varying User-Agents and realistic payload lengths (64 to 2,048 bytes).
   - Natural entropy distributions for benign payloads ($H \in [2.5, 4.8]$ bits/byte) that overlap realistically with attack payloads.
   - Legitimate SSH connection attempts, normal keep-alives, and benign administrative commands.
3. **Diverse Attack Distributions:**
   - Multi-stage attack categories:
     - Remote code execution / command injection.
     - SQL injection (error-based, union-based, blind).
     - Directory traversal / local file inclusion.
     - SSH brute force (distributed and single-source).
     - Port scans (SYN, TCP connect, fragmented).
     - Protocol evasion and anomalous packet sizes.
4. **Realistic Feature Overlap:**
   - No single feature may achieve $>85\%$ classification accuracy on its own.
   - Enforce overlapping class distributions requiring multi-dimensional non-linear feature interactions for accurate classification.
5. **Rigorous Partitioning:**
   - Strict temporal splitting (train on $T_0 \to T_1$, test on $T_1 \to T_2$) or disjoint IP splitting (stratified across separate CIDR blocks) to prevent identity leakage.
   - Target size: $N \ge 5,000$ to $10,000$ samples with a balanced 70:30 or 80:20 benign-to-malicious distribution.
