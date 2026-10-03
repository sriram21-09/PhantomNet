# ML-10: Baseline Forensics & Environment Verification

---

## 1. Executive Overview

Phase ML-10 establishes a formal deployment-safety and governance framework around the canonical 12D-v1 machine learning subsystem. Prior to any experimental execution, the baseline repository state, environment dependencies, and cryptographic checksums of all protected artifacts were verified against historical baselines established in ML-1 through ML-9.

---

## 2. Git & Working Tree State

- **Branch**: `fix/full-codebase-audit-remediation`
- **Baseline Commit SHA**: `686e880a240a671390e68eb42f24ece21156c1f2`
- **Working Tree Integrity**: Isolated to `backend/ml/ml10/`, `scripts/`, `tests/experiments/`, `experiments/results/`, and `docs/`.

---

## 3. Environment Manifest

| Component | Version / Specification |
| :--- | :--- |
| **Python** | 3.11.9 (64-bit AMD64) |
| **Operating System** | Windows 10 (Build 26300) |
| **scikit-learn** | 1.8.0 |
| **scipy** | 1.16.3 |
| **numpy** | 2.3.5 |
| **pandas** | 2.3.3 |
| **joblib** | 1.5.3 |
| **pytest** | 9.0.2 |

---

## 4. Protected Canonical Artifact Checksums

Every protected artifact has remained strictly unmodified across Phase ML-10:

```json
{
  "canonical_dataset": {
    "path": "data/remediated_dataset_v3.csv",
    "sha256": "390f653966410e70a386ffbfaf6ab381ff9e647a2c4da179a2ad37d46d7bb363",
    "status": "VERIFIED_BITWISE_IDENTICAL"
  },
  "canonical_rf": {
    "path": "ml_models/registry/AttackClassifier_Enhanced_v1.0.0.pkl",
    "sha256": "7ca8651fca269842d7f0f829a5aba9485453a38fa6263a67c2130ac0c9c66dc2",
    "status": "VERIFIED_BITWISE_IDENTICAL"
  },
  "canonical_if": {
    "path": "ml_models/iforest_baseline.pkl",
    "sha256": "3a057d52a125d22ae46f7b83f92aaec02aea42a2c56519c70add3890a9c04b7b",
    "status": "VERIFIED_BITWISE_IDENTICAL"
  },
  "canonical_scaler": {
    "path": "ml_models/registry/scaler.pkl",
    "sha256": "4f7b1ea192f136f718af7868947c23b965c41c083ccab1b3da955a9035f74e8d",
    "status": "VERIFIED_BITWISE_IDENTICAL"
  },
  "feature_schema": {
    "path": "backend/ml/config/feature_schema.py",
    "sha256": "6484bbf27b7bc918133133ba48170f8c5e036ddac31f23b5bb6b6db8e6258a2e",
    "status": "VERIFIED_BITWISE_IDENTICAL"
  },
  "thresholds": {
    "path": "backend/ml/config/thresholds.py",
    "sha256": "a3353927332ecf5bee332cff3c3fba92ee6587850a4d895c4c8bb26c1db7d8cd",
    "status": "VERIFIED_BITWISE_IDENTICAL"
  }
}
```

---

## 5. Summary & Verification

All pre-conditions for Phase ML-10 execution were met without discrepancies. All new models and evaluation files are strictly quarantined under `backend/ml/ml10/` and `ml_models/experimental/ml10/`.
