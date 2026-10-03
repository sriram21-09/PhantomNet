# ML-10: Model Governance, Registry & Deterministic Rollback

---

## 1. Executive Summary

Phase ML-10 implements an isolated experimental model governance registry ([model_governance.py](file:///c:/Users/srira/Project/PhantomNet/backend/ml/ml10/model_governance.py)) tracking full lineage metadata, schema versioning, dataset hashes, and deterministic rollback capability.

---

## 2. Model Lifecycle States

1. **`EXPERIMENTAL`**: Initial quarantine state for retrained/adapted models.
2. **`HOLD`**: Validation complete; awaiting security supervisor promotion approval.
3. **`PROMOTE`**: Approved for active evaluation.
4. **`QUARANTINE`**: Flagged due to detected performance degradation, data drift, or corruption.
5. **`ROLLBACK`**: Demoted checkpoint restored to prior trusted state.

---

## 3. Rollback Verification

Rollback was verified by registering an experimental candidate adapted model (`ML10_Adapted_Candidate_NFToN_v1`), setting it to `PROMOTE`, simulating metric degradation, and triggering automated rollback.
- **Previous Active**: `ML10_Adapted_Candidate_NFToN_v1` (Demoted to `ROLLBACK`)
- **Restored Active**: `AttackClassifier_Enhanced_v1.0.0_CANONICAL` (Restored to `PROMOTE`)
- **Restored Checksum**: `7ca8651fca269842d7f0f829a5aba9485453a38fa6263a67c2130ac0c9c66dc2` (Exact 100% SHA-256 match)

The rollback mechanism guarantees zero-downtime, deterministic recovery to verified baseline checkpoints.
