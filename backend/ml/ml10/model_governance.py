"""
PhantomNet Phase ML-10: Model Governance, Registry, and Deterministic Rollback
=============================================================================
Manages experimental model lifecycle states (PROMOTE, HOLD, QUARANTINE, ROLLBACK),
immutable artifact hashing, and fail-safe rollback to previous trusted checkpoints.
"""

from enum import Enum
from typing import Dict, List, Any, Optional
import os
import json
import hashlib
import joblib


class ModelLifecycleState(str, Enum):
    EXPERIMENTAL = "EXPERIMENTAL"
    PROMOTE = "PROMOTE"
    HOLD = "HOLD"
    QUARANTINE = "QUARANTINE"
    ROLLBACK = "ROLLBACK"


class ModelRegistryEntry:
    def __init__(
        self,
        model_id: str,
        parent_model_id: Optional[str],
        state: ModelLifecycleState,
        dataset_hash: str,
        training_hash: str,
        feature_schema_version: str,
        calibration_version: str,
        threshold_policy_version: str,
        seed: int,
        metrics: Dict[str, float],
        model_artifact_path: str,
        checksum: str,
        timestamp: str,
        notes: str = ""
    ):
        self.model_id = model_id
        self.parent_model_id = parent_model_id
        self.state = state
        self.dataset_hash = dataset_hash
        self.training_hash = training_hash
        self.feature_schema_version = feature_schema_version
        self.calibration_version = calibration_version
        self.threshold_policy_version = threshold_policy_version
        self.seed = seed
        self.metrics = metrics
        self.model_artifact_path = model_artifact_path
        self.checksum = checksum
        self.timestamp = timestamp
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "parent_model_id": self.parent_model_id,
            "state": self.state.value,
            "dataset_hash": self.dataset_hash,
            "training_hash": self.training_hash,
            "feature_schema_version": self.feature_schema_version,
            "calibration_version": self.calibration_version,
            "threshold_policy_version": self.threshold_policy_version,
            "seed": self.seed,
            "metrics": {k: float(v) for k, v in self.metrics.items()},
            "model_artifact_path": self.model_artifact_path,
            "checksum": self.checksum,
            "timestamp": self.timestamp,
            "notes": self.notes
        }


class ModelGovernanceRegistry:
    """
    Isolated experimental registry for tracking, validating, and rolling back models.
    """

    def __init__(self, registry_file: Optional[str] = None):
        self.registry_file = registry_file
        self.entries: Dict[str, ModelRegistryEntry] = {}
        self.active_model_id: Optional[str] = None
        self.history: List[str] = []

    def register_model(self, entry: ModelRegistryEntry) -> None:
        self.entries[entry.model_id] = entry
        self.history.append(entry.model_id)
        if entry.state == ModelLifecycleState.PROMOTE or self.active_model_id is None:
            self.active_model_id = entry.model_id

    def set_state(self, model_id: str, new_state: ModelLifecycleState, notes: str = "") -> None:
        if model_id not in self.entries:
            raise KeyError(f"Model ID '{model_id}' not found in registry.")
        entry = self.entries[model_id]
        entry.state = new_state
        if notes:
            entry.notes += f" | {notes}"

    def rollback(self, target_model_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Rolls back active model to target_model_id or previous PROMOTE model in history.
        """
        if not self.active_model_id:
            raise RuntimeError("No active model to rollback from.")

        old_active = self.active_model_id
        self.set_state(old_active, ModelLifecycleState.ROLLBACK, notes="Rolled back by governance engine.")

        if target_model_id:
            if target_model_id not in self.entries:
                raise KeyError(f"Target model '{target_model_id}' not found.")
            target_entry = self.entries[target_model_id]
        else:
            # Find most recent prior model with PROMOTE state
            candidates = [
                m_id for m_id in reversed(self.history)
                if m_id != old_active and self.entries[m_id].state in [ModelLifecycleState.PROMOTE, ModelLifecycleState.HOLD]
            ]
            if not candidates:
                raise RuntimeError("No eligible fallback model found in registry history.")
            target_entry = self.entries[candidates[0]]

        self.active_model_id = target_entry.model_id
        target_entry.state = ModelLifecycleState.PROMOTE

        return {
            "action": "ROLLBACK_SUCCESS",
            "previous_active": old_active,
            "new_active": self.active_model_id,
            "restored_checksum": target_entry.checksum,
            "restored_metrics": target_entry.metrics
        }

    def save_registry(self, filepath: str) -> None:
        data = {
            "active_model_id": self.active_model_id,
            "total_registered": len(self.entries),
            "history": self.history,
            "models": {k: v.to_dict() for k, v in self.entries.items()}
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
