"""
PhantomNet Phase ML-10: Deployment Governance Package
=====================================================
Modular, fail-closed deployment-safety reference architecture for the 12D-v1 canonical ML system.
"""

from .schema_gate import SchemaGate, SchemaValidationResult, SchemaSeverity
from .drift_monitor import DistributionDriftMonitor, DriftStatus, DriftSeverity
from .confidence_abstention import ConfidenceAbstentionEngine, AbstentionDecision, ConfidenceState
from .calibration_service import CalibrationService, CalibrationMethod
from .threshold_governor import ThresholdGovernor, PolicyObjective
from .model_governance import ModelGovernanceRegistry, ModelLifecycleState
from .pipeline import DeploymentGovernancePipeline, GovernanceTelemetryDecision

__all__ = [
    "SchemaGate",
    "SchemaValidationResult",
    "SchemaSeverity",
    "DistributionDriftMonitor",
    "DriftStatus",
    "DriftSeverity",
    "ConfidenceAbstentionEngine",
    "AbstentionDecision",
    "ConfidenceState",
    "CalibrationService",
    "CalibrationMethod",
    "ThresholdGovernor",
    "PolicyObjective",
    "ModelGovernanceRegistry",
    "ModelLifecycleState",
    "DeploymentGovernancePipeline",
    "GovernanceTelemetryDecision",
]
