"""
PhantomNet Phase ML-10: 12D Schema and Feature-Quality Gate
===========================================================
Validates input telemetry against the 12D-v1 canonical feature contract before any downstream model ingestion.
Fails closed upon critical schema violations, NaN/inf presence, or invalid value ranges.
"""

from enum import Enum
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import pandas as pd

from backend.ml.config.feature_schema import CANONICAL_FEATURE_NAMES, CANONICAL_FEATURE_COUNT


class SchemaSeverity(str, Enum):
    VALID = "VALID"
    WARNING = "WARNING"
    SEVERE = "SEVERE"
    REJECT = "REJECT"


class SchemaValidationResult:
    def __init__(
        self,
        severity: SchemaSeverity,
        is_admissible: bool,
        messages: List[str],
        sanitized_vector: Optional[np.ndarray] = None,
        feature_count: int = 0
    ):
        self.severity = severity
        self.is_admissible = is_admissible
        self.messages = messages
        self.sanitized_vector = sanitized_vector
        self.feature_count = feature_count

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "is_admissible": self.is_admissible,
            "messages": self.messages,
            "feature_count": self.feature_count,
            "has_sanitized_vector": self.sanitized_vector is not None
        }


# Canonical domain bounds and constraints for the 12D-v1 contract
FEATURE_BOUNDS = {
    "packet_length": (0.0, 65535.0, False),            # (min, max, allow_negative)
    "protocol_encoding": (0.0, 255.0, False),          # IANA protocol numbers
    "dst_port_class": (0.0, 10.0, False),              # Categorical port encoding class
    "src_port_ephemeral": (0.0, 1.0, False),           # Binary 0/1 indicator
    "event_rate_1m": (0.0, 1e9, False),                # Flow rate per minute
    "burst_rate_10s": (0.0, 1e9, False),               # Burst flow rate per 10s
    "inter_arrival_mean": (0.0, 1e7, False),           # Flow timing inter-arrival mean
    "inter_arrival_std": (0.0, 1e7, False),            # Flow timing inter-arrival std
    "packet_size_variance": (0.0, 1e12, False),        # Packet size variance
    "payload_entropy": (0.0, 8.0, False),              # Shannon entropy bounded in [0, 8]
    "unique_dst_ips": (0.0, 1e9, False),               # Distinct destination count
    "unique_dst_ports": (0.0, 65535.0, False),         # Distinct port count
}


class SchemaGate:
    """
    Validates single records, numpy vectors, or pandas DataFrames against 12D-v1 canonical contract.
    """

    def __init__(self, strict_mode: bool = True):
        self.strict_mode = strict_mode
        self.expected_features = list(CANONICAL_FEATURE_NAMES)
        self.expected_dim = CANONICAL_FEATURE_COUNT

    def validate_record(self, record: Any) -> SchemaValidationResult:
        """
        Validates a single record (dict, list, 1D array, or 1-row DataFrame).
        """
        messages = []
        severity = SchemaSeverity.VALID

        # Case 1: Dict input with feature names
        if isinstance(record, dict):
            keys = list(record.keys())
            missing = [f for f in self.expected_features if f not in record]
            extra = [k for k in keys if k not in self.expected_features]

            if missing:
                return SchemaValidationResult(
                    severity=SchemaSeverity.REJECT,
                    is_admissible=False,
                    messages=[f"Schema rejection: Missing mandatory 12D canonical features: {missing}"],
                    feature_count=len(keys)
                )

            if extra:
                messages.append(f"Schema warning: Input contains {len(extra)} non-canonical extra fields: {extra}")
                severity = SchemaSeverity.WARNING

            # Extract vector in canonical order
            try:
                raw_vec = np.array([float(record[f]) for f in self.expected_features], dtype=np.float64)
            except (ValueError, TypeError) as e:
                return SchemaValidationResult(
                    severity=SchemaSeverity.REJECT,
                    is_admissible=False,
                    messages=[f"Schema rejection: Non-numeric feature value encountered: {e}"],
                    feature_count=len(keys)
                )

        # Case 2: 1D array or list input
        elif isinstance(record, (list, np.ndarray, pd.Series)):
            raw_vec = np.asarray(record, dtype=np.float64).flatten()
            if len(raw_vec) != self.expected_dim:
                return SchemaValidationResult(
                    severity=SchemaSeverity.REJECT,
                    is_admissible=False,
                    messages=[f"Schema rejection: Expected {self.expected_dim} dimensions, received {len(raw_vec)}"],
                    feature_count=len(raw_vec)
                )

        elif isinstance(record, pd.DataFrame):
            if record.shape[0] != 1:
                return self.validate_batch(record)[0]
            row_dict = record.iloc[0].to_dict()
            return self.validate_record(row_dict)

        else:
            return SchemaValidationResult(
                severity=SchemaSeverity.REJECT,
                is_admissible=False,
                messages=[f"Schema rejection: Unsupported record type: {type(record)}"],
                feature_count=0
            )

        # Check for NaN and Infs
        if np.isnan(raw_vec).any():
            return SchemaValidationResult(
                severity=SchemaSeverity.REJECT,
                is_admissible=False,
                messages=["Schema rejection: Vector contains NaN values."],
                feature_count=len(raw_vec)
            )

        if np.isinf(raw_vec).any():
            return SchemaValidationResult(
                severity=SchemaSeverity.REJECT,
                is_admissible=False,
                messages=["Schema rejection: Vector contains infinite (+/- inf) values."],
                feature_count=len(raw_vec)
            )

        # Check value constraints & boundaries
        sanitized_vec = raw_vec.copy()
        for idx, feat_name in enumerate(self.expected_features):
            val = sanitized_vec[idx]
            min_val, max_val, allow_neg = FEATURE_BOUNDS[feat_name]

            if not allow_neg and val < 0.0:
                return SchemaValidationResult(
                    severity=SchemaSeverity.REJECT,
                    is_admissible=False,
                    messages=[f"Schema rejection: Feature '{feat_name}' has impossible negative value: {val}"],
                    feature_count=len(raw_vec)
                )

            if val > max_val:
                messages.append(f"Outlier warning: Feature '{feat_name}' exceeds expected maximum ({val} > {max_val})")
                if severity == SchemaSeverity.VALID:
                    severity = SchemaSeverity.WARNING

        # Check for degenerate zero-filled telemetry
        if np.all(sanitized_vec == 0.0):
            messages.append("Telemetry warning: Input vector is entirely zero-filled.")
            if severity == SchemaSeverity.VALID:
                severity = SchemaSeverity.WARNING

        is_admissible = severity != SchemaSeverity.REJECT
        return SchemaValidationResult(
            severity=severity,
            is_admissible=is_admissible,
            messages=messages,
            sanitized_vector=sanitized_vec,
            feature_count=len(sanitized_vec)
        )

    def validate_batch(self, df: pd.DataFrame) -> Tuple[List[SchemaValidationResult], np.ndarray, np.ndarray]:
        """
        Validates an entire batch/DataFrame of flow telemetry.
        Returns:
            - results: List of SchemaValidationResult
            - valid_mask: Boolean array indicating admissible rows
            - clean_matrix: Clean (N_valid, 12) numpy matrix
        """
        missing_cols = [c for c in self.expected_features if c not in df.columns]
        if missing_cols:
            reject_res = SchemaValidationResult(
                severity=SchemaSeverity.REJECT,
                is_admissible=False,
                messages=[f"Batch schema rejection: Missing required columns: {missing_cols}"],
                feature_count=len(df.columns)
            )
            return [reject_res] * len(df), np.zeros(len(df), dtype=bool), np.empty((0, 12))

        matrix = df[self.expected_features].to_numpy(dtype=np.float64)
        n_rows = matrix.shape[0]
        results = []
        valid_mask = np.ones(n_rows, dtype=bool)

        for i in range(n_rows):
            row_vec = matrix[i]
            res = self.validate_record(row_vec)
            results.append(res)
            if not res.is_admissible:
                valid_mask[i] = False

        clean_matrix = matrix[valid_mask] if np.any(valid_mask) else np.empty((0, 12))
        return results, valid_mask, clean_matrix
