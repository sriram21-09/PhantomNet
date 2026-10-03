"""
PhantomNet Authoritative 12-Dimensional Feature Contract (Phase ML-3)
====================================================================
Defines the single source of truth for:
- Canonical feature names, ordering, and count (12 continuous/discrete features)
- Canonical supervised target name ("label")
- Machine-readable schema version ("12D-v1")
- Validation boundaries enforcing schema adherence and rejecting positional truncation
"""

from typing import Tuple, List, Dict, Any, Union, Optional
import numpy as np
import pandas as pd

# ============================================================================
# 1. CANONICAL FEATURE SPECIFICATION
# ============================================================================

SCHEMA_VERSION: str = "12D-v1"

CANONICAL_FEATURE_NAMES: Tuple[str, ...] = (
    "packet_length",
    "protocol_encoding",
    "dst_port_class",
    "src_port_ephemeral",
    "event_rate_1m",
    "burst_rate_10s",
    "inter_arrival_mean",
    "inter_arrival_std",
    "packet_size_variance",
    "payload_entropy",
    "unique_dst_ips",
    "unique_dst_ports",
)

CANONICAL_FEATURE_COUNT: int = len(CANONICAL_FEATURE_NAMES)
assert CANONICAL_FEATURE_COUNT == 12, f"Expected 12 canonical features, found {CANONICAL_FEATURE_COUNT}"

CANONICAL_TARGET_NAME: str = "label"

# Disallowed leakage / downstream features
PROHIBITED_LEAKAGE_COLUMNS: Tuple[str, ...] = (
    "is_malicious",
    "threat_score",
    "malicious_flag_ratio",
    "attack_type",
    "honeypot_type",
    "composite_score",
)

# Known incompatible dimensionalities from historical prototypes
KNOWN_INCOMPATIBLE_DIMENSIONS: Tuple[int, ...] = (6, 13, 15, 32)


# ============================================================================
# 2. VALIDATION BOUNDARIES
# ============================================================================

def validate_feature_vector(
    vector: Union[np.ndarray, List[float], pd.DataFrame, pd.Series],
    expected_dim: int = CANONICAL_FEATURE_COUNT,
) -> np.ndarray:
    """
    Validates that a feature vector adheres to the canonical 12D schema.

    Enforces:
    1. Exact dimensionality (default: 12)
    2. Column names & exact ordering if passed as DataFrame/Series
    3. Numeric dtype compatibility
    4. Finite values (no NaN, +Inf, -Inf)
    5. Zero positional truncation (rejects attempts to truncate wider vectors)

    Returns:
        np.ndarray: Validated 2D numerical array of shape (N, 12).

    Raises:
        ValueError: If dimensionality, ordering, or values violate the contract.
        TypeError: If input cannot be converted to numeric floats.
    """
    # 1. Validate DataFrame or Series schema
    if isinstance(vector, pd.DataFrame):
        actual_cols = list(vector.columns)
        if len(actual_cols) != expected_dim:
            raise ValueError(
                f"Feature schema violation: DataFrame has {len(actual_cols)} columns, expected {expected_dim}. "
                f"Detected columns: {actual_cols}. Positional truncation is forbidden."
            )
        if tuple(actual_cols) != CANONICAL_FEATURE_NAMES:
            raise ValueError(
                f"Feature ordering/naming mismatch: DataFrame columns do not match canonical sequence.\n"
                f"Expected: {list(CANONICAL_FEATURE_NAMES)}\n"
                f"Actual:   {actual_cols}"
            )
        arr = vector.to_numpy(dtype=np.float64)

    elif isinstance(vector, pd.Series):
        if len(vector) != expected_dim:
            raise ValueError(
                f"Feature schema violation: Series has {len(vector)} columns, expected {expected_dim}."
            )
        if hasattr(vector, "index") and list(vector.index) != list(CANONICAL_FEATURE_NAMES):
            raise ValueError(
                f"Feature ordering mismatch in Series index.\n"
                f"Expected: {list(CANONICAL_FEATURE_NAMES)}\n"
                f"Actual:   {list(vector.index)}"
            )
        arr = vector.to_numpy(dtype=np.float64).reshape(1, -1)

    else:
        try:
            arr = np.asarray(vector, dtype=np.float64)
        except (ValueError, TypeError) as e:
            raise TypeError(f"Non-numeric values in feature vector: {e}") from e

    # 2. Reshape 1D to 2D
    if arr.ndim == 1:
        arr = arr.reshape(1, -1)
    elif arr.ndim > 2:
        raise ValueError(f"Feature vector must be 1D or 2D, found ndim={arr.ndim}")

    # 3. Dimensionality check
    n_features = arr.shape[1]
    if n_features != expected_dim:
        raise ValueError(
            f"Feature dimensionality violation: Vector has {n_features} columns, expected {expected_dim}. "
            "Positional truncation or padding is strictly prohibited."
        )

    # 4. Check for NaN or Inf
    if not np.all(np.isfinite(arr)):
        nan_count = int(np.isnan(arr).sum())
        inf_count = int(np.isinf(arr).sum())
        raise ValueError(
            f"Non-finite values detected in feature vector: {nan_count} NaNs, {inf_count} Infs. "
            "All flow features must be finite numbers."
        )

    return arr


def validate_feature_dict(
    feature_dict: Dict[str, Any],
    require_all: bool = True,
) -> Dict[str, float]:
    """
    Validates a dictionary of extracted features against the canonical schema.

    Enforces:
    1. Presence of all 12 canonical keys (no missing features)
    2. No prohibited target/label leakage keys present
    3. Numeric, finite float values for all canonical features

    Returns:
        Dict[str, float]: Clean dictionary containing exactly the 12 canonical features.

    Raises:
        ValueError: If keys are missing, extra prohibited keys exist, or values are invalid.
    """
    # Check for prohibited leakage
    leakage_keys = [k for k in feature_dict if k in PROHIBITED_LEAKAGE_COLUMNS]
    if leakage_keys:
        raise ValueError(
            f"Target/Label leakage detected in feature dictionary: {leakage_keys}. "
            "These fields must never enter the feature extractor."
        )

    clean_dict: Dict[str, float] = {}
    missing_keys = []

    for name in CANONICAL_FEATURE_NAMES:
        if name not in feature_dict:
            missing_keys.append(name)
        else:
            val = feature_dict[name]
            try:
                float_val = float(val)
                if not np.isfinite(float_val):
                    raise ValueError(f"Feature '{name}' has non-finite value: {val}")
                clean_dict[name] = float_val
            except (ValueError, TypeError) as e:
                raise ValueError(f"Feature '{name}' could not be converted to float: {val} ({e})") from e

    if require_all and missing_keys:
        raise ValueError(
            f"Missing required canonical features in dictionary: {missing_keys}. "
            f"Expected all {CANONICAL_FEATURE_COUNT} canonical features."
        )

    return clean_dict


def dict_to_canonical_vector(feature_dict: Dict[str, Any]) -> List[float]:
    """
    Converts a feature dictionary to an ordered 12D list strictly following CANONICAL_FEATURE_NAMES.
    """
    validated_dict = validate_feature_dict(feature_dict, require_all=True)
    return [validated_dict[name] for name in CANONICAL_FEATURE_NAMES]
