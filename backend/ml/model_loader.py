import mlflow
import os
import joblib
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

try:
    from ml.config.mlflow_env import TRACKING_URI, MODEL_NAME
    from ml.config.feature_schema import (
        CANONICAL_FEATURE_NAMES,
        CANONICAL_FEATURE_COUNT,
        SCHEMA_VERSION,
        KNOWN_INCOMPATIBLE_DIMENSIONS,
    )
except ImportError:
    from backend.ml.config.mlflow_env import TRACKING_URI, MODEL_NAME
    from backend.ml.config.feature_schema import (
        CANONICAL_FEATURE_NAMES,
        CANONICAL_FEATURE_COUNT,
        SCHEMA_VERSION,
        KNOWN_INCOMPATIBLE_DIMENSIONS,
    )

logger = logging.getLogger(__name__)

# Model Lifecycle & Compatibility Statuses (Phase ML-3)
STATUS_CANONICAL = "CANONICAL"
STATUS_QUARANTINED = "QUARANTINED_INCOMPATIBLE"
STATUS_LEGACY = "LEGACY"
STATUS_EXPERIMENTAL = "EXPERIMENTAL"

# Singleton instances
_MODEL = None
_IF_MODEL = None
_ENSEMBLE = None
_LOAD_ATTEMPTED = False


def reset_model_cache():
    """Resets cached model singletons (used in testing and rollback)."""
    global _MODEL, _IF_MODEL, _ENSEMBLE, _LOAD_ATTEMPTED
    _MODEL = None
    _IF_MODEL = None
    _ENSEMBLE = None
    _LOAD_ATTEMPTED = False


def validate_checkpoint_schema(model: Any, model_identifier: str = "Model") -> Dict[str, Any]:
    """
    Validates model feature compatibility against the canonical 12D schema (Phase ML-3).
    Rejects incompatible dimensions (6D, 13D, 15D, 32D) explicitly.
    Positional truncation or padding is strictly prohibited.

    Returns:
        Dict[str, Any] with metadata: status, detected_dimension, expected_dimension, etc.

    Raises:
        ValueError: If model dimensionality or feature names violate the contract.
    """
    if model is None:
        raise ValueError(f"Cannot validate None model for '{model_identifier}'")

    expected_dim = CANONICAL_FEATURE_COUNT
    n_features = getattr(model, "n_features_in_", None)
    feat_names = getattr(model, "feature_names_in_", None)

    # Inspect Pipeline steps recursively if applicable
    if hasattr(model, "named_steps"):
        for step_name, step_obj in model.named_steps.items():
            step_dim = getattr(step_obj, "n_features_in_", None)
            step_names = getattr(step_obj, "feature_names_in_", None)
            if step_dim is not None:
                n_features = step_dim
            if step_names is not None:
                feat_names = step_names

    # Check dimensionality
    if n_features is not None and n_features != expected_dim:
        status = STATUS_QUARANTINED
        disposition = (
            f"Quarantine checkpoint '{model_identifier}'; strictly forbidden from production "
            f"inference under Phase ML-3 contract."
        )
        raise ValueError(
            f"Model Compatibility Violation [{status}]:\n"
            f"  • Model Identifier:       {model_identifier}\n"
            f"  • Detected Dimension:     {n_features} features\n"
            f"  • Expected Dimension:     {expected_dim} features ({list(CANONICAL_FEATURE_NAMES)})\n"
            f"  • Known Incompatible Dims:{KNOWN_INCOMPATIBLE_DIMENSIONS}\n"
            f"  • Compatibility Status:   {status}\n"
            f"  • Recommended Action:     {disposition}"
        )

    # Check feature names if available
    if feat_names is not None:
        names_list = list(feat_names)
        if tuple(names_list) != CANONICAL_FEATURE_NAMES:
            status = "INCOMPATIBLE_SCHEMA_MISMATCH"
            disposition = (
                f"Quarantine checkpoint '{model_identifier}'; feature schema conflicts with "
                f"authoritative {SCHEMA_VERSION} contract."
            )
            raise ValueError(
                f"Model Schema Mismatch [{status}]:\n"
                f"  • Model Identifier:       {model_identifier}\n"
                f"  • Detected Features:      {names_list}\n"
                f"  • Expected Features:      {list(CANONICAL_FEATURE_NAMES)}\n"
                f"  • Compatibility Status:   {status}\n"
                f"  • Recommended Action:     {disposition}"
            )

    return {
        "model_identifier": model_identifier,
        "status": STATUS_CANONICAL,
        "detected_dimension": n_features or expected_dim,
        "expected_dimension": expected_dim,
        "feature_names": list(feat_names) if feat_names is not None else list(CANONICAL_FEATURE_NAMES),
        "schema_version": SCHEMA_VERSION,
    }


def inspect_model_checkpoint(filepath: Union[str, Path]) -> Dict[str, Any]:
    """
    Forensically inspects any model checkpoint on disk without crashing.
    Categorizes status into CANONICAL, QUARANTINED_INCOMPATIBLE, LEGACY, or EXPERIMENTAL.
    """
    path_obj = Path(filepath)
    result = {
        "path": str(path_obj),
        "filename": path_obj.name,
        "exists": path_obj.exists(),
        "size_bytes": path_obj.stat().st_size if path_obj.exists() else 0,
        "model_type": "Unknown",
        "detected_dimension": None,
        "expected_dimension": CANONICAL_FEATURE_COUNT,
        "feature_names": [],
        "status": STATUS_QUARANTINED,
        "recommended_disposition": "Quarantine",
        "error": None,
    }

    if not path_obj.exists():
        result["error"] = "File does not exist"
        return result

    if path_obj.suffix == ".h5":
        result["model_type"] = "Keras HDF5"
        result["status"] = STATUS_EXPERIMENTAL
        result["recommended_disposition"] = "Isolate behind feature flag (experimental LSTM)"
        return result

    try:
        loaded = joblib.load(path_obj)
        result["model_type"] = type(loaded).__name__

        n_feat = getattr(loaded, "n_features_in_", None)
        fn = getattr(loaded, "feature_names_in_", None)

        if hasattr(loaded, "named_steps"):
            result["model_type"] = f"Pipeline({list(loaded.named_steps.keys())})"
            for s_name, s_obj in loaded.named_steps.items():
                if getattr(s_obj, "n_features_in_", None) is not None:
                    n_feat = getattr(s_obj, "n_features_in_", None)
                if getattr(s_obj, "feature_names_in_", None) is not None:
                    fn = getattr(s_obj, "feature_names_in_", None)

        result["detected_dimension"] = n_feat
        if fn is not None:
            result["feature_names"] = list(fn)

        # Categorize
        if n_feat == CANONICAL_FEATURE_COUNT:
            if fn is not None and tuple(fn) != CANONICAL_FEATURE_NAMES:
                result["status"] = STATUS_QUARANTINED
                result["recommended_disposition"] = "Quarantine: feature name/domain mismatch"
            else:
                result["status"] = STATUS_CANONICAL
                result["recommended_disposition"] = "Active production inference"
        elif n_feat in KNOWN_INCOMPATIBLE_DIMENSIONS:
            result["status"] = STATUS_QUARANTINED
            result["recommended_disposition"] = f"Quarantine: incompatible {n_feat}D dimension"
        else:
            result["status"] = STATUS_LEGACY
            result["recommended_disposition"] = "Preserve for forensic record"

    except Exception as e:
        result["error"] = str(e)
        result["status"] = STATUS_QUARANTINED
        result["recommended_disposition"] = "Quarantine: corrupt or unpicklable artifact"

    return result


def load_model():
    """
    Loads the production Random Forest classifier from MLflow or local verified artifacts.
    Implements caching and strictly validates 12D schema compliance.
    """
    global _MODEL, _LOAD_ATTEMPTED

    if _MODEL is not None:
        return _MODEL

    if not _LOAD_ATTEMPTED:
        logger.info("[MODEL_LOADER] Initializing ML scoring engine...")
        _LOAD_ATTEMPTED = True

    # 1. Try MLflow (supports test mocking, versioning, rollback)
    try:
        mlflow.set_tracking_uri(TRACKING_URI)
        client = mlflow.tracking.MlflowClient()

        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=FutureWarning)
            versions = client.get_latest_versions(MODEL_NAME, stages=["Production"])
            if not versions:
                versions = client.get_latest_versions(
                    MODEL_NAME, stages=["None", "Staging"]
                )

        if versions:
            latest_version = versions[0]
            model_uri = f"models:/{MODEL_NAME}/{latest_version.version}"
            logger.info(f"[MODEL_LOADER] Loading from MLflow: {model_uri}")
            loaded = mlflow.sklearn.load_model(model_uri)
            validate_checkpoint_schema(loaded, f"MLflow:{MODEL_NAME}")
            _MODEL = loaded
            return _MODEL

    except Exception as e:
        logger.debug(f"[MODEL_LOADER] MLflow load bypassed: {e}")

    # 2. Fallback to Local Verified Artifact
    local_path = Path(__file__).parent.parent.parent / "ml_models" / "registry" / "AttackClassifier_Enhanced_v1.0.0.pkl"
    if not local_path.exists():
        local_path = Path(__file__).parent.parent.parent / "ml_models" / "attack_classifier_latest.pkl"

    if local_path.exists():
        try:
            loaded = joblib.load(local_path)
            validate_checkpoint_schema(loaded, str(local_path))
            _MODEL = loaded
            logger.info(f"[MODEL_LOADER] Successfully loaded production model: {local_path}")
            return _MODEL
        except Exception as e:
            logger.error(f"[MODEL_LOADER] Failed to load local model {local_path}: {e}")
            raise

    return None


def get_model():
    """Public accessor for the supervised classifier model."""
    return load_model()


def load_isolation_forest():
    """
    Loads the canonical 12D Isolation Forest anomaly detector from disk.
    Enforces strict 12D schema validation and rejects incompatible checkpoints.
    """
    global _IF_MODEL

    if _IF_MODEL is not None:
        return _IF_MODEL

    canonical_path = Path(__file__).parent.parent.parent / "ml_models" / "iforest_baseline.pkl"
    if canonical_path.exists():
        try:
            loaded = joblib.load(canonical_path)
            validate_checkpoint_schema(loaded, str(canonical_path))
            _IF_MODEL = loaded
            logger.info(f"[MODEL_LOADER] Successfully loaded Isolation Forest: {canonical_path}")
            return _IF_MODEL
        except Exception as e:
            logger.error(f"[MODEL_LOADER] Failed to load Isolation Forest {canonical_path}: {e}")
            raise

    return None


def get_isolation_forest():
    """Public accessor for the canonical Isolation Forest model."""
    return load_isolation_forest()


def load_ensemble():
    """
    Loads the canonical Hybrid Ensemble Predictor combining RF (0.85) and IF (0.15).
    """
    global _ENSEMBLE

    if _ENSEMBLE is not None:
        return _ENSEMBLE

    from ml.models.ensemble_predictor import EnsemblePredictor

    rf = load_model()
    iso = load_isolation_forest()
    _ENSEMBLE = EnsemblePredictor(rf_model=rf, if_model=iso)
    return _ENSEMBLE


def get_ensemble():
    """Public accessor for the canonical Ensemble Predictor."""
    return load_ensemble()
