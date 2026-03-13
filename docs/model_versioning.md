# Model Versioning Guide

This document defines the architecture and rules for model versioning in the PhantomNet infrastructure.

## Versioning Scheme

Models released and stored in the `ModelRegistry` must follow Semantic Versioning (SemVer) format specifically designed for machine learning artifacts: `v{MAJOR}.{MINOR}.{PATCH}`.

### Version Components

1.  **Major Version (`v1.x.x`)**:
    *   Incremented when there is a significant architectural change (e.g., switching from Random Forest to LSTM).
    *   Incremented when there are breaking changes to feature inputs (e.g., removing a required feature or drastically changing how features are scaled).
    *   Incremented for entirely non-backward-compatible API updates required for inference.
    *   *Resets Minor and Patch versions to 0.*

2.  **Minor Version (`vX.1.x`)**:
    *   Incremented when new features are added to the model training dataset (backward-compatible addition).
    *   Incremented when the model is retrained on a substantially newer or larger dataset that yields significant performance improvements without changing the core architecture.
    *   Incremented when adding new derived outputs or metrics to the model's metadata.
    *   *Resets Patch version to 0.*

3.  **Patch Version (`vX.X.1`)**:
    *   Incremented for minor retrains using the same architecture and feature set (e.g., weekly retraining jobs to capture mild drift).
    *   Incremented when fixing bugs in the model inference wrapper or fixing incorrect metadata.
    *   Incremented for minor hyperparameter tuning tweaks that yield small improvements.

## Version Lifecycle and Status

Each version in the registry has a status:
*   **Staging**: Newly registered model undergoing testing and comparison.
*   **Production**: The current active model handling real traffic.
*   **Archived / Deprecated**: Older models kept for rollback purposes or historical records.

## Automated Versioning

The `ModelRegistry` handles the logic to automatically increment versions based on user requests (e.g., asking for a `patch` bump on the latest `v1` model).

## Rollback Policy
If an error occurs or performance degrades with a new `Production` model (e.g. `v1.2.0`), the system must support automated or manual rollback to the immediately preceding reliable version (e.g. `v1.1.0`). Validated by `ml/tests/test_rollback.py`.
