# Model Rollback Guide

This guide outlines the automated and manual procedures for rolling back a registered machine learning model in the PhantomNet infrastructure when performance degrades or severe bugs are identified in production inference.

## Rollback Concept
In PhantomNet, we do not delete registered models unless absolutely necessary. Instead, rollback is managed via **Model Statuses**.
*   When a new model triggers a rollback, its status is changed to `Archived` or `Deprecated`.
*   The system then automatically falls back to fetching the model with the highest version number that has the status `Production`.

## Automated Rollback
Automated rollbacks are natively integrated into our evaluation gates:
1.  **Evaluation Phase**: A staging model is run through `ModelComparator`.
2.  **Degradation Threshold**: If the metrics (e.g. `accuracy`, `f1_score`) drop below a defined error threshold (e.g., `-5%` compared to the current production model).
3.  **Action**: The Staging model is assigned `Archived` status instantly, and never reaches `Production`. The previous `Production` model is retained.
*Refer to `ml/tests/test_rollback.py` to see this automation validated in the test suite.*

## Manual Rollback
If a model successfully enters `Production` but begins exhibiting concept drift or introduces latency bugs, operators must manually update the metadata index.

### Steps
1.  **Identify the failing version**: e.g., `v1.2.0`
2.  **Use the Registry API**:
    ```python
    from ml.registry.model_registry import ModelRegistry
    
    registry = ModelRegistry()
    registry.update_model_status("v1.2.0", "Archived")
    ```
3.  **Verify Production Load**: Ensure the backend model-loader grabs the previous functional version (e.g. `v1.1.0`).
    ```python
    current_prod = registry.get_model_by_status("Production")
    print(current_prod["version"]) # Should output the older stable version
    ```

## Post-Rollback Diagnostics
Always run error analysis on the reverted model and store reports in `docs/` to isolate why the version failed in production despite passing staging gate checks.
