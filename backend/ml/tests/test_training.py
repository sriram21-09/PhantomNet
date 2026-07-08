# backend/ml/tests/test_training.py

import os
import subprocess
import sys
import pytest
from config.mlflow_env import *

PROJECT_ROOT = os.path.abspath(os.path.join(__file__, "../../../.."))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
TRAINING_CSVS = ["week6_test_events_balanced.csv", "week6_test_events.csv"]
_has_training_data = any(
    os.path.exists(os.path.join(DATA_DIR, f)) for f in TRAINING_CSVS
)


@pytest.mark.skipif(
    not _has_training_data,
    reason=f"Training data not found: need one of {TRAINING_CSVS} in data/",
)
def test_training_pipeline_runs():
    """
    Smoke test for training pipeline
    """
    result = subprocess.run(
        [sys.executable, "run_training.py"],
        cwd=os.path.join(PROJECT_ROOT, "backend", "ml"),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, "Training script failed"
    assert "Training complete" in result.stdout
    assert "accuracy" in result.stdout.lower()

