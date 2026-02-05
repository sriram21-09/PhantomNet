# backend/ml/tests/test_training.py

import os
import subprocess
import sys
from config.mlflow_env import *



PROJECT_ROOT = os.path.abspath(os.path.join(__file__, "../../../.."))

def test_training_pipeline_runs():
    """
    Smoke test for training pipeline
    """
    result = subprocess.run(
        [sys.executable, "run_training.py"],
        cwd=os.path.join(PROJECT_ROOT, "backend", "ml"),
        capture_output=True,
        text=True
    )

    assert result.returncode == 0, "Training script failed"
    assert "Training complete" in result.stdout
    assert "accuracy" in result.stdout.lower()
