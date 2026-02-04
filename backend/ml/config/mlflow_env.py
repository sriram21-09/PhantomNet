import os
import mlflow

BASE_DIR = os.path.abspath(os.path.join(__file__, "../../../.."))
MLRUNS_PATH = os.path.join(BASE_DIR, "mlruns")

mlflow.set_tracking_uri(f"file:///{MLRUNS_PATH}")
