import sys
from pathlib import Path

# Add backend/ml to PYTHONPATH for pytest
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
