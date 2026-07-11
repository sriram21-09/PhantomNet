import sys
from pathlib import Path

# Add backend/ to sys.path so we can import 'ml' submodules
ROOT = Path(__file__).resolve().parent
BACKEND = ROOT.parent
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
