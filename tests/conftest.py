"""
tests/conftest.py
-----------------
Adds the backend/ directory to sys.path so that `sentinel` package imports
(e.g. `from sentinel.rule_generator import ...`) resolve correctly for every
test module inside tests/.
"""
import sys
import os

# Project root is one level above this file (tests/../)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

# Ensure backend/ is at the very beginning of sys.path
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
# Append PROJECT_ROOT to the end so it doesn't shadow backend/ packages
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

# If 'sentinel' was already imported from the root directory, unload it so it can be re-imported from backend/
if 'sentinel' in sys.modules:
    sentinel_mod = sys.modules['sentinel']
    # Some namespace packages might not have __file__
    if hasattr(sentinel_mod, '__file__') and sentinel_mod.__file__:
        if not sentinel_mod.__file__.startswith(BACKEND_DIR):
            for key in list(sys.modules.keys()):
                if key == 'sentinel' or key.startswith('sentinel.'):
                    del sys.modules[key]
