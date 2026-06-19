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

for _path in (PROJECT_ROOT, BACKEND_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)
