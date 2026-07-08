import sys
import os

# Exclude Docker-only tests, manual scripts, ML infra tests, and venv from collection
# - Honeypot tests require Docker compose network (phantomnet_postgres hostname)
# - ML tests (ml/tests/) require isolated sys.path; run separately: pytest ml/tests/ -v
collect_ignore_glob = [
    "backend/honeypots/*/tests/*",
    "backend/scripts/test_*",
    "backend/venv/*",
    "ml/tests/*",
]

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")

# Check if we are running ML tests to avoid shadowing the root ml package
is_ml_test = any("ml/tests" in arg or "ml\\" in arg or "ml/tests" in arg.replace("\\", "/") for arg in sys.argv)

if is_ml_test:
    # Put PROJECT_ROOT at the front and ensure BACKEND_DIR is not present
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
    while BACKEND_DIR in sys.path:
        sys.path.remove(BACKEND_DIR)
    # Unload ml from sys.modules to force clean re-import from PROJECT_ROOT
    for key in list(sys.modules.keys()):
        if key == "ml" or key.startswith("ml."):
            del sys.modules[key]
else:
    if BACKEND_DIR not in sys.path:
        sys.path.insert(0, BACKEND_DIR)
    if PROJECT_ROOT not in sys.path:
        sys.path.append(PROJECT_ROOT)

# Ensure 'ml' namespace package can find submodules in both backend/ml and root ml/ if not in ML tests
if not is_ml_test:
    try:
        import ml
        if hasattr(ml, "__path__"):
            root_ml_dir = os.path.join(PROJECT_ROOT, "ml")
            if root_ml_dir not in ml.__path__:
                ml.__path__.append(root_ml_dir)
    except ImportError:
        pass


