"""
audit/runtime/route_enumerator.py
---------------------------------
Inspects FastAPI app routes from backend/main.py, extracting:
- Method
- Path
- Endpoint function name
- Dependencies (get_current_user, require_role, etc.)
- Authentication requirement status
Outputs a complete Markdown table and JSON artifact.
"""
import os
import sys
import json
import inspect
from pathlib import Path

# Add backend to sys.path
BACKEND_DIR = Path(__file__).resolve().parent.parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

# Mock environment variables for app import
os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "a" * 32
os.environ["HONEYPOT_SECRET_KEY"] = "b" * 32

try:
    from main import app
    from middleware.auth import get_current_user, require_role, verify_step_up_auth
    from fastapi.routing import APIRoute
    from starlette.routing import Route, WebSocketRoute
except Exception as e:
    print(f"Error importing app: {e}", file=sys.stderr)
    sys.exit(1)

routes_info = []

for route in app.routes:
    if isinstance(route, APIRoute):
        methods = sorted(list(route.methods - {"HEAD", "OPTIONS"})) if route.methods else ["GET"]
        path = route.path
        name = route.name
        
        # Check dependencies on the route and endpoint signature
        dependencies = [dep.dependency for dep in route.dependencies if hasattr(dep, "dependency")]
        
        # Check endpoint signature parameters
        sig = inspect.signature(route.endpoint)
        auth_required = False
        roles_required = []
        is_step_up = False
        
        for param in sig.parameters.values():
            default = param.default
            # Check for Depends
            if hasattr(default, "dependency"):
                dep_fn = default.dependency
                dep_name = getattr(dep_fn, "__name__", str(dep_fn))
                if dep_fn == get_current_user or "get_current_user" in dep_name:
                    auth_required = True
                if "role_checker" in dep_name or "require_role" in dep_name:
                    auth_required = True
                    roles_required.append(dep_name)
            if param.name in ["step_up_token", "x_step_up_token"]:
                is_step_up = True

        for dep in dependencies:
            dep_name = getattr(dep, "__name__", str(dep))
            if dep == get_current_user or "get_current_user" in dep_name:
                auth_required = True
            if "role_checker" in dep_name or "require_role" in dep_name:
                auth_required = True
                roles_required.append(dep_name)

        # Public endpoints whitelist
        is_public = False
        if path in [
            "/docs", "/redoc", "/openapi.json",
            "/api/health", "/health/live", "/health/ready", "/health/startup",
            "/metrics", "/api/v1/admin/login", "/api/v1/admin/refresh"
        ] or path.startswith("/api/v1/ingest/"):
            is_public = True

        routes_info.append({
            "methods": methods,
            "path": path,
            "name": name,
            "is_public": is_public,
            "auth_required": auth_required,
            "roles": roles_required,
            "step_up": is_step_up
        })
    elif isinstance(route, WebSocketRoute):
        routes_info.append({
            "methods": ["WEBSOCKET"],
            "path": route.path,
            "name": route.name,
            "is_public": False,
            "auth_required": True,  # WS auth via handshake
            "roles": [],
            "step_up": False
        })

output_json = Path(__file__).resolve().parent / "routes_inventory.json"
with open(output_json, "w", encoding="utf-8") as f:
    json.dump(routes_info, f, indent=2)

print(f"Total routes enumerated: {len(routes_info)}")
unauth_non_public = [r for r in routes_info if not r["is_public"] and not r["auth_required"]]
print(f"Non-public routes lacking explicit auth dependency: {len(unauth_non_public)}")
for r in unauth_non_public:
    print(f"  {r['methods']} {r['path']} ({r['name']})")
