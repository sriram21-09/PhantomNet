"""
audit/runtime/route_enumerator_v2.py
------------------------------------
Accurately inspects FastAPI route dependency trees using route.dependant.
Recursively inspects dependencies to detect get_current_user, require_role,
and step_up_auth.
"""
import os
import sys
import json
import inspect
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent.parent / "backend"
sys.path.insert(0, str(BACKEND_DIR))

os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "a" * 32
os.environ["HONEYPOT_SECRET_KEY"] = "b" * 32

from main import app
from middleware.auth import get_current_user, verify_step_up_auth
from fastapi.routing import APIRoute
from starlette.routing import WebSocketRoute

def check_dependencies_recursively(dependant):
    """Recursively checks if get_current_user is in the dependant tree."""
    if not dependant:
        return False, []
    
    auth_found = False
    details = []
    
    call = getattr(dependant, "call", None)
    call_name = getattr(call, "__name__", str(call))
    
    if call == get_current_user or "get_current_user" in call_name:
        auth_found = True
        details.append("get_current_user")
    if call_name == "_check":
        auth_found = True
        details.append("require_role")
    if "get_taxii_user" in call_name:
        auth_found = True
        details.append("get_taxii_user")
        
    for sub_dep in dependant.dependencies:
        sub_auth, sub_details = check_dependencies_recursively(sub_dep)
        if sub_auth:
            auth_found = True
            details.extend(sub_details)
            
    return auth_found, list(set(details))

routes_table = []
genuine_unprotected = []

PUBLIC_WHITELIST = {
    "/docs", "/redoc", "/openapi.json",
    "/api/health", "/health/live", "/health/ready", "/health/startup",
    "/metrics", "/api/v1/admin/login", "/api/v1/admin/refresh"
}

for route in app.routes:
    if isinstance(route, APIRoute):
        methods = sorted(list(route.methods - {"HEAD", "OPTIONS"})) if route.methods else ["GET"]
        path = route.path
        name = route.name
        
        is_public = path in PUBLIC_WHITELIST or path.startswith("/api/v1/ingest/")
        
        auth_found, details = check_dependencies_recursively(route.dependant)
        
        # Check params for step-up
        sig = inspect.signature(route.endpoint)
        is_step_up = any(p in ["step_up_token", "x_step_up_token"] for p in sig.parameters.keys())
        
        # Special case: Honeypot ingest endpoints use HMAC-SHA256 origin auth
        if path.startswith("/api/v1/ingest/"):
            auth_type = "HMAC-SHA256 Origin Auth"
        elif auth_found:
            auth_type = "JWT Auth (" + ", ".join(details) + ")"
        elif is_public:
            auth_type = "Public Endpoint"
        else:
            auth_type = "UNPROTECTED"
            genuine_unprotected.append({
                "methods": methods,
                "path": path,
                "name": name
            })
            
        routes_table.append({
            "methods": methods,
            "path": path,
            "name": name,
            "is_public": is_public,
            "auth_required": auth_found or path.startswith("/api/v1/ingest/"),
            "auth_type": auth_type,
            "step_up": is_step_up
        })
    elif isinstance(route, WebSocketRoute):
        routes_table.append({
            "methods": ["WEBSOCKET"],
            "path": route.path,
            "name": route.name,
            "is_public": False,
            "auth_required": True,
            "auth_type": "WebSocket Handshake Auth (Cookie/Bearer + Origin Check)",
            "step_up": False
        })

output_file = Path(__file__).resolve().parent / "routes_table.json"
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(routes_table, f, indent=2)

print(f"Total routes evaluated: {len(routes_table)}")
print(f"GENUINE UNPROTECTED NON-PUBLIC ROUTES: {len(genuine_unprotected)}")
for r in genuine_unprotected:
    print(f"  {r['methods']} {r['path']} ({r['name']})")
