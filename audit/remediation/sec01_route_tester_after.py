import os
import sys
import json
import requests
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

os.environ["ENVIRONMENT"] = "production"
os.environ["JWT_SECRET"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
os.environ["HONEYPOT_SECRET_KEY"] = "c3f7b19a82e44d01b8e8f3a921d74659b8a0e1c2d3e4f5a6b7c8d9e0f1a2b3c4"

from backend.main import app
from fastapi.testclient import TestClient
from fastapi.routing import APIRoute
from backend.middleware.auth import create_access_token

client = TestClient(app, raise_server_exceptions=False)

# Generate test tokens
admin_token = create_access_token({"sub": "admin_test", "role": "Admin", "permissions": ["*"]})
analyst_token = create_access_token({"sub": "analyst_test", "role": "Analyst", "permissions": ["read"]})
expired_token = create_access_token(
    {"sub": "expired_test", "role": "Admin"},
    expires_delta=timedelta(minutes=-60)
)
invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"

PUBLIC_ROUTES = {
    "/health/live",
    "/health/ready",
    "/health/startup",
    "/api/health",
    "/metrics",
    "/api/v1/auth/login",
    "/api/v1/auth/refresh",
    "/api/v1/admin/login",
    "/docs",
    "/redoc",
    "/openapi.json",
}

SERVICE_TO_SERVICE_ROUTES = {
    "/api/v1/ingest/event",
    "/api/v1/ingest/batch",
    "/api/v1/taxii/status",
    "/api/v1/taxii/collections",
    "/api/v1/taxii/collections/{collection_id}",
    "/api/v1/taxii/collections/{collection_id}/objects",
    "/api/v1/taxii/collections/{collection_id}/manifest",
}

def run_sec01_revalidation():
    matrix = []
    unprotected_count = 0
    total_routes = 0

    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue

        total_routes += 1
        path = route.path
        methods = list(route.methods - {"HEAD", "OPTIONS"})
        if not methods:
            continue
        method = methods[0]

        is_public = path in PUBLIC_ROUTES
        is_s2s = path in SERVICE_TO_SERVICE_ROUTES

        # 1. Anonymous Request
        resp_anon = client.request(method, path)
        status_anon = resp_anon.status_code

        # 2. Invalid Token Request
        resp_invalid = client.request(method, path, headers={"Authorization": f"Bearer {invalid_token}"})
        status_invalid = resp_invalid.status_code

        # 3. Expired Token Request
        resp_expired = client.request(method, path, headers={"Authorization": f"Bearer {expired_token}"})
        status_expired = resp_expired.status_code

        # 4. Analyst Token Request
        resp_analyst = client.request(method, path, headers={"Authorization": f"Bearer {analyst_token}"})
        status_analyst = resp_analyst.status_code

        # 5. Admin Token Request
        resp_admin = client.request(method, path, headers={"Authorization": f"Bearer {admin_token}"})
        status_admin = resp_admin.status_code

        # Classification
        # For non-public routes, anonymous access MUST return 401 or 403
        auth_enforced = status_anon in [401, 403]

        if is_public:
            classification = "PUBLIC_BY_DESIGN"
        elif is_s2s:
            if auth_enforced:
                classification = "SERVICE_TO_SERVICE_AUTHENTICATED"
            else:
                classification = "UNPROTECTED_EXPOSED"
                unprotected_count += 1
        elif not auth_enforced:
            classification = "UNPROTECTED_EXPOSED"
            unprotected_count += 1
        elif status_analyst in [401, 403] and status_admin not in [401, 403]:
            classification = "ROLE_PROTECTED_ADMIN_ONLY"
        else:
            classification = "AUTHENTICATED_GENERAL"

        entry = {
            "path": path,
            "method": method,
            "endpoint": f"{route.endpoint.__module__}.{route.endpoint.__name__}",
            "is_public_by_design": is_public,
            "is_service_to_service": is_s2s,
            "classification": classification,
            "auth_enforced": auth_enforced or is_public,
            "responses": {
                "anonymous": {"status": status_anon, "body_preview": resp_anon.text[:120]},
                "invalid_token": {"status": status_invalid, "body_preview": resp_invalid.text[:120]},
                "expired_token": {"status": status_expired, "body_preview": resp_expired.text[:120]},
                "analyst_token": {"status": status_analyst, "body_preview": resp_analyst.text[:120]},
                "admin_token": {"status": status_admin, "body_preview": resp_admin.text[:120]},
            }
        }
        matrix.append(entry)

    # Save after JSON matrix
    out_json = ROOT / "audit" / "remediation" / "sec01_route_auth_matrix_after.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "total_routes_tested": total_routes,
            "unprotected_count": unprotected_count,
            "matrix": matrix
        }, f, indent=2)

    print(f"[+] SEC-01 After-Test Complete: {total_routes} routes tested, {unprotected_count} unprotected routes found.")
    return total_routes, unprotected_count, matrix

if __name__ == "__main__":
    run_sec01_revalidation()
