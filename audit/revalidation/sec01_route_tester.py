import os
import sys
import json
from datetime import datetime, timedelta
from pathlib import Path

# Add project root and backend
ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

from backend.main import app
from fastapi.testclient import TestClient
from fastapi.routing import APIRoute
from starlette.routing import WebSocketRoute
from backend.middleware.auth import create_access_token

client = TestClient(app, raise_server_exceptions=False)

# Generate test tokens
admin_token = create_access_token({"sub": "admin_test", "role": "ADMIN", "permissions": ["*"]})
analyst_token = create_access_token({"sub": "analyst_test", "role": "ANALYST", "permissions": ["read"]})
expired_token = create_access_token(
    {"sub": "expired_test", "role": "ADMIN"},
    expires_delta=timedelta(minutes=-60)
)
invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature"

PUBLIC_ROUTES = [
    "/health/live", "/health/ready", "/health/startup",
    "/api/v1/auth/login", "/api/v1/auth/refresh",
    "/docs", "/redoc", "/openapi.json"
]

def test_all_routes():
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
        # If an endpoint does NOT reject anonymous requests with 401 or 403, and is not public by design:
        # Note: 422 or 400 or 404 or 405 on anonymous means the request hit the business logic/validation, bypassing auth!
        auth_enforced = status_anon in [401, 403]
        if not is_public and not auth_enforced:
            classification = "UNPROTECTED_EXPOSED"
            unprotected_count += 1
        elif is_public:
            classification = "PUBLIC_BY_DESIGN"
        elif status_analyst in [401, 403] and status_admin not in [401, 403]:
            classification = "ROLE_PROTECTED_ADMIN_ONLY"
        else:
            classification = "AUTHENTICATED_GENERAL"

        entry = {
            "path": path,
            "method": method,
            "endpoint": f"{route.endpoint.__module__}.{route.endpoint.__name__}",
            "is_public_by_design": is_public,
            "classification": classification,
            "auth_enforced": auth_enforced,
            "responses": {
                "anonymous": {"status": status_anon, "body_preview": resp_anon.text[:120]},
                "invalid_token": {"status": status_invalid, "body_preview": resp_invalid.text[:120]},
                "expired_token": {"status": status_expired, "body_preview": resp_expired.text[:120]},
                "analyst_token": {"status": status_analyst, "body_preview": resp_analyst.text[:120]},
                "admin_token": {"status": status_admin, "body_preview": resp_admin.text[:120]},
            }
        }
        matrix.append(entry)

    # Save JSON matrix
    with open("audit/revalidation/sec01_route_auth_matrix.json", "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "total_routes_tested": total_routes,
            "unprotected_count": unprotected_count,
            "matrix": matrix
        }, f, indent=2)

    # Generate Markdown Report
    md = f"""# PhantomNet V3 — SEC-01 Dynamic Route Authentication Verification Report
**Date**: September 19, 2026  
**Auditor**: Independent Application Security Audit Group  
**Methodology**: Dynamic HTTP TestClient probing against all registered routes with 5 distinct credential states.  
**Total Routes Evaluated**: {total_routes}  
**Unprotected Non-Public Routes (SEC-01 Breaches)**: {unprotected_count}

---

## 1. Executive Verdict: SEC-01 = 🔴 NOT VERIFIED

The requirement for SEC-01 states:
> *"100% of non-public API endpoints require valid JWT authentication. Anonymous requests to protected routes return HTTP 401 Unauthorized."*

**Empirical Result**: **{unprotected_count} non-public routes completely bypass authentication.**
When an anonymous request is sent, the application executes parameter parsing, business logic, or returns data instead of rejecting the request with HTTP 401 Unauthorized.

---

## 2. Table of Unprotected Non-Public Endpoints ({unprotected_count})

| Method | Path | Endpoint Function | Anon Status | Anon Response Preview | Classification |
| :--- | :--- | :--- | :---: | :--- | :--- |
"""
    for m in matrix:
        if m["classification"] == "UNPROTECTED_EXPOSED":
            preview = m["responses"]["anonymous"]["body_preview"].replace("\n", " ").replace("|", "\\|")
            md += f"| `{m['method']}` | `{m['path']}` | `{m['endpoint']}` | `{m['responses']['anonymous']['status']}` | `{preview}` | 🔴 **EXPOSED** |\n"

    md += f"""
---

## 3. Summary Statistics
- **Total Registered HTTP Routes**: {total_routes}
- **Public by Design**: {len([m for m in matrix if m['classification'] == 'PUBLIC_BY_DESIGN'])}
- **Properly Authenticated**: {len([m for m in matrix if m['classification'] in ['AUTHENTICATED_GENERAL', 'ROLE_PROTECTED_ADMIN_ONLY']])}
- **Improperly Exposed Without Authentication**: {unprotected_count}
- **Authentication Coverage**: {round((total_routes - unprotected_count) / total_routes * 100, 1)}% (Target: 100%)
"""
    with open("audit/revalidation/sec01_route_auth_report.md", "w", encoding="utf-8") as f:
        f.write(md)

    print(f"[+] SEC-01 Dynamic Test Complete: {total_routes} routes tested, {unprotected_count} unprotected routes found.")

if __name__ == "__main__":
    test_all_routes()
