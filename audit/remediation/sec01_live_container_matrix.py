import os
import sys
import json
import requests
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.middleware.auth import create_access_token

BASE_URL = "http://localhost:8000"
JWT_SECRET = "a8f9c1e2d3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0"
os.environ["JWT_SECRET"] = JWT_SECRET

# Generate test tokens using the container's JWT_SECRET
admin_token = create_access_token({"sub": "admin", "role": "Admin", "permissions": ["*"]})
analyst_token = create_access_token({"sub": "analyst", "role": "Analyst", "permissions": ["read"]})
expired_token = create_access_token(
    {"sub": "admin", "role": "Admin"},
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

def test_live_container():
    # Fetch OpenAPI schema from live container to enumerate all registered routes
    resp = requests.get(f"{BASE_URL}/openapi.json")
    if resp.status_code != 200:
        print(f"Failed to fetch openapi.json from live container: {resp.status_code}")
        sys.exit(1)

    schema = resp.json()
    paths = schema.get("paths", {})
    
    matrix = []
    unprotected_count = 0
    total_routes = 0

    for path, methods in sorted(paths.items()):
        for method, details in sorted(methods.items()):
            if method.upper() in ["HEAD", "OPTIONS"]:
                continue

            total_routes += 1
            m_upper = method.upper()
            is_public = path in PUBLIC_ROUTES
            is_s2s = path in SERVICE_TO_SERVICE_ROUTES

            # Resolve template path params for live requests (e.g. {ip} -> 127.0.0.1, {id} -> 1)
            live_path = path.replace("{ip}", "127.0.0.1")\
                            .replace("{id}", "1")\
                            .replace("{playbook_id}", "PB-TEST-001")\
                            .replace("{campaign_id}", "CAMP-TEST-001")\
                            .replace("{collection_id}", "default")\
                            .replace("{event_id}", "1")

            # 1. Anonymous Request
            try:
                r_anon = requests.request(m_upper, f"{BASE_URL}{live_path}", timeout=5)
                status_anon = r_anon.status_code
                body_anon = r_anon.text[:120]
            except Exception as e:
                status_anon = 500
                body_anon = str(e)

            # 2. Invalid Token Request
            try:
                r_inv = requests.request(m_upper, f"{BASE_URL}{live_path}", headers={"Authorization": f"Bearer {invalid_token}"}, timeout=5)
                status_inv = r_inv.status_code
                body_inv = r_inv.text[:120]
            except Exception as e:
                status_inv = 500
                body_inv = str(e)

            # 3. Expired Token Request
            try:
                r_exp = requests.request(m_upper, f"{BASE_URL}{live_path}", headers={"Authorization": f"Bearer {expired_token}"}, timeout=5)
                status_exp = r_exp.status_code
                body_exp = r_exp.text[:120]
            except Exception as e:
                status_exp = 500
                body_exp = str(e)

            # 4. Analyst Token Request
            try:
                r_ana = requests.request(m_upper, f"{BASE_URL}{live_path}", headers={"Authorization": f"Bearer {analyst_token}"}, timeout=5)
                status_ana = r_ana.status_code
                body_ana = r_ana.text[:120]
            except Exception as e:
                status_ana = 500
                body_ana = str(e)

            # 5. Admin Token Request
            try:
                r_adm = requests.request(m_upper, f"{BASE_URL}{live_path}", headers={"Authorization": f"Bearer {admin_token}"}, timeout=5)
                status_adm = r_adm.status_code
                body_adm = r_adm.text[:120]
            except Exception as e:
                status_adm = 500
                body_adm = str(e)

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
            elif status_ana in [401, 403] and status_adm not in [401, 403]:
                classification = "ROLE_PROTECTED_ADMIN_ONLY"
            else:
                classification = "AUTHENTICATED_GENERAL"

            entry = {
                "path": path,
                "method": m_upper,
                "endpoint": details.get("operationId", path),
                "is_public_by_design": is_public,
                "is_service_to_service": is_s2s,
                "classification": classification,
                "auth_enforced": auth_enforced or is_public,
                "responses": {
                    "anonymous": {"status": status_anon, "body_preview": body_anon},
                    "invalid_token": {"status": status_inv, "body_preview": body_inv},
                    "expired_token": {"status": status_exp, "body_preview": body_exp},
                    "analyst_token": {"status": status_ana, "body_preview": body_ana},
                    "admin_token": {"status": status_adm, "body_preview": body_adm},
                }
            }
            matrix.append(entry)

    out_file = ROOT / "audit" / "remediation" / "sec01_route_auth_matrix_after.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.utcnow().isoformat(),
            "target": BASE_URL,
            "total_routes_tested": total_routes,
            "unprotected_count": unprotected_count,
            "matrix": matrix
        }, f, indent=2)

    print(f"[+] LIVE CONTAINER SEC-01 TEST COMPLETE: {total_routes} routes probed, {unprotected_count} unprotected routes found.")
    return total_routes, unprotected_count

if __name__ == "__main__":
    test_live_container()
