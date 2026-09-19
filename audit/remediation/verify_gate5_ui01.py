import json
import requests
import re
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent.parent

def verify_ui01():
    print("=" * 60)
    print("PHANTOMNET V3 — UI-01 TOKEN STORAGE & COOKIE AUTH REVALIDATION")
    print("=" * 60)

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "dimension": "UI-01",
        "description": "Administrative JWT storage migration from localStorage to HttpOnly cookies",
        "backend_api_tests": {},
        "frontend_code_audit": {},
        "browser_storage_checks": {},
        "properties_verified": {}
    }

    base_url = "http://localhost:8000"
    session = requests.Session()

    # 1. Test Login Endpoint and Set-Cookie Header
    print("\n--- 1. Testing POST /api/v1/admin/login Set-Cookie Header ---")
    try:
        login_resp = session.post(
            f"{base_url}/api/v1/admin/login",
            json={"username": "admin", "password": "admin123"},
            timeout=5
        )
        set_cookie_header = login_resp.headers.get("Set-Cookie", "")
        print(f"Login Status: {login_resp.status_code}")
        print(f"Set-Cookie Header: {set_cookie_header}")

        has_httponly = "httponly" in set_cookie_header.lower()
        has_admin_cookie = "admin_access_token" in set_cookie_header
        has_samesite = "samesite" in set_cookie_header.lower()

        token = login_resp.json().get("access_token")
        results["backend_api_tests"]["login"] = {
            "status_code": login_resp.status_code,
            "set_cookie_header": set_cookie_header,
            "has_admin_cookie": has_admin_cookie,
            "httponly_flag": has_httponly,
            "samesite_flag": has_samesite
        }
        print(f"HttpOnly flag present: {has_httponly}")
        print(f"SameSite flag present: {has_samesite}")
    except Exception as e:
        print(f"Error testing login: {e}")
        results["backend_api_tests"]["login_error"] = str(e)
        token = None

    # 2. Test GET /api/v1/admin/me with Cookie
    print("\n--- 2. Testing GET /api/v1/admin/me (Authenticated via Cookie) ---")
    try:
        # Pass cookie directly (needed over localhost http when Secure flag is set for production)
        cookies = {"phantomnet_access_token": token} if token else {}
        me_resp = requests.get(f"{base_url}/api/v1/admin/me", cookies=cookies, timeout=5)
        print(f"GET /me with Cookie Status: {me_resp.status_code}")
        print(f"GET /me Response: {me_resp.text}")

        results["backend_api_tests"]["get_me_authenticated"] = {
            "status_code": me_resp.status_code,
            "data": me_resp.json() if me_resp.status_code == 200 else me_resp.text,
            "authenticated": me_resp.status_code == 200
        }
    except Exception as e:
        print(f"Error testing GET /me: {e}")
        results["backend_api_tests"]["get_me_error"] = str(e)

    # 3. Test GET /api/v1/admin/me without Cookie
    print("\n--- 3. Testing GET /api/v1/admin/me (Anonymous / No Cookie) ---")
    try:
        unauth_resp = requests.get(f"{base_url}/api/v1/admin/me", timeout=5)
        print(f"GET /me without Cookie Status: {unauth_resp.status_code}")

        results["backend_api_tests"]["get_me_unauthenticated"] = {
            "status_code": unauth_resp.status_code,
            "blocked_401": unauth_resp.status_code == 401
        }
    except Exception as e:
        print(f"Error testing unauthenticated GET /me: {e}")
        results["backend_api_tests"]["get_me_unauth_error"] = str(e)

    # 4. Test POST /api/v1/admin/logout
    print("\n--- 4. Testing POST /api/v1/admin/logout ---")
    try:
        cookies = {"phantomnet_access_token": token} if token else {}
        logout_resp = requests.post(f"{base_url}/api/v1/admin/logout", cookies=cookies, timeout=5)
        logout_cookie = logout_resp.headers.get("Set-Cookie", "")
        print(f"Logout Status: {logout_resp.status_code}")
        print(f"Logout Set-Cookie: {logout_cookie}")

        results["backend_api_tests"]["logout"] = {
            "status_code": logout_resp.status_code,
            "set_cookie_header": logout_cookie,
            "cookie_cleared": "max-age=0" in logout_cookie.lower() or 'phantomnet_access_token=""' in logout_cookie or 'phantomnet_access_token=;' in logout_cookie
        }
    except Exception as e:
        print(f"Error testing logout: {e}")
        results["backend_api_tests"]["logout_error"] = str(e)

    # 5. Frontend Code Audit for localStorage / sessionStorage Token Usage
    print("\n--- 5. Frontend Code Audit for Token Storage ---")
    frontend_dir = ROOT / "frontend-dev"
    js_files = list(frontend_dir.rglob("*.js")) + list(frontend_dir.rglob("*.jsx")) + list(frontend_dir.rglob("*.ts")) + list(frontend_dir.rglob("*.tsx"))
    
    violations = []
    token_storage_patterns = [
        re.compile(r'localStorage\.setItem\s*\(\s*[\'"][^\'"]*token[^\'"]*[\'"]', re.IGNORECASE),
        re.compile(r'sessionStorage\.setItem\s*\(\s*[\'"][^\'"]*token[^\'"]*[\'"]', re.IGNORECASE),
        re.compile(r'localStorage\.getItem\s*\(\s*[\'"]admin_token[\'"]', re.IGNORECASE),
    ]

    for fpath in js_files:
        if "node_modules" in str(fpath) or "dist" in str(fpath) or "storybook-static" in str(fpath):
            continue
        try:
            content = fpath.read_text(encoding="utf-8")
            for i, line in enumerate(content.splitlines(), start=1):
                for pat in token_storage_patterns:
                    if pat.search(line):
                        violations.append({
                            "file": str(fpath.relative_to(ROOT)),
                            "line": i,
                            "content": line.strip()
                        })
        except Exception:
            pass

    results["frontend_code_audit"]["violations_found"] = len(violations)
    results["frontend_code_audit"]["violations"] = violations
    print(f"Token storage violations found in frontend: {len(violations)}")

    # 6. Evaluate Overall Properties
    login_ok = results["backend_api_tests"].get("login", {}).get("httponly_flag", False)
    auth_ok = results["backend_api_tests"].get("get_me_authenticated", {}).get("authenticated", False)
    unauth_ok = results["backend_api_tests"].get("get_me_unauthenticated", {}).get("blocked_401", False)
    logout_ok = results["backend_api_tests"].get("logout", {}).get("cookie_cleared", False)
    zero_violations = len(violations) == 0

    results["properties_verified"]["httponly_cookie_on_login"] = login_ok
    results["properties_verified"]["authenticated_via_cookie_get_me"] = auth_ok
    results["properties_verified"]["unauthenticated_get_me_blocked_401"] = unauth_ok
    results["properties_verified"]["logout_clears_cookie"] = logout_ok
    results["properties_verified"]["zero_token_storage_in_localstorage"] = zero_violations

    all_verified = all(results["properties_verified"].values())
    results["overall_verdict"] = "VERIFIED" if all_verified else "NOT VERIFIED"

    out_file = ROOT / "audit" / "remediation" / "ui01_token_storage_evidence.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nProperties Verified:")
    for prop, val in results["properties_verified"].items():
        print(f"  {prop}: {val}")
    print(f"\nFinal Verdict for UI-01: {results['overall_verdict']}")
    print(f"Saved evidence to {out_file}")

if __name__ == "__main__":
    verify_ui01()
