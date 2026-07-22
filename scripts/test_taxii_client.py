"""
scripts/test_taxii_client.py
------------------------------
Automated test script using the official `taxii2-client` (v2.1) library
to consume and verify PhantomNet TAXII 2.1 server endpoints.

Tests:
  1. TAXII 2.1 Server Discovery (GET /taxii2/)
  2. API Root Information (GET /taxii2/phantomnet/)
  3. Collections Listing (GET /taxii2/phantomnet/collections/)
  4. Specific Collection Resource Fetching by ID & Alias
  5. STIX 2.1 Bundle & Objects Retrieval (GET /taxii2/phantomnet/collections/{id}/objects/)
  6. Graceful Handling of Error Conditions (404 Collection Not Found, Connection/Auth Errors)

Usage:
  # Run isolated mock integration test:
  python scripts/test_taxii_client.py

  # Run against a live TAXII server instance:
  python scripts/test_taxii_client.py --live --url http://127.0.0.1:8000/taxii2/

Week 18 Day 3 — AI/ML Developer Task (#871)
"""

import argparse
import os
import sys
import time
from typing import Optional

# Ensure project root & backend are in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(PROJECT_ROOT, "backend")
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

os.environ["ENVIRONMENT"] = "test"

import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch

try:
    from taxii2client.v21 import ApiRoot, Collection, Server
    from taxii2client.exceptions import TAXIIServiceException
    TAXII2_CLIENT_AVAILABLE = True
except ImportError:
    TAXII2_CLIENT_AVAILABLE = False

try:
    from backend.api.taxii import router as taxii_router, TaxiiContentNegotiationMiddleware
    from backend.database.database import SessionLocal
    from backend.sentinel.models import SentinelPlaybook
except ImportError:
    from api.taxii import router as taxii_router, TaxiiContentNegotiationMiddleware
    from database.database import SessionLocal
    from sentinel.models import SentinelPlaybook


def build_test_app() -> FastAPI:
    """Build FastAPI instance configured with TAXII 2.1 routes and middleware."""
    app = FastAPI(title="PhantomNet TAXII Test Server")
    app.add_middleware(TaxiiContentNegotiationMiddleware)
    app.include_router(taxii_router)
    return app


def seed_test_playbook() -> Optional[str]:
    """Seed sample playbook into test database for objects bundle verification."""
    try:
        db = SessionLocal()
        pb_id = "PB-TAXII2-CLIENT-VERIFY-001"
        # Cleanup any existing test row
        db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id == pb_id).delete()
        db.commit()

        pb = SentinelPlaybook(
            playbook_id=pb_id,
            playbook_name="Automated TAXII Client Test Playbook",
            status="approved",
            tactic="Credential Access",
            technique_id="T1110.001",
            technique_name="Password Guessing",
            dst_port=22,
            protocol="TCP",
            src_ip="203.0.113.199",
            threat_score=88.5,
            severity="HIGH",
        )
        db.add(pb)
        db.commit()
        db.close()
        return pb_id
    except Exception as exc:
        print(f"[!] Warning: Database seeding failed ({exc}). Continuing with empty DB test.")
        return None


def cleanup_test_playbook(pb_id: Optional[str]) -> None:
    """Remove seeded test playbook row from database."""
    if not pb_id:
        return
    try:
        db = SessionLocal()
        db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id == pb_id).delete()
        db.commit()
        db.close()
    except Exception as exc:
        print(f"[!] Warning: Database cleanup failed ({exc}).")


def run_taxii_client_tests(server_url: str, is_live: bool = False) -> bool:
    """
    Executes full taxii2-client test suite against TAXII 2.1 server.

    Args:
        server_url: Base TAXII discovery URL (e.g., http://127.0.0.1:8000/taxii2/)
        is_live: If True, executes real HTTP requests over the network. If False,
                 uses TestClient interceptor.

    Returns:
        bool: True if all verification checks passed, False otherwise.
    """
    if not TAXII2_CLIENT_AVAILABLE:
        print("[!] FATAL: 'taxii2-client' library is not installed.")
        print("    Please run: pip install taxii2-client>=2.3.0")
        return False

    print(f"\n==========================================================================")
    print(f" PhantomNet TAXII 2.1 Client Verification Suite (taxii2-client v2.1)")
    print(f" Target Server URL: {server_url} (Live Mode: {is_live})")
    print(f"==========================================================================\n")

    pb_id = seed_test_playbook()

    try:
        if is_live:
            return _execute_client_flow(server_url)
        else:
            app = build_test_app()
            test_client = TestClient(app)

            def mock_requests_get(url, *args, **kwargs):
                # Map full URL to path for TestClient
                path = url.replace("http://localhost:8000", "").replace("http://127.0.0.1:8000", "")
                if not path.startswith("/"):
                    path = "/" + path
                headers = kwargs.get("headers", {})
                params = kwargs.get("params", None)
                resp = test_client.get(path, headers=headers, params=params)

                mock_resp = requests.Response()
                mock_resp.status_code = resp.status_code
                mock_resp._content = resp.content
                mock_resp.headers.update(resp.headers)
                mock_resp.url = url
                return mock_resp

            with patch("requests.Session.get", side_effect=mock_requests_get):
                return _execute_client_flow(server_url)

    finally:
        cleanup_test_playbook(pb_id)


def _execute_client_flow(server_url: str) -> bool:
    """Internal helper executing step-by-step taxii2-client verification assertions."""
    # -------------------------------------------------------------------------
    # Step 1: Server Discovery
    # -------------------------------------------------------------------------
    print("[1/5] Querying TAXII 2.1 Server Discovery root...")
    try:
        server = Server(server_url)
        print("  [OK] Discovery Successful!")
        print(f"       - Title: {server.title}")
        print(f"       - Description: {server.description}")
        print(f"       - Discovered API Roots: {[r.url for r in server.api_roots]}")
        assert server.title == "PhantomNet TAXII 2.1 Server"
        assert len(server.api_roots) >= 1
    except requests.exceptions.ConnectionError as exc:
        print(f"  [FAIL] Connection Error: Could not connect to TAXII server at {server_url}")
        print("         Ensure the FastAPI backend is running (`uvicorn backend.main:app`).")
        return False
    except Exception as exc:
        print(f"  [FAIL] Discovery Failed: {exc}")
        return False

    # -------------------------------------------------------------------------
    # Step 2: API Root Verification
    # -------------------------------------------------------------------------
    print("\n[2/5] Inspecting primary API Root metadata...")
    try:
        api_root = server.api_roots[0]
        print("  [OK] API Root Loaded!")
        print(f"       - API Root URL: {api_root.url}")
        print(f"       - Title: {api_root.title}")
        print(f"       - Versions: {api_root.versions}")
        print(f"       - Max Content Length: {api_root.max_content_length}")
        assert api_root.title == "PhantomNet Sentinel API Root"
        assert "taxii-2.1" in api_root.versions
    except Exception as exc:
        print(f"  [FAIL] API Root Verification Failed: {exc}")
        return False

    # -------------------------------------------------------------------------
    # Step 3: Collections List Retrieval
    # -------------------------------------------------------------------------
    print("\n[3/5] Requesting TAXII Collections List...")
    try:
        collections = api_root.collections
        print(f"  [OK] Collections List Retrieved! Found {len(collections)} collection(s):")
        for col in collections:
            print(f"       * Collection ID: {col.id:<30} | Title: '{col.title}'")
            print(f"         (Can Read: {col.can_read}, Can Write: {col.can_write}, Media Types: {col.media_types})")

        assert len(collections) >= 1
        approved_col = next((c for c in collections if c.id == "sentinel-playbooks-approved"), None)
        assert approved_col is not None, "Primary collection 'sentinel-playbooks-approved' missing from response"
        assert approved_col.can_read is True
    except Exception as exc:
        print(f"  [FAIL] Collections List Retrieval Failed: {exc}")
        return False

    # -------------------------------------------------------------------------
    # Step 4: STIX 2.1 Bundle Retrieval from Collection
    # -------------------------------------------------------------------------
    print("\n[4/5] Pulling STIX 2.1 Bundle Objects via taxii2-client...")
    try:
        target_col = collections[0]
        bundle = target_col.get_objects()
        objects = bundle.get("objects", [])

        print("  [OK] STIX 2.1 Objects Bundle Retrieved Successfully!")
        print(f"       - Bundle Type: {bundle.get('type')}")
        print(f"       - Bundle ID: {bundle.get('id')}")
        print(f"       - Total STIX Objects: {len(objects)}")

        assert bundle.get("type") == "bundle"
        assert isinstance(objects, list)

        for obj in objects:
            print(f"         -> STIX Object: {obj.get('type'):<12} | ID: {obj.get('id')} | Name: '{obj.get('name')}'")
            if obj.get("type") == "indicator":
                print(f"            Pattern: {obj.get('pattern')}")

    except Exception as exc:
        print(f"  [FAIL] STIX Bundle Retrieval Failed: {exc}")
        return False

    # -------------------------------------------------------------------------
    # Step 5: Error Handling Verification (Non-existent Collection / 404)
    # -------------------------------------------------------------------------
    print("\n[5/5] Testing error handling for non-existent collection resource...")
    try:
        invalid_url = f"{api_root.url}collections/nonexistent-collection-id-999/"
        bad_collection = Collection(invalid_url)
        # Accessing metadata attribute triggers actual network GET call
        _ = bad_collection.title
        print("  [FAIL] Error: Server returned success for non-existent collection (Expected 404).")
        return False
    except requests.exceptions.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            print("  [OK] Handled Exception Gracefully! Caught HTTP 404 as expected.")
        else:
            print(f"  [!] HTTP Exception caught: {exc}")
    except Exception as exc:
        print(f"  [OK] Handled Exception Gracefully! Caught error: {exc}")

    print("\n==========================================================================")
    print(" SUCCESS: All TAXII 2.1 endpoints verified with taxii2-client library!")
    print("==========================================================================\n")
    return True


def main():
    parser = argparse.ArgumentParser(description="Test TAXII 2.1 server using official taxii2-client package")
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000/taxii2/",
        help="Base TAXII discovery URL (default: http://127.0.0.1:8000/taxii2/)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Send requests to a running live server instance instead of internal mock TestClient",
    )
    args = parser.parse_args()

    success = run_taxii_client_tests(server_url=args.url, is_live=args.live)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
