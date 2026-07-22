"""
scripts/test_taxii_client.py
------------------------------
Automated test script using official `taxii2-client` (v2.1) library
to query PhantomNet TAXII 2.1 server endpoints.

Week 18 Day 3 — AI/ML Developer Task
"""

import os
import sys
from typing import Any, Dict
from unittest.mock import patch

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from fastapi.testclient import TestClient
import requests

from fastapi import FastAPI

try:
    from backend.api.taxii import router as taxii_router, TaxiiContentNegotiationMiddleware
except ImportError:
    from api.taxii import router as taxii_router, TaxiiContentNegotiationMiddleware

app = FastAPI()
app.add_middleware(TaxiiContentNegotiationMiddleware)
app.include_router(taxii_router)

try:
    from taxii2client.v21 import ApiRoot, Collection, Server
    TAXII2_CLIENT_AVAILABLE = True
except ImportError:
    TAXII2_CLIENT_AVAILABLE = False


def test_taxii_client_integration():
    """
    Simulates taxii2-client requests hitting the PhantomNet FastAPI TAXII 2.1 server.
    """
    if not TAXII2_CLIENT_AVAILABLE:
        print("[!] taxii2-client library not available, skipping.")
        return

    test_client = TestClient(app)

    # Custom requests adapter that routes taxii2client HTTP calls directly to FastAPI TestClient
    def mock_requests_get(url, *args, **kwargs):
        path = url.replace("http://localhost:8000", "").replace("http://127.0.0.1:8000", "")
        headers = kwargs.get("headers", {})
        resp = test_client.get(path, headers=headers)

        mock_resp = requests.Response()
        mock_resp.status_code = resp.status_code
        mock_resp._content = resp.content
        mock_resp.headers.update(resp.headers)
        return mock_resp

    with patch("requests.Session.get", side_effect=mock_requests_get):
        server_url = "http://127.0.0.1:8000/taxii2/"
        server = Server(server_url)

        print(f"[+] Server Title: {server.title}")
        print(f"[+] Server Description: {server.description}")
        assert server.title == "PhantomNet TAXII 2.1 Server"
        assert len(server.api_roots) >= 1

        api_root = server.api_roots[0]
        print(f"[+] API Root Title: {api_root.title}")
        assert api_root.title == "PhantomNet Sentinel API Root"
        assert len(api_root.collections) >= 1

        collection = api_root.collections[0]
        print(f"[+] Collection Title: {collection.title}")
        assert collection.id == "sentinel-playbooks-approved"
        assert collection.can_read is True

        objects_bundle = collection.get_objects()
        print(f"[+] STIX Objects Bundle Type: {objects_bundle.get('type')}")
        assert objects_bundle.get("type") == "bundle"
        print("[SUCCESS] taxii2-client successfully consumed PhantomNet TAXII 2.1 Server!")


if __name__ == "__main__":
    test_taxii_client_integration()
