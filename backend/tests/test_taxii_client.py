"""
backend/tests/test_taxii_client.py
-----------------------------------
Pytest automated unit/integration tests using the official `taxii2-client` (v2.1) library
to query PhantomNet TAXII 2.1 server endpoints.

Tests:
  - Server Discovery via taxii2client.v21.Server
  - API Root metadata retrieval via taxii2client
  - Collections listing via ApiRoot.collections
  - Collection STIX bundle retrieval via Collection.get_objects()
  - Error handling for invalid collection requests

Week 18, Day 3 — Test TAXII Endpoints with taxii2-client Library (#871)
"""

import os
os.environ["ENVIRONMENT"] = "test"

from unittest.mock import patch
import pytest
import requests
from fastapi import FastAPI
from fastapi.testclient import TestClient

try:
    from taxii2client.v21 import ApiRoot, Collection, Server
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


app = FastAPI()
app.add_middleware(TaxiiContentNegotiationMiddleware)
app.include_router(taxii_router)


@pytest.fixture(scope="module")
def test_client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def mocked_taxii_session(test_client):
    """Fixture wrapping requests.Session.get to route taxii2client calls to TestClient."""
    def mock_get(url, *args, **kwargs):
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

    with patch("requests.Session.get", side_effect=mock_get) as p:
        yield p


@pytest.mark.skipif(not TAXII2_CLIENT_AVAILABLE, reason="taxii2-client library not installed")
def test_taxii2_client_discovery(mocked_taxii_session):
    """Verify taxii2-client Server class connects to discovery endpoint."""
    server = Server("http://127.0.0.1:8000/taxii2/")
    assert server.title == "PhantomNet TAXII 2.1 Server"
    assert len(server.api_roots) >= 1
    assert "http://127.0.0.1:8000/taxii2/phantomnet/" in [r.url for r in server.api_roots]


@pytest.mark.skipif(not TAXII2_CLIENT_AVAILABLE, reason="taxii2-client library not installed")
def test_taxii2_client_api_root(mocked_taxii_session):
    """Verify taxii2-client reads ApiRoot attributes successfully."""
    server = Server("http://127.0.0.1:8000/taxii2/")
    api_root = server.api_roots[0]
    assert api_root.title == "PhantomNet Sentinel API Root"
    assert "taxii-2.1" in api_root.versions
    assert api_root.max_content_length > 0


@pytest.mark.skipif(not TAXII2_CLIENT_AVAILABLE, reason="taxii2-client library not installed")
def test_taxii2_client_collections(mocked_taxii_session):
    """Verify taxii2-client lists available collection resources."""
    server = Server("http://127.0.0.1:8000/taxii2/")
    api_root = server.api_roots[0]
    cols = api_root.collections
    assert len(cols) >= 1

    primary = next((c for c in cols if c.id == "sentinel-playbooks-approved"), None)
    assert primary is not None
    assert primary.title == "Approved Sentinel Playbooks"
    assert primary.can_read is True
    assert primary.can_write is False


@pytest.mark.skipif(not TAXII2_CLIENT_AVAILABLE, reason="taxii2-client library not installed")
def test_taxii2_client_get_objects(mocked_taxii_session):
    """Verify taxii2-client Collection.get_objects() retrieves a valid STIX 2.1 bundle."""
    db = SessionLocal()
    pb_id = "PB-TAXII2-CLIENT-PYTEST-001"
    try:
        # Insert test playbook row
        pb = SentinelPlaybook(
            playbook_id=pb_id,
            playbook_name="Pytest TAXII Client Playbook",
            status="approved",
            tactic="Initial Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            dst_port=80,
            protocol="TCP",
            src_ip="198.51.100.77",
            threat_score=92.0,
            severity="CRITICAL",
        )
        db.add(pb)
        db.commit()

        server = Server("http://127.0.0.1:8000/taxii2/")
        api_root = server.api_roots[0]
        col = api_root.collections[0]

        bundle = col.get_objects()
        assert bundle.get("type") == "bundle"
        assert "objects" in bundle
        assert isinstance(bundle["objects"], list)

        # Check for indicator object in bundle
        indicator = next((o for o in bundle["objects"] if o.get("type") == "indicator" and "198.51.100.77" in o.get("pattern", "")), None)
        assert indicator is not None
        assert indicator["pattern"] == "[ipv4-addr:value = '198.51.100.77']"

    finally:
        db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id == pb_id).delete()
        db.commit()
        db.close()


@pytest.mark.skipif(not TAXII2_CLIENT_AVAILABLE, reason="taxii2-client library not installed")
def test_taxii2_client_error_handling(mocked_taxii_session):
    """Verify taxii2-client handles HTTP errors gracefully when requesting non-existent collection."""
    invalid_url = "http://127.0.0.1:8000/taxii2/phantomnet/collections/invalid-collection-id/"
    bad_col = Collection(invalid_url)
    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        _ = bad_col.title
    assert exc_info.value.response.status_code == 404
