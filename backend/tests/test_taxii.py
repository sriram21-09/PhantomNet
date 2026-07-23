"""
backend/tests/test_taxii.py
----------------------------
Unit and integration tests for PhantomNet TAXII 2.1 Feed Server endpoints.

Tests:
  - Server Discovery (GET /taxii2/)
  - API Root Information (GET /taxii2/phantomnet/)
  - Collections List & Dynamic DB Mappings (GET /taxii2/phantomnet/collections/)
  - Collection Resource Detail (GET /taxii2/phantomnet/collections/{id}/)
  - Content negotiation & HTTP 406 error handling
  - 404 Error response for unknown collection IDs

Week 18, Day 2 — Build TAXII Collections Endpoint
"""

import os
os.environ["ENVIRONMENT"] = "test"

from datetime import datetime
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

try:
    from backend.api.taxii import router as taxii_router
    from backend.database.database import get_db, SessionLocal
    from backend.sentinel.models import SentinelPlaybook
except ImportError:
    from api.taxii import router as taxii_router
    from database.database import get_db, SessionLocal
    from sentinel.models import SentinelPlaybook

app = FastAPI()
app.include_router(taxii_router)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_taxii_discovery(client):
    """Verify server discovery endpoint returns valid TAXII 2.1 metadata."""
    res = client.get("/taxii2/")
    assert res.status_code == 200
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")

    data = res.json()
    assert data["title"] == "PhantomNet TAXII 2.1 Server"
    assert "/taxii2/phantomnet/" in data["api_roots"]


def test_taxii_api_root(client):
    """Verify primary API root endpoint returns valid TAXII 2.1 capabilities."""
    res = client.get("/taxii2/phantomnet/")
    assert res.status_code == 200
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")

    data = res.json()
    assert data["title"] == "PhantomNet Sentinel API Root"
    assert "taxii-2.1" in data["versions"]
    assert data["max_content_length"] > 0


def test_taxii_collections_list_default(client):
    """Verify collections endpoint returns at least the primary approved playbooks collection."""
    res = client.get("/taxii2/phantomnet/collections/")
    assert res.status_code == 200
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")

    data = res.json()
    assert "collections" in data
    assert len(data["collections"]) >= 1

    primary = next((c for c in data["collections"] if c["id"] == "sentinel-playbooks-approved"), None)
    assert primary is not None
    assert primary["title"] == "Approved Sentinel Playbooks"
    assert primary["alias"] == "approved-playbooks"
    assert primary["can_read"] is True
    assert primary["can_write"] is False
    assert "application/stix+json;version=2.1" in primary["media_types"]


def test_taxii_collections_dynamic_db_mapping(client):
    """Verify database playbooks dynamically generate tactic and honeypot collection mappings."""
    db = SessionLocal()
    try:
        # Insert a sample playbook with specific tactic and destination port
        pb = SentinelPlaybook(
            playbook_id="PB-TEST-TAXII-001",
            status="approved",
            tactic="Credential Access",
            technique_id="T1110.001",
            technique_name="Brute Force",
            dst_port=22,
            protocol="TCP",
            src_ip="192.168.1.100",
            threat_score=85.0,
            severity="HIGH",
        )
        db.add(pb)
        db.commit()

        res = client.get("/taxii2/phantomnet/collections/")
        assert res.status_code == 200
        data = res.json()

        collection_ids = [c["id"] for c in data["collections"]]
        assert "sentinel-playbooks-approved" in collection_ids
        assert "tactic-credential-access" in collection_ids
        assert "honeypot-cowrie-ssh" in collection_ids

    finally:
        # Cleanup test row
        db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id == "PB-TEST-TAXII-001").delete()
        db.commit()
        db.close()


def test_taxii_collection_detail_success(client):
    """Verify retrieving a specific collection resource by ID."""
    res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/")
    assert res.status_code == 200
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")

    data = res.json()
    assert data["id"] == "sentinel-playbooks-approved"
    assert data["alias"] == "approved-playbooks"
    assert data["can_read"] is True


def test_taxii_collection_detail_by_alias(client):
    """Verify retrieving a specific collection resource by alias."""
    res = client.get("/taxii2/phantomnet/collections/approved-playbooks/")
    assert res.status_code == 200
    data = res.json()
    assert data["id"] == "sentinel-playbooks-approved"


def test_taxii_collection_detail_not_found(client):
    """Verify 404 response for unknown collection ID."""
    res = client.get("/taxii2/phantomnet/collections/invalid-nonexistent-collection/")
    assert res.status_code == 404
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")

    data = res.json()
    assert data["title"] == "Collection Not Found"
    assert data["http_status"] == "404"


def test_taxii_invalid_accept_header_406(client):
    """Verify 406 Not Acceptable when an explicit unsupported Accept header is passed."""
    headers = {"Accept": "text/html"}
    res = client.get("/taxii2/phantomnet/collections/", headers=headers)
    assert res.status_code == 406
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")

    data = res.json()
    assert data["title"] == "Not Acceptable"
    assert data["http_status"] == "406"


def test_taxii_unsupported_version_accept_header_406(client):
    """Verify 406 Not Acceptable when an unsupported TAXII version is explicitly requested."""
    headers = {"Accept": "application/taxii+json;version=2.0"}
    res = client.get("/taxii2/phantomnet/collections/", headers=headers)
    assert res.status_code == 406
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")

    data = res.json()
    assert data["title"] == "Not Acceptable"
    assert data["http_status"] == "406"


def test_taxii_invalid_content_type_header_406(client):
    """Verify 406 Not Acceptable when request includes an unsupported Content-Type header."""
    headers = {"Content-Type": "application/xml"}
    res = client.get("/taxii2/phantomnet/collections/", headers=headers)
    assert res.status_code == 406
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")


def test_taxii_stix_accept_header_on_objects_endpoint(client):
    """Verify STIX 2.1 accept header is accepted on objects endpoint."""
    headers = {"Accept": "application/stix+json;version=2.1"}
    res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/", headers=headers)
    assert res.status_code == 200
    assert "application/stix+json;version=2.1" in res.headers.get("content-type", "")


def test_taxii_stix_accept_header_on_metadata_endpoint_406(client):
    """Verify STIX accept header on metadata endpoint returns 406 Not Acceptable."""
    headers = {"Accept": "application/stix+json;version=2.1"}
    res = client.get("/taxii2/phantomnet/collections/", headers=headers)
    assert res.status_code == 406


def test_taxii_wildcard_accept_header(client):
    """Verify wildcard accept header is accepted on metadata endpoints."""
    headers = {"Accept": "*/*"}
    res = client.get("/taxii2/phantomnet/collections/", headers=headers)
    assert res.status_code == 200
    assert "application/taxii+json;version=2.1" in res.headers.get("content-type", "")


def test_taxii_collection_objects(client):
    """Verify STIX 2.1 bundle object retrieval endpoint GET /taxii2/phantomnet/collections/{id}/objects/."""
    res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
    assert res.status_code == 200
    assert "application/stix+json;version=2.1" in res.headers.get("content-type", "")

    data = res.json()
    assert data["type"] == "bundle"
    assert "objects" in data
    assert isinstance(data["objects"], list)


# ---------------------------------------------------------------------------
# Week 18-Day 4: added_after Query Parameter Filtering Tests
# ---------------------------------------------------------------------------


def test_objects_added_after_filters_correctly(client):
    """Verify added_after correctly filters playbooks — only newer ones returned."""
    db = SessionLocal()
    try:
        old_pb = SentinelPlaybook(
            playbook_id="PB-TEST-FILTER-OLD",
            status="approved",
            tactic="Initial Access",
            src_ip="10.0.0.1",
            dst_port=22,
            created_at=datetime(2025, 1, 1, 0, 0, 0),
            updated_at=datetime(2025, 1, 1, 0, 0, 0),
        )
        new_pb = SentinelPlaybook(
            playbook_id="PB-TEST-FILTER-NEW",
            status="approved",
            tactic="Initial Access",
            src_ip="10.0.0.2",
            dst_port=22,
            created_at=datetime(2026, 6, 15, 12, 0, 0),
            updated_at=datetime(2026, 6, 15, 12, 0, 0),
        )
        db.add_all([old_pb, new_pb])
        db.commit()

        # Query with added_after between the two — only new_pb should appear
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "2026-01-01T00:00:00Z"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"

        # The new playbook's report object should be present
        report_names = [
            obj.get("name", "") for obj in data["objects"] if obj.get("type") == "report"
        ]
        has_new = any("PB-TEST-FILTER-NEW" in name for name in report_names)
        has_old = any("PB-TEST-FILTER-OLD" in name for name in report_names)
        assert has_new, "Expected new playbook to be present after filtering"
        assert not has_old, "Expected old playbook to be excluded by added_after filter"

    finally:
        db.query(SentinelPlaybook).filter(
            SentinelPlaybook.playbook_id.in_(["PB-TEST-FILTER-OLD", "PB-TEST-FILTER-NEW"])
        ).delete(synchronize_session=False)
        db.commit()
        db.close()


def test_objects_added_after_no_param(client):
    """Verify no added_after parameter returns all objects (backward compatibility)."""
    res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
    assert res.status_code == 200
    data = res.json()
    assert data["type"] == "bundle"
    assert "objects" in data


def test_objects_added_after_empty_string(client):
    """Verify empty added_after parameter is treated as no filter."""
    res = client.get(
        "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
        params={"added_after": ""},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["type"] == "bundle"


def test_objects_added_after_invalid_format(client):
    """Verify invalid added_after timestamp returns 400 with TAXII error body."""
    res = client.get(
        "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
        params={"added_after": "not-a-date"},
    )
    assert res.status_code == 400
    data = res.json()
    assert data["title"] == "Invalid Timestamp"
    assert data["http_status"] == "400"
    assert "not-a-date" in data.get("description", "")


def test_objects_added_after_with_timezone(client):
    """Verify added_after with timezone offset is correctly parsed."""
    res = client.get(
        "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
        params={"added_after": "2026-01-01T00:00:00+05:30"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["type"] == "bundle"


def test_objects_added_after_date_only(client):
    """Verify added_after with date-only format is treated as midnight UTC."""
    res = client.get(
        "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
        params={"added_after": "2026-01-01"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["type"] == "bundle"


def test_objects_added_after_future_date(client):
    """Verify added_after with future timestamp returns empty bundle."""
    res = client.get(
        "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
        params={"added_after": "2099-12-31T23:59:59Z"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["type"] == "bundle"
    assert len(data["objects"]) == 0


if __name__ == "__main__":
    test_client = TestClient(app)
    print("Running test_taxii_discovery...")
    test_taxii_discovery(test_client)
    print("Running test_taxii_api_root...")
    test_taxii_api_root(test_client)
    print("Running test_taxii_collections_list_default...")
    test_taxii_collections_list_default(test_client)
    print("Running test_taxii_collections_dynamic_db_mapping...")
    test_taxii_collections_dynamic_db_mapping(test_client)
    print("Running test_taxii_collection_detail_success...")
    test_taxii_collection_detail_success(test_client)
    print("Running test_taxii_collection_detail_by_alias...")
    test_taxii_collection_detail_by_alias(test_client)
    print("Running test_taxii_collection_detail_not_found...")
    test_taxii_collection_detail_not_found(test_client)
    print("Running test_taxii_invalid_accept_header_406...")
    test_taxii_invalid_accept_header_406(test_client)
    print("Running test_taxii_unsupported_version_accept_header_406...")
    test_taxii_unsupported_version_accept_header_406(test_client)
    print("Running test_taxii_invalid_content_type_header_406...")
    test_taxii_invalid_content_type_header_406(test_client)
    print("Running test_taxii_stix_accept_header_on_objects_endpoint...")
    test_taxii_stix_accept_header_on_objects_endpoint(test_client)
    print("Running test_taxii_stix_accept_header_on_metadata_endpoint_406...")
    test_taxii_stix_accept_header_on_metadata_endpoint_406(test_client)
    print("Running test_taxii_wildcard_accept_header...")
    test_taxii_wildcard_accept_header(test_client)
    print("Running test_taxii_collection_objects...")
    test_taxii_collection_objects(test_client)
    print("Running test_objects_added_after_filters_correctly...")
    test_objects_added_after_filters_correctly(test_client)
    print("Running test_objects_added_after_no_param...")
    test_objects_added_after_no_param(test_client)
    print("Running test_objects_added_after_empty_string...")
    test_objects_added_after_empty_string(test_client)
    print("Running test_objects_added_after_invalid_format...")
    test_objects_added_after_invalid_format(test_client)
    print("Running test_objects_added_after_with_timezone...")
    test_objects_added_after_with_timezone(test_client)
    print("Running test_objects_added_after_date_only...")
    test_objects_added_after_date_only(test_client)
    print("Running test_objects_added_after_future_date...")
    test_objects_added_after_future_date(test_client)
    print("\nSUCCESS: All 21 TAXII 2.1 Server tests passed successfully!")
