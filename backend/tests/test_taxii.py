"""
backend/tests/test_taxii.py
----------------------------
Comprehensive unit and integration tests for PhantomNet TAXII 2.1 Feed Server.

Coverage Matrix:
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ Endpoint                                    │ Tests  │ HTTP Codes     │
  ├─────────────────────────────────────────────────────────────────────────┤
  │ GET /taxii2/                (Discovery)      │  6     │ 200, 406       │
  │ GET /taxii2/phantomnet/     (API Root)        │  5     │ 200, 406       │
  │ GET /taxii2/phantomnet/collections/           │  7     │ 200, 406       │
  │ GET /taxii2/phantomnet/collections/{id}/      │  6     │ 200, 404, 406  │
  │ GET /taxii2/phantomnet/collections/{id}/objects/│ 20   │ 200,400,406    │
  │ Content Negotiation (cross-endpoint)         │  8     │ 406            │
  │ HTTP Method Validation                       │  3     │ 405            │
  └─────────────────────────────────────────────────────────────────────────┘

Week 18, Day 4 — Comprehensive TAXII Endpoint Test Suite (AI/ML Developer)
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

TAXII_CT = "application/taxii+json;version=2.1"
STIX_CT = "application/stix+json;version=2.1"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def seeded_db():
    """Insert test playbooks into the database for integration tests and clean up after."""
    db = SessionLocal()
    test_playbooks = [
        SentinelPlaybook(
            playbook_id="PB-TEST-COMPREHENSIVE-001",
            status="approved",
            tactic="Credential Access",
            technique_id="T1110.001",
            technique_name="Brute Force: Password Guessing",
            dst_port=22,
            protocol="TCP",
            src_ip="192.168.1.100",
            threat_score=85.0,
            severity="HIGH",
            playbook_name="SSH Brute Force Response",
            playbook_content="## Playbook: SSH Brute Force\nBlock source IP.",
            created_at=datetime(2026, 3, 15, 10, 0, 0),
            updated_at=datetime(2026, 3, 15, 10, 0, 0),
        ),
        SentinelPlaybook(
            playbook_id="PB-TEST-COMPREHENSIVE-002",
            status="approved",
            tactic="Initial Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            dst_port=80,
            protocol="TCP",
            src_ip="10.0.0.50",
            threat_score=92.0,
            severity="CRITICAL",
            playbook_name="Web Exploit Detection",
            playbook_content="## Playbook: Web Exploit\nAnalyze HTTP payloads.",
            created_at=datetime(2026, 6, 20, 14, 30, 0),
            updated_at=datetime(2026, 6, 20, 14, 30, 0),
        ),
        SentinelPlaybook(
            playbook_id="PB-TEST-COMPREHENSIVE-003",
            status="pending",
            tactic="Credential Access",
            technique_id="T1110.003",
            technique_name="Brute Force: Password Spraying",
            dst_port=3306,
            protocol="TCP",
            src_ip="172.16.0.5",
            threat_score=60.0,
            severity="MEDIUM",
            created_at=datetime(2025, 1, 10, 8, 0, 0),
            updated_at=datetime(2025, 1, 10, 8, 0, 0),
        ),
    ]
    for pb in test_playbooks:
        db.add(pb)
    db.commit()
    yield db
    # Cleanup
    for pb_id in ["PB-TEST-COMPREHENSIVE-001", "PB-TEST-COMPREHENSIVE-002", "PB-TEST-COMPREHENSIVE-003"]:
        db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id == pb_id).delete()
    db.commit()
    db.close()


# =============================================================================
# Section 1: Server Discovery Endpoint — GET /taxii2/
# =============================================================================


class TestTaxiiDiscovery:
    """Tests for TAXII 2.1 Server Discovery endpoint."""

    def test_discovery_returns_200(self, client):
        """Verify discovery endpoint returns HTTP 200 with correct content type."""
        res = client.get("/taxii2/")
        assert res.status_code == 200
        assert TAXII_CT in res.headers.get("content-type", "")

    def test_discovery_response_schema(self, client):
        """Verify discovery response contains all required TAXII 2.1 fields."""
        data = client.get("/taxii2/").json()
        assert data["title"] == "PhantomNet TAXII 2.1 Server"
        assert "description" in data
        assert "contact" in data
        assert "default" in data
        assert isinstance(data["api_roots"], list)
        assert "/taxii2/phantomnet/" in data["api_roots"]

    def test_discovery_without_trailing_slash(self, client):
        """Verify discovery works without trailing slash (alternate route)."""
        res = client.get("/taxii2")
        assert res.status_code == 200
        data = res.json()
        assert data["title"] == "PhantomNet TAXII 2.1 Server"

    def test_discovery_invalid_accept_header_406(self, client):
        """Verify 406 when unsupported Accept header sent to discovery."""
        res = client.get("/taxii2/", headers={"Accept": "text/html"})
        assert res.status_code == 406
        data = res.json()
        assert data["title"] == "Not Acceptable"
        assert data["http_status"] == "406"

    def test_discovery_invalid_content_type_406(self, client):
        """Verify 406 when unsupported Content-Type sent to discovery."""
        res = client.get("/taxii2/", headers={"Content-Type": "application/xml"})
        assert res.status_code == 406

    def test_discovery_valid_json_accept_header(self, client):
        """Verify application/json Accept header is accepted on discovery."""
        res = client.get("/taxii2/", headers={"Accept": "application/json"})
        assert res.status_code == 200


# =============================================================================
# Section 2: API Root Information Endpoint — GET /taxii2/phantomnet/
# =============================================================================


class TestTaxiiApiRoot:
    """Tests for TAXII 2.1 API Root Information endpoint."""

    def test_api_root_returns_200(self, client):
        """Verify API root returns HTTP 200 with TAXII content type."""
        res = client.get("/taxii2/phantomnet/")
        assert res.status_code == 200
        assert TAXII_CT in res.headers.get("content-type", "")

    def test_api_root_response_schema(self, client):
        """Verify API root response contains all required TAXII 2.1 fields."""
        data = client.get("/taxii2/phantomnet/").json()
        assert data["title"] == "PhantomNet Sentinel API Root"
        assert "description" in data
        assert isinstance(data["versions"], list)
        assert "taxii-2.1" in data["versions"]
        assert data["max_content_length"] > 0

    def test_api_root_without_trailing_slash(self, client):
        """Verify API root works without trailing slash."""
        res = client.get("/taxii2/phantomnet")
        assert res.status_code == 200
        data = res.json()
        assert data["title"] == "PhantomNet Sentinel API Root"

    def test_api_root_invalid_accept_406(self, client):
        """Verify 406 when unsupported Accept header sent to API root."""
        res = client.get("/taxii2/phantomnet/", headers={"Accept": "text/plain"})
        assert res.status_code == 406

    def test_api_root_stix_accept_on_metadata_406(self, client):
        """Verify STIX-only Accept header rejected on metadata endpoint."""
        res = client.get("/taxii2/phantomnet/", headers={"Accept": STIX_CT})
        assert res.status_code == 406


# =============================================================================
# Section 3: Collections List Endpoint — GET /taxii2/phantomnet/collections/
# =============================================================================


class TestTaxiiCollectionsList:
    """Tests for TAXII 2.1 Collections List endpoint."""

    def test_collections_returns_200(self, client):
        """Verify collections endpoint returns HTTP 200."""
        res = client.get("/taxii2/phantomnet/collections/")
        assert res.status_code == 200
        assert TAXII_CT in res.headers.get("content-type", "")

    def test_collections_contains_primary(self, client):
        """Verify primary approved playbooks collection is always present."""
        data = client.get("/taxii2/phantomnet/collections/").json()
        assert "collections" in data
        assert len(data["collections"]) >= 1

        primary = next((c for c in data["collections"] if c["id"] == "sentinel-playbooks-approved"), None)
        assert primary is not None
        assert primary["title"] == "Approved Sentinel Playbooks"
        assert primary["alias"] == "approved-playbooks"
        assert primary["can_read"] is True
        assert primary["can_write"] is False
        assert STIX_CT in primary["media_types"]

    def test_collections_dynamic_tactic_mapping(self, client, seeded_db):
        """Verify tactic-based dynamic collections are created from DB playbooks."""
        data = client.get("/taxii2/phantomnet/collections/").json()
        collection_ids = [c["id"] for c in data["collections"]]
        assert "tactic-credential-access" in collection_ids
        assert "tactic-initial-access" in collection_ids

    def test_collections_dynamic_honeypot_mapping(self, client, seeded_db):
        """Verify honeypot port-based dynamic collections are created from DB playbooks."""
        data = client.get("/taxii2/phantomnet/collections/").json()
        collection_ids = [c["id"] for c in data["collections"]]
        assert "honeypot-cowrie-ssh" in collection_ids
        assert "honeypot-web-http" in collection_ids
        assert "honeypot-dionaea-mysql" in collection_ids

    def test_collections_without_trailing_slash(self, client):
        """Verify collections works without trailing slash."""
        res = client.get("/taxii2/phantomnet/collections")
        assert res.status_code == 200

    def test_collections_invalid_accept_406(self, client):
        """Verify 406 when unsupported Accept header sent to collections."""
        res = client.get("/taxii2/phantomnet/collections/", headers={"Accept": "text/html"})
        assert res.status_code == 406
        data = res.json()
        assert data["title"] == "Not Acceptable"
        assert data["http_status"] == "406"

    def test_collections_stix_only_accept_406(self, client):
        """Verify STIX-only Accept header rejected on collections metadata endpoint."""
        res = client.get("/taxii2/phantomnet/collections/", headers={"Accept": STIX_CT})
        assert res.status_code == 406


# =============================================================================
# Section 4: Collection Detail Endpoint — GET /taxii2/phantomnet/collections/{id}/
# =============================================================================


class TestTaxiiCollectionDetail:
    """Tests for TAXII 2.1 Collection Resource Detail endpoint."""

    def test_collection_detail_by_id(self, client):
        """Verify retrieving collection by its canonical ID."""
        res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/")
        assert res.status_code == 200
        assert TAXII_CT in res.headers.get("content-type", "")
        data = res.json()
        assert data["id"] == "sentinel-playbooks-approved"
        assert data["can_read"] is True

    def test_collection_detail_by_alias(self, client):
        """Verify retrieving collection by its alias."""
        res = client.get("/taxii2/phantomnet/collections/approved-playbooks/")
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == "sentinel-playbooks-approved"

    def test_collection_detail_without_trailing_slash(self, client):
        """Verify collection detail works without trailing slash."""
        res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved")
        assert res.status_code == 200

    def test_collection_detail_not_found_404(self, client):
        """Verify 404 response for unknown collection ID."""
        res = client.get("/taxii2/phantomnet/collections/nonexistent-collection-xyz/")
        assert res.status_code == 404
        assert TAXII_CT in res.headers.get("content-type", "")
        data = res.json()
        assert data["title"] == "Collection Not Found"
        assert data["http_status"] == "404"
        assert "nonexistent-collection-xyz" in data.get("description", "")

    def test_collection_detail_dynamic_tactic_collection(self, client, seeded_db):
        """Verify dynamically created tactic collection detail is accessible."""
        res = client.get("/taxii2/phantomnet/collections/tactic-credential-access/")
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == "tactic-credential-access"
        assert data["can_read"] is True

    def test_collection_detail_dynamic_by_alias(self, client, seeded_db):
        """Verify dynamically created collection accessible by alias."""
        res = client.get("/taxii2/phantomnet/collections/credential-access/")
        assert res.status_code == 200
        data = res.json()
        assert data["id"] == "tactic-credential-access"


# =============================================================================
# Section 5: Collection Objects Endpoint — GET /taxii2/phantomnet/collections/{id}/objects/
# =============================================================================


class TestTaxiiCollectionObjects:
    """Tests for TAXII 2.1 STIX Objects retrieval endpoint."""

    def test_objects_returns_stix_bundle(self, client):
        """Verify objects endpoint returns a valid STIX 2.1 bundle."""
        res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
        assert res.status_code == 200
        assert STIX_CT in res.headers.get("content-type", "")
        data = res.json()
        assert data["type"] == "bundle"
        assert "id" in data
        assert data["id"].startswith("bundle--")
        assert "objects" in data
        assert isinstance(data["objects"], list)

    def test_objects_without_trailing_slash(self, client):
        """Verify objects endpoint works without trailing slash."""
        res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects")
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"

    def test_objects_stix_accept_header(self, client):
        """Verify STIX Accept header accepted on objects endpoint."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            headers={"Accept": STIX_CT},
        )
        assert res.status_code == 200
        assert STIX_CT in res.headers.get("content-type", "")

    def test_objects_taxii_accept_returns_taxii_ct(self, client):
        """Verify TAXII Accept header on objects returns TAXII content type."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            headers={"Accept": TAXII_CT},
        )
        assert res.status_code == 200
        assert TAXII_CT in res.headers.get("content-type", "")

    def test_objects_contains_report_and_indicator(self, client, seeded_db):
        """Verify STIX bundle contains report objects and indicator objects with src_ip."""
        res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
        data = res.json()
        object_types = {obj["type"] for obj in data["objects"]}
        assert "report" in object_types, "Expected 'report' STIX objects in bundle"
        assert "indicator" in object_types, "Expected 'indicator' STIX objects in bundle"

    def test_objects_report_structure(self, client, seeded_db):
        """Verify report STIX objects have required fields."""
        res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
        data = res.json()
        reports = [obj for obj in data["objects"] if obj["type"] == "report"]
        assert len(reports) > 0
        for report in reports:
            assert report["id"].startswith("report--")
            assert "name" in report
            assert "created" in report
            assert "modified" in report
            assert "object_refs" in report
            assert isinstance(report["object_refs"], list)

    def test_objects_indicator_structure(self, client, seeded_db):
        """Verify indicator STIX objects have required fields."""
        res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
        data = res.json()
        indicators = [obj for obj in data["objects"] if obj["type"] == "indicator"]
        assert len(indicators) > 0
        for ind in indicators:
            assert ind["id"].startswith("indicator--")
            assert "name" in ind
            assert "pattern" in ind
            assert "pattern_type" in ind
            assert ind["pattern_type"] == "stix"
            assert "valid_from" in ind

    def test_objects_tactic_collection_filter(self, client, seeded_db):
        """Verify tactic collection only returns playbooks matching that tactic."""
        res = client.get("/taxii2/phantomnet/collections/tactic-credential-access/objects/")
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"
        # Should contain reports for credential-access playbooks (PB-001 and PB-003)
        report_names = [obj.get("name", "") for obj in data["objects"] if obj.get("type") == "report"]
        assert len(report_names) > 0

    def test_objects_honeypot_collection_filter(self, client, seeded_db):
        """Verify honeypot collection only returns playbooks for that port."""
        res = client.get("/taxii2/phantomnet/collections/honeypot-cowrie-ssh/objects/")
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"
        # Should contain at least PB-001 (dst_port=22)
        report_names = [obj.get("name", "") for obj in data["objects"] if obj.get("type") == "report"]
        has_ssh = any("SSH" in name or "PB-TEST-COMPREHENSIVE-001" in name for name in report_names)
        assert has_ssh, "Expected SSH honeypot playbook in cowrie-ssh collection"

    def test_objects_invalid_accept_406(self, client):
        """Verify 406 when unsupported Accept header sent to objects endpoint."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            headers={"Accept": "text/html"},
        )
        assert res.status_code == 406
        data = res.json()
        assert data["title"] == "Not Acceptable"


# =============================================================================
# Section 6: added_after Query Parameter Filtering
# =============================================================================


class TestAddedAfterFiltering:
    """Tests for added_after timestamp query parameter on the objects endpoint."""

    def test_added_after_filters_correctly(self, client, seeded_db):
        """Verify added_after returns only playbooks created after the timestamp."""
        # PB-003 created 2025-01-10, PB-001 created 2026-03-15, PB-002 created 2026-06-20
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "2026-06-01T00:00:00Z"},
        )
        assert res.status_code == 200
        data = res.json()
        reports = [obj for obj in data["objects"] if obj.get("type") == "report"]
        # Only PB-002 (2026-06-20) should appear
        report_names = [r.get("name", "") for r in reports]
        has_002 = any("Web Exploit" in n or "PB-TEST-COMPREHENSIVE-002" in n for n in report_names)
        has_001 = any("SSH Brute" in n or "PB-TEST-COMPREHENSIVE-001" in n for n in report_names)
        assert has_002, "Expected PB-002 (after 2026-06-01) to be present"
        assert not has_001, "Expected PB-001 (before 2026-06-01) to be excluded"

    def test_added_after_no_param_returns_all(self, client):
        """Verify omitting added_after returns all objects (backward compatibility)."""
        res = client.get("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"
        assert "objects" in data

    def test_added_after_empty_string_no_filter(self, client):
        """Verify empty added_after string treated as no filter."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": ""},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"

    def test_added_after_invalid_format_400(self, client):
        """Verify invalid timestamp returns 400 with TAXII error body."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "not-a-date"},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["title"] == "Invalid Timestamp"
        assert data["http_status"] == "400"
        assert "not-a-date" in data.get("description", "")

    def test_added_after_garbage_timestamp_400(self, client):
        """Verify random garbage string returns 400."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "yesterday"},
        )
        assert res.status_code == 400
        data = res.json()
        assert data["http_status"] == "400"

    def test_added_after_with_z_suffix(self, client):
        """Verify Z suffix timestamp is correctly parsed."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "2026-07-01T00:00:00Z"},
        )
        assert res.status_code == 200

    def test_added_after_with_positive_offset(self, client):
        """Verify positive timezone offset is correctly parsed."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "2026-01-01T00:00:00+05:30"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"

    def test_added_after_with_negative_offset(self, client):
        """Verify negative timezone offset is correctly parsed."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "2026-01-01T12:00:00-08:00"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"

    def test_added_after_date_only(self, client):
        """Verify date-only format treated as midnight UTC."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "2026-01-01"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"

    def test_added_after_future_date_empty_bundle(self, client):
        """Verify future timestamp returns empty bundle."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "2099-12-31T23:59:59Z"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["type"] == "bundle"
        assert len(data["objects"]) == 0

    def test_added_after_with_microseconds(self, client):
        """Verify microsecond precision timestamp is parsed correctly."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "2026-01-01T00:00:00.123456Z"},
        )
        assert res.status_code == 200


# =============================================================================
# Section 7: Content Negotiation — Cross-Endpoint Header Validation
# =============================================================================


class TestContentNegotiation:
    """Tests for TAXII 2.1 content negotiation across all endpoints."""

    def test_wildcard_accept_accepted(self, client):
        """Verify */* wildcard Accept header is accepted on metadata endpoints."""
        res = client.get("/taxii2/phantomnet/collections/", headers={"Accept": "*/*"})
        assert res.status_code == 200
        assert TAXII_CT in res.headers.get("content-type", "")

    def test_application_wildcard_accept_accepted(self, client):
        """Verify application/* wildcard Accept header is accepted."""
        res = client.get("/taxii2/phantomnet/collections/", headers={"Accept": "application/*"})
        assert res.status_code == 200

    def test_unsupported_taxii_version_406(self, client):
        """Verify wrong TAXII version in Accept header returns 406."""
        res = client.get(
            "/taxii2/phantomnet/collections/",
            headers={"Accept": "application/taxii+json;version=2.0"},
        )
        assert res.status_code == 406
        data = res.json()
        assert data["title"] == "Not Acceptable"

    def test_unsupported_content_type_406(self, client):
        """Verify unsupported Content-Type header returns 406."""
        res = client.get(
            "/taxii2/phantomnet/collections/",
            headers={"Content-Type": "application/xml"},
        )
        assert res.status_code == 406

    def test_content_type_wrong_version_406(self, client):
        """Verify Content-Type with wrong version returns 406."""
        res = client.get(
            "/taxii2/phantomnet/collections/",
            headers={"Content-Type": "application/taxii+json;version=1.0"},
        )
        assert res.status_code == 406

    def test_multi_value_accept_with_valid(self, client):
        """Verify multi-value Accept header containing a valid type succeeds."""
        res = client.get(
            "/taxii2/phantomnet/collections/",
            headers={"Accept": "text/html, application/taxii+json;version=2.1"},
        )
        assert res.status_code == 200

    def test_multi_value_accept_all_invalid_406(self, client):
        """Verify multi-value Accept header with all invalid types returns 406."""
        res = client.get(
            "/taxii2/phantomnet/collections/",
            headers={"Accept": "text/html, text/plain, image/png"},
        )
        assert res.status_code == 406

    def test_stix_accept_on_objects_200(self, client):
        """Verify STIX Accept header works specifically on objects endpoint."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            headers={"Accept": STIX_CT},
        )
        assert res.status_code == 200
        assert STIX_CT in res.headers.get("content-type", "")

    def test_stix_accept_on_metadata_endpoint_406(self, client):
        """Verify STIX-only Accept header rejected on collections metadata."""
        res = client.get(
            "/taxii2/phantomnet/collections/",
            headers={"Accept": STIX_CT},
        )
        assert res.status_code == 406

    def test_json_accept_header_on_discovery(self, client):
        """Verify plain application/json Accept is accepted."""
        res = client.get("/taxii2/", headers={"Accept": "application/json"})
        assert res.status_code == 200

    def test_no_accept_header_defaults_200(self, client):
        """Verify no Accept header at all defaults to success."""
        res = client.get("/taxii2/")
        assert res.status_code == 200


# =============================================================================
# Section 8: HTTP Method Validation
# =============================================================================


class TestHttpMethodValidation:
    """Verify unsupported HTTP methods return 405 Method Not Allowed."""

    def test_post_on_discovery_405(self, client):
        """Verify POST to discovery endpoint returns 405."""
        res = client.post("/taxii2/")
        assert res.status_code == 405

    def test_put_on_collections_405(self, client):
        """Verify PUT to collections endpoint returns 405."""
        res = client.put("/taxii2/phantomnet/collections/")
        assert res.status_code == 405

    def test_delete_on_objects_405(self, client):
        """Verify DELETE to objects endpoint returns 405."""
        res = client.delete("/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/")
        assert res.status_code == 405


# =============================================================================
# Section 9: Error Response Structure Validation
# =============================================================================


class TestErrorResponseStructure:
    """Verify all TAXII error responses follow the TAXII 2.1 error schema."""

    def test_406_error_body_schema(self, client):
        """Verify 406 error responses have complete TAXII error schema."""
        res = client.get("/taxii2/", headers={"Accept": "text/html"})
        assert res.status_code == 406
        data = res.json()
        assert "title" in data
        assert "description" in data
        assert "http_status" in data
        assert TAXII_CT in res.headers.get("content-type", "")

    def test_404_error_body_schema(self, client):
        """Verify 404 error responses have complete TAXII error schema."""
        res = client.get("/taxii2/phantomnet/collections/does-not-exist/")
        assert res.status_code == 404
        data = res.json()
        assert "title" in data
        assert "description" in data
        assert "http_status" in data
        assert data["http_status"] == "404"

    def test_400_error_body_schema(self, client):
        """Verify 400 error responses have complete TAXII error schema."""
        res = client.get(
            "/taxii2/phantomnet/collections/sentinel-playbooks-approved/objects/",
            params={"added_after": "INVALID"},
        )
        assert res.status_code == 400
        data = res.json()
        assert "title" in data
        assert "description" in data
        assert "http_status" in data
        assert data["http_status"] == "400"


# =============================================================================
# Main Runner (for standalone execution)
# =============================================================================


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v", "--tb=short"]))
