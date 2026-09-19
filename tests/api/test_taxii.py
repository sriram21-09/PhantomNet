"""
tests/api/test_taxii.py
----------------------
Verifies TAXII 2.1 Machine-to-Machine (M2M) authentication and authorization
using dedicated TaxiiClient credentials and basic authentication.
"""
import base64
import pytest
from fastapi.testclient import TestClient


def test_taxii_unauthenticated_returns_401(client: TestClient):
    """Unauthenticated requests to TAXII endpoints return 401."""
    response = client.get("/taxii2/")
    assert response.status_code == 401


def test_taxii_m2m_custom_headers_authentication(client: TestClient):
    """M2M authentication via X-TAXII-Key-ID and X-TAXII-Secret headers."""
    headers = {
        "X-TAXII-Key-ID": "taxii-client-01",
        "X-TAXII-Secret": "SecretTaxiiPass123!",
        "Accept": "application/taxii+json;version=2.1"
    }
    response = client.get("/taxii2/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "api_roots" in data
    assert "/taxii2/phantomnet/" in data["api_roots"]


def test_taxii_http_basic_authentication(client: TestClient):
    """M2M authentication via standard HTTP Basic header with client credentials."""
    creds = base64.b64encode(b"taxii-client-01:SecretTaxiiPass123!").decode("ascii")
    headers = {
        "Authorization": f"Basic {creds}",
        "Accept": "application/taxii+json;version=2.1"
    }
    response = client.get("/taxii2/", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "title" in data


def test_taxii_invalid_credentials_rejected(client: TestClient):
    """Invalid secret returns 401."""
    headers = {
        "X-TAXII-Key-ID": "taxii-client-01",
        "X-TAXII-Secret": "WrongSecretValue!",
    }
    response = client.get("/taxii2/", headers=headers)
    assert response.status_code == 401


def test_taxii_unknown_client_rejected(client: TestClient):
    """Unknown client ID returns 401."""
    headers = {
        "X-TAXII-Key-ID": "non-existent-client-id",
        "X-TAXII-Secret": "SomeSecret123!",
    }
    response = client.get("/taxii2/", headers=headers)
    assert response.status_code == 401
