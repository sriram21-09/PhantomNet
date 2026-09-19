import os
import sys
import pytest
from starlette.testclient import TestClient

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.main import app
from backend.middleware.auth import create_access_token


@pytest.fixture
def client():
    return TestClient(app)


def test_governance_retention_policies_unauthenticated(client):
    res = client.get("/api/v1/governance/retention/policies")
    assert res.status_code == 401


def test_governance_retention_policies_viewer_access(client):
    token = create_access_token(data={"sub": "viewer_user", "role": "Viewer"})
    res = client.get(
        "/api/v1/governance/retention/policies",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "packet_logs_days" in data
    assert "events_days" in data
    assert "alerts_days" in data
    assert "audit_log_immutable" in data


def test_governance_retention_run_rbac_forbidden_for_analyst(client):
    token = create_access_token(data={"sub": "analyst_user", "role": "Analyst"})
    res = client.post(
        "/api/v1/governance/retention/run?dry_run=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 403


def test_governance_retention_run_admin_allowed(client):
    token = create_access_token(data={"sub": "admin_user", "role": "Admin"})
    res = client.post(
        "/api/v1/governance/retention/run?dry_run=true",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["dry_run"] is True
    assert "purged" in data
    assert "total_purged" in data
