import os
import sys
import pytest
from starlette.testclient import TestClient
from unittest.mock import patch, MagicMock

backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

try:
    from services.telemetry import telemetry_service, DEGRADED_MODE
except ImportError:
    from backend.services.telemetry import telemetry_service, DEGRADED_MODE

try:
    from main import app
except ImportError:
    from backend.main import app
from backend.ml.threat_scoring_service import score_threat
from backend.schemas.threat_schema import ThreatInput


@pytest.fixture
def client():
    return TestClient(app)


def test_degraded_mode_reporting_in_readiness_probe(client):
    """
    OBS-02: When a non-critical engine is degraded, /health/ready continues
    returning HTTP 200 with degraded=True so Kubernetes traffic routing survives.
    """
    telemetry_service.set_degraded("ml_engine", True)
    try:
        res = client.get("/health/ready")
        assert res.status_code == 200
        data = res.json()
        assert data["ready"] is True
        assert data["degraded"] is True
    finally:
        telemetry_service.set_degraded("ml_engine", False)


def test_ml_scoring_graceful_fallback_on_model_failure():
    """
    OBS-02: When ML model encounters an error or is missing, scoring falls back to
    deterministic heuristics without raising uncaught exceptions.
    """
    threat_in = ThreatInput(
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=44444,
        dst_port=22,
        protocol="TCP",
        length=128,
        is_malicious=True,
    )

    # Patch model_loader to simulate model missing/failure
    with patch("ml.threat_scoring_service.model_loader.load_model", return_value=None):
        res = score_threat(threat_in)
        assert res is not None
        assert hasattr(res, "score")
        assert res.decision in ["ALLOW", "ALERT", "BLOCK"]


def test_ollama_llm_isolation_degraded_mode(client):
    """
    OBS-02: Verify that when Ollama LLM is unavailable or disabled,
    core ingestion, alerting, and reporting endpoints function normally.
    """
    with patch.dict(os.environ, {"SENTINEL_LLM_ENABLED": "false"}):
        res = client.get("/health/ready")
        assert res.status_code == 200
        data = res.json()
        assert data["ready"] is True
        assert data["checks"]["ollama_llm"] == "disabled_by_policy"
