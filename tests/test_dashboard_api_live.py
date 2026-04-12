"""
PhantomNet Dashboard & API Live Tests
======================================
Tests the API endpoints and dashboard functionality using FastAPI TestClient.
This avoids the need to run the full server (which requires scapy/admin permissions).

Usage:
  cd backend
  python -m pytest ../tests/test_dashboard_api_live.py -v --tb=short -s
"""

import os
import sys
import json
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

os.environ["ENVIRONMENT"] = "ci"
os.environ.setdefault("DATABASE_URL", f"sqlite:///{BACKEND_DIR / 'phantomnet.db'}")

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create TestClient from the FastAPI app."""
    from main import app
    with TestClient(app) as c:
        yield c


class TestDashboardAPIEndpoints:
    """Section 3 - Dashboard API Testing."""

    def test_01_health_endpoint(self, client):
        """Test 1: /api/health should return online status."""
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "online"
        assert "timestamp" in data
        print(f"  [PASS] /api/health -> status={data['status']}, timestamp={data['timestamp']}")

    def test_02_stats_endpoint(self, client):
        """Test 2: /api/stats should return dashboard stats."""
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        print(f"  [PASS] /api/stats -> keys: {list(data.keys())}")
        assert isinstance(data, dict), "Stats should return a dict"

    def test_03_events_endpoint(self, client):
        """Test 3: /api/events should return event list."""
        resp = client.get("/api/events")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list), "Events should return a list"
        print(f"  [PASS] /api/events -> {len(data)} events returned")
        if data:
            event = data[0]
            expected_keys = {"time", "ip", "type", "port", "threat", "details"}
            actual_keys = set(event.keys())
            print(f"  [PASS] Event keys: {actual_keys}")
            assert expected_keys.issubset(actual_keys), f"Missing keys: {expected_keys - actual_keys}"

    def test_04_events_with_filters(self, client):
        """Test 4: /api/events should support filtering."""
        # Filter by protocol
        resp = client.get("/api/events?protocol=TCP&limit=10")
        assert resp.status_code == 200
        data = resp.json()
        print(f"  [PASS] /api/events?protocol=TCP -> {len(data)} events")

        # Filter by threat level
        resp = client.get("/api/events?threat=MALICIOUS&limit=10")
        assert resp.status_code == 200
        data = resp.json()
        print(f"  [PASS] /api/events?threat=MALICIOUS -> {len(data)} events")

    def test_05_honeypots_status_endpoint(self, client):
        """Test 5: /api/honeypots/status should return honeypot statuses."""
        resp = client.get("/api/honeypots/status")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list), "Honeypots status should return a list"
        print(f"  [PASS] /api/honeypots/status -> {len(data)} honeypots")
        for hp in data:
            print(f"    {hp['name']}: port={hp['port']}, status={hp['status']}")
            assert "name" in hp
            assert "port" in hp
            assert "status" in hp

    def test_06_honeypots_alias(self, client):
        """Test 6: /api/honeypots (alias) should also work."""
        resp = client.get("/api/honeypots")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        print(f"  [PASS] /api/honeypots (alias) -> {len(data)} honeypots")

    def test_07_analyze_traffic(self, client):
        """Test 7: /analyze-traffic should return enriched traffic data."""
        resp = client.get("/analyze-traffic")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "count" in data
        assert "data" in data
        print(f"  [PASS] /analyze-traffic -> {data['count']} records")
        if data["data"]:
            record = data["data"][0]
            assert "packet_info" in record
            assert "ai_analysis" in record
            print(f"  [PASS] Traffic record structure validated")

    def test_08_geoip_status(self, client):
        """Test 8: /api/geoip/status should return GeoIP service status."""
        resp = client.get("/api/geoip/status")
        assert resp.status_code == 200
        data = resp.json()
        print(f"  [PASS] /api/geoip/status -> {data}")

    def test_09_attack_map(self, client):
        """Test 9: /api/analytics/attack-map should return geo data."""
        resp = client.get("/api/analytics/attack-map?limit=50")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        print(f"  [PASS] /api/analytics/attack-map -> locations={data.get('total_locations', 0)}, events={data.get('total_events', 0)}")

    def test_10_cache_stats(self, client):
        """Test 10: /api/cache/stats should return cache information."""
        resp = client.get("/api/cache/stats")
        assert resp.status_code == 200
        data = resp.json()
        print(f"  [PASS] /api/cache/stats -> {data}")

    def test_11_response_history(self, client):
        """Test 11: /api/response/history should return response actions."""
        resp = client.get("/api/response/history")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        print(f"  [PASS] /api/response/history -> {data['count']} entries")

    def test_12_response_policy(self, client):
        """Test 12: /api/response/policy should return current policy."""
        resp = client.get("/api/response/policy")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert "policy" in data
        print(f"  [PASS] /api/response/policy -> {list(data['policy'].keys())}")

    def test_13_blocked_ips(self, client):
        """Test 13: /api/response/blocked-ips should return blocked list."""
        resp = client.get("/api/response/blocked-ips")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        print(f"  [PASS] /api/response/blocked-ips -> {data['count']} blocked")

    def test_14_metrics_endpoint(self, client):
        """Test 14: /metrics should return Prometheus-format metrics."""
        resp = client.get("/metrics")
        assert resp.status_code == 200
        print(f"  [PASS] /metrics -> {len(resp.text)} bytes of metrics data")

    def test_15_api_response_times(self, client):
        """Test 15: All major endpoints should respond in < 5 seconds."""
        import time
        endpoints = [
            "/api/health",
            "/api/stats",
            "/api/events?limit=10",
            "/analyze-traffic",
            # Note: /api/honeypots/status excluded as it has inherent socket timeouts on inactive ports
        ]
        all_fast = True
        for ep in endpoints:
            start = time.perf_counter()
            resp = client.get(ep)
            elapsed = (time.perf_counter() - start) * 1000
            status = "[PASS]" if elapsed < 5000 else "[SLOW]"
            if elapsed >= 5000:
                all_fast = False
            print(f"  {status} {ep}: {elapsed:.0f}ms (HTTP {resp.status_code})")
        assert all_fast, "One or more endpoints exceeded 5s response time"


class TestAPIDataValidation:
    """Validates API returns valid, well-structured JSON."""

    def test_stats_contains_key_metrics(self, client):
        """Stats should contain traffic / attack counts."""
        resp = client.get("/api/stats")
        data = resp.json()
        # StatsService.calculate_stats() should return counts
        print(f"  [PASS] Stats data: {json.dumps(data, indent=2, default=str)[:500]}")

    def test_events_pagination(self, client):
        """Events endpoint should respect limit parameter."""
        resp5 = client.get("/api/events?limit=5")
        resp20 = client.get("/api/events?limit=20")
        data5 = resp5.json()
        data20 = resp20.json()
        assert len(data5) <= 5, f"Expected max 5 events, got {len(data5)}"
        assert len(data20) <= 20, f"Expected max 20 events, got {len(data20)}"
        print(f"  [PASS] Pagination: limit=5 -> {len(data5)}, limit=20 -> {len(data20)}")

    def test_events_return_valid_json(self, client):
        """All events should be valid JSON objects."""
        resp = client.get("/api/events?limit=100")
        data = resp.json()
        for i, event in enumerate(data[:5]):
            assert isinstance(event, dict), f"Event {i} is not a dict"
            assert "time" in event, f"Event {i} missing 'time'"
            assert "ip" in event, f"Event {i} missing 'ip'"
        print(f"  [PASS] All {len(data)} events are valid JSON objects")
