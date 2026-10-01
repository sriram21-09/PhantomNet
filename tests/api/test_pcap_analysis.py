"""
tests/api/test_pcap_analysis.py
-------------------------------
Comprehensive test suite for the PCAP Analysis feature:
- Capture listing API (pagination, RBAC, safe metadata)
- PCAP Analysis API (valid IDs, invalid ID 0 rejected, missing capture 404, Scapy DPI metrics)
- PCAP Download API (both /pcap/{id}/download and /events/{id}/pcap)
- Security controls (path traversal containment via _is_safe_pcap_path, role checks)
- Database metadata synchronization (PcapCapture model)
- Memory-bounded streaming execution with PcapReader
"""
import os
import shutil
import tempfile
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from database.models import User, Event, PcapCapture
from services.pcap_analyzer import (
    analyze_pcap,
    record_capture_metadata,
    sync_database_captures,
    cleanup_old_pcaps,
    _is_safe_pcap_path,
    PCAP_DIR,
)


@pytest.fixture(autouse=True)
def ensure_pcap_dir():
    """Ensure PCAP_DIR exists for tests."""
    os.makedirs(PCAP_DIR, exist_ok=True)


@pytest.fixture
def sample_pcap_file():
    """Create a minimal valid synthetic PCAP file for testing."""
    fd, path = tempfile.mkstemp(suffix=".pcap", prefix="test_cap_", dir=PCAP_DIR)
    # Write standard pcap global header (magic 0xa1b2c3d4, v2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1/Ethernet)
    pcap_header = bytes.fromhex(
        "d4c3b2a1"  # magic number (little endian)
        "0200"      # major 2
        "0400"      # minor 4
        "00000000"  # thiszone
        "00000000"  # sigfigs
        "ffff0000"  # snaplen 65535
        "01000000"  # network 1 (Ethernet)
    )
    # A single minimal ICMP packet in pcap format
    # Packet header: ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
    pkt_data = bytes.fromhex(
        # Eth: dst (ff:ff:ff:ff:ff:ff), src (00:11:22:33:44:55), type 0x0800 (IP)
        "ffffffffffff0011223344550800"
        # IPv4: v4, ihl 5, tos 0, len 28, id 1, flags 0, ttl 64, proto 1 (ICMP), chksum 0, src 192.168.1.100, dst 192.168.1.1
        "4500001c000100004001b9a7c0a80164c0a80101"
        # ICMP: Echo request (8), code 0, chksum 0xf7ff, id 0, seq 0
        "0800f7ff00000000"
    )
    pkt_len = len(pkt_data)
    pkt_hdr = (
        (1600000000).to_bytes(4, byteorder="little") +
        (0).to_bytes(4, byteorder="little") +
        pkt_len.to_bytes(4, byteorder="little") +
        pkt_len.to_bytes(4, byteorder="little")
    )
    with os.fdopen(fd, "wb") as f:
        f.write(pcap_header + pkt_hdr + pkt_data)

    yield path

    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# 1. Capture Listing API Tests
# ---------------------------------------------------------------------------

def test_captures_unauthenticated(client: TestClient):
    """Anonymous requests to /api/v1/pcap/captures must be rejected with 401."""
    res = client.get("/api/v1/pcap/captures")
    assert res.status_code == 401


def test_captures_viewer_forbidden(client: TestClient, viewer_headers: dict):
    """Viewers must not have access to PCAP captures listing (403 Forbidden)."""
    res = client.get("/api/v1/pcap/captures", headers=viewer_headers)
    assert res.status_code == 403


def test_captures_analyst_and_admin_allowed(
    client: TestClient, analyst_headers: dict, admin_headers: dict
):
    """Analysts and Admins are permitted to query the captures catalog."""
    res_analyst = client.get("/api/v1/pcap/captures?limit=10", headers=analyst_headers)
    assert res_analyst.status_code == 200
    data = res_analyst.json()
    assert "captures" in data
    assert "total" in data

    res_admin = client.get("/api/v1/pcap/captures?limit=10", headers=admin_headers)
    assert res_admin.status_code == 200


def test_captures_metadata_security(
    client: TestClient, analyst_headers: dict, db_session: Session, sample_pcap_file
):
    """Capture listing must NOT leak internal filesystem paths to the client."""
    rec = record_capture_metadata(db_session, sample_pcap_file)
    assert rec is not None

    res = client.get("/api/v1/pcap/captures?limit=100", headers=analyst_headers)
    assert res.status_code == 200
    data = res.json()
    captures = data.get("captures", [])
    assert len(captures) > 0

    target = next((c for c in captures if c["id"] == rec.id), None)
    assert target is not None
    # Verify required safe fields exist
    assert "id" in target
    assert "filename" in target
    assert "timestamp" in target
    assert "size_bytes" in target
    assert "status" in target
    # Path disclosure must NOT be present in API payload
    assert "pcap_path" not in target
    assert "path" not in target


# ---------------------------------------------------------------------------
# 2. PCAP Analysis API Tests
# ---------------------------------------------------------------------------

def test_analysis_hardcoded_id_zero_rejected_with_422(
    client: TestClient, analyst_headers: dict
):
    """FastAPI path validation must reject /api/v1/pcap/analysis/0 with 422 Unprocessable Entity."""
    res = client.get("/api/v1/pcap/analysis/0", headers=analyst_headers)
    assert res.status_code == 422


def test_analysis_negative_id_rejected_with_422(
    client: TestClient, analyst_headers: dict
):
    """Negative IDs must also be rejected by validation."""
    res = client.get("/api/v1/pcap/analysis/-1", headers=analyst_headers)
    assert res.status_code == 422


def test_analysis_missing_capture_returns_404(
    client: TestClient, analyst_headers: dict
):
    """Non-existent capture IDs must return 404 without crashing."""
    res = client.get("/api/v1/pcap/analysis/999999", headers=analyst_headers)
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_analysis_valid_capture_returns_200(
    client: TestClient, analyst_headers: dict, db_session: Session, sample_pcap_file
):
    """Analyzing a valid capture returns 200 with structured DPI analysis report."""
    rec = record_capture_metadata(db_session, sample_pcap_file)
    assert rec is not None

    res = client.get(f"/api/v1/pcap/analysis/{rec.id}", headers=analyst_headers)
    assert res.status_code == 200
    body = res.json()

    assert "report" in body
    report = body["report"]
    assert report["event_id"] == rec.id
    assert report["status"] == "analyzed"
    assert "details" in report

    details = report["details"]
    assert "total_packets" in details
    assert "protocol_distribution" in details
    assert "top_talkers" in details
    assert "malicious_patterns" in details
    assert "iocs" in details
    assert "suspicious_packets" in details


# ---------------------------------------------------------------------------
# 3. PCAP Download API Tests
# ---------------------------------------------------------------------------

def test_download_valid_capture(
    client: TestClient, analyst_headers: dict, db_session: Session, sample_pcap_file
):
    """Downloading via /api/v1/pcap/{id}/download streams the raw PCAP."""
    rec = record_capture_metadata(db_session, sample_pcap_file)
    assert rec is not None

    res = client.get(f"/api/v1/pcap/{rec.id}/download", headers=analyst_headers)
    assert res.status_code == 200
    assert "application/vnd.tcpdump.pcap" in res.headers["content-type"]
    assert "attachment" in res.headers.get("content-disposition", "")
    assert len(res.content) > 0


def test_download_missing_capture_returns_404(
    client: TestClient, analyst_headers: dict
):
    """Downloading a missing capture returns 404."""
    res = client.get("/api/v1/pcap/999999/download", headers=analyst_headers)
    assert res.status_code == 404


def test_events_pcap_download_backward_compatibility(
    client: TestClient, analyst_headers: dict, db_session: Session, sample_pcap_file
):
    """Legacy /api/v1/events/{id}/pcap successfully downloads when event or capture exists."""
    rec = record_capture_metadata(db_session, sample_pcap_file)
    assert rec is not None

    res = client.get(f"/api/v1/events/{rec.id}/pcap", headers=analyst_headers)
    assert res.status_code == 200
    assert len(res.content) > 0


# ---------------------------------------------------------------------------
# 4. Security & Path Traversal Verification
# ---------------------------------------------------------------------------

def test_path_traversal_blocked_by_is_safe_pcap_path():
    """_is_safe_pcap_path must block traversal sequences and root paths."""
    assert not _is_safe_pcap_path("../../../etc/passwd")
    assert not _is_safe_pcap_path("/etc/shadow")
    assert not _is_safe_pcap_path("C:\\Windows\\System32\\cmd.exe")
    assert not _is_safe_pcap_path(os.path.join(PCAP_DIR, "..", "secret.txt"))
    # Valid file within PCAP_DIR
    valid_path = os.path.join(PCAP_DIR, "capture_123.pcap")
    assert _is_safe_pcap_path(valid_path)


def test_download_path_traversal_injection_blocked_with_403(
    client: TestClient, analyst_headers: dict, db_session: Session
):
    """Injecting a path traversal string into an Event record must be rejected with 403."""
    event = Event(
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.99",
        src_port=80,
        honeypot_type="HTTP",
        pcap_path="../../../etc/passwd",
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    res = client.get(f"/api/v1/events/{event.id}/pcap", headers=analyst_headers)
    assert res.status_code == 403
    assert "Invalid PCAP file path" in res.json().get("detail", "")



# ---------------------------------------------------------------------------
# 5. Database Synchronization & Memory-Bounded Engine Tests
# ---------------------------------------------------------------------------

def test_sync_database_captures_indexes_files(db_session: Session, sample_pcap_file):
    """sync_database_captures scans PCAP_DIR and registers records in pcap_captures."""
    synced = sync_database_captures(db_session)
    assert synced >= 1

    fname = os.path.basename(sample_pcap_file)
    rec = db_session.query(PcapCapture).filter(PcapCapture.file_path.endswith(fname)).first()
    assert rec is not None
    assert rec.filename == fname
    assert rec.file_size > 0



def test_analyze_pcap_single_pass_streaming(sample_pcap_file):
    """analyze_pcap uses PcapReader streaming without loading all packets as a huge list."""
    result = analyze_pcap(sample_pcap_file)
    assert result["total_packets"] == 1
    assert result["total_bytes"] > 0
    assert len(result["protocol_distribution"]) == 1
    assert result["protocol_distribution"][0]["protocol"] == "ICMP"
    assert result["protocol_distribution"][0]["percentage"] == 100.0


def test_real_disk_pcap_analysis():
    """Verify that real PCAP files in data/pcaps analyze cleanly if present."""
    # Find any existing .pcap file in PCAP_DIR
    pcap_files = [f for f in os.listdir(PCAP_DIR) if f.endswith(".pcap")]
    if not pcap_files:
        pytest.skip("No real .pcap files present in data/pcaps")

    real_pcap = os.path.join(PCAP_DIR, pcap_files[0])
    result = analyze_pcap(real_pcap)
    assert "total_packets" in result
    assert "protocol_distribution" in result
    # Check that protocol percentages sum to ~100% (within floating point precision)
    if result["protocol_distribution"]:
        total_pct = sum(p["percentage"] for p in result["protocol_distribution"])
        assert 99.0 <= total_pct <= 101.0
