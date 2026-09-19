import os
import sys
import tempfile
import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if os.path.join(backend_dir, "backend") not in sys.path:
    sys.path.insert(0, os.path.join(backend_dir, "backend"))

from backend.database.models import Base, PacketLog, Event, Alert, TrafficStats, PcapCapture, AuditLog
from backend.services.retention_service import TieredRetentionEngine, RetentionConfig


@pytest.fixture
def retention_db():
    """Provides a fresh isolated in-memory SQLite database for retention testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    yield db
    db.close()


def test_retention_tier_boundaries(retention_db):
    """
    GOV-03: Verify that records within retention window are preserved,
    while records older than the specific cutoff are purged.
    """
    now = datetime.utcnow()

    # PacketLog: 30 days retention
    old_packet = PacketLog(
        src_ip="192.168.1.1", dst_ip="10.0.0.1", protocol="TCP",
        timestamp=now - timedelta(days=35)
    )
    new_packet = PacketLog(
        src_ip="192.168.1.2", dst_ip="10.0.0.1", protocol="TCP",
        timestamp=now - timedelta(days=5)
    )

    # Alert: 90 days retention
    old_alert = Alert(
        level="HIGH", type="INTRUSION", description="Old alert",
        timestamp=now - timedelta(days=95)
    )
    new_alert = Alert(
        level="HIGH", type="INTRUSION", description="New alert",
        timestamp=now - timedelta(days=45)
    )

    retention_db.add_all([old_packet, new_packet, old_alert, new_alert])
    retention_db.commit()

    config = RetentionConfig(
        packet_logs_days=30,
        alerts_days=90,
        batch_size=10,
    )
    engine = TieredRetentionEngine(config=config)
    res = engine.run_retention_cycle(retention_db, dry_run=False)

    assert res["purged"]["packet_logs"] == 1
    assert res["purged"]["alerts"] == 1

    # Verify database state
    remaining_packets = retention_db.query(PacketLog).all()
    assert len(remaining_packets) == 1
    assert remaining_packets[0].src_ip == "192.168.1.2"

    remaining_alerts = retention_db.query(Alert).all()
    assert len(remaining_alerts) == 1
    assert remaining_alerts[0].description == "New alert"


def test_chunked_batch_deletion(retention_db):
    """
    GOV-03: Verify bounded chunk deletion (zero lock contention architecture).
    Tests purging 25 records with batch_size=7 (requires 4 discrete batch commits).
    """
    now = datetime.utcnow()
    old_packets = [
        PacketLog(
            src_ip=f"10.0.0.{i}", dst_ip="10.0.0.1", protocol="TCP",
            timestamp=now - timedelta(days=40)
        )
        for i in range(25)
    ]
    retention_db.add_all(old_packets)
    retention_db.commit()

    assert retention_db.query(PacketLog).count() == 25

    config = RetentionConfig(packet_logs_days=30, batch_size=7)
    engine = TieredRetentionEngine(config=config)

    purged = engine.purge_model_in_batches(
        retention_db, PacketLog, cutoff=now - timedelta(days=30)
    )

    assert purged == 25
    assert retention_db.query(PacketLog).count() == 0


def test_dry_run_mode(retention_db):
    """
    GOV-03: Verify dry run mode inspects counts without deleting any data.
    """
    now = datetime.utcnow()
    for i in range(10):
        retention_db.add(
            PacketLog(
                src_ip=f"10.0.0.{i}", dst_ip="10.0.0.1", protocol="TCP",
                timestamp=now - timedelta(days=45)
            )
        )
    retention_db.commit()

    config = RetentionConfig(packet_logs_days=30)
    engine = TieredRetentionEngine(config=config)

    res = engine.run_retention_cycle(retention_db, dry_run=True)
    assert res["purged"]["packet_logs"] == 10
    assert res["dry_run"] is True

    # Data must still be present in database
    assert retention_db.query(PacketLog).count() == 10


def test_audit_log_immutability_guard(retention_db):
    """
    GOV-03: Verify audit logs are strictly protected by immutability guard
    even when their timestamp exceeds the configured retention window.
    """
    now = datetime.utcnow()
    old_audit = AuditLog(
        actor="admin", action="TEST_ACTION", result="success",
        timestamp=now - timedelta(days=500)
    )
    retention_db.add(old_audit)
    retention_db.commit()

    # Immutable mode enabled (default)
    config = RetentionConfig(audit_logs_days=365, audit_log_immutable=True)
    engine = TieredRetentionEngine(config=config)
    res = engine.run_retention_cycle(retention_db, dry_run=False)

    assert res["purged"]["audit_logs"] == 0
    assert res["audit_logs_status"] == "immutable_retention_enforced"
    assert retention_db.query(AuditLog).count() == 1

    # When explicitly disabled for testing
    mutable_config = RetentionConfig(audit_logs_days=365, audit_log_immutable=False)
    mutable_engine = TieredRetentionEngine(config=mutable_config)
    res2 = mutable_engine.run_retention_cycle(retention_db, dry_run=False)

    assert res2["purged"]["audit_logs"] == 1
    assert res2["audit_logs_status"] == "purged_past_retention_window"


def test_pcap_file_cleanup(retention_db):
    """
    GOV-03: Verify that purging PCAP records also removes associated files from disk.
    """
    fd, temp_pcap = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    with open(temp_pcap, "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)

    assert os.path.exists(temp_pcap)

    now = datetime.utcnow()
    pcap_rec = PcapCapture(
        file_path=temp_pcap,
        file_size=104,
        created_at=now - timedelta(days=20),
    )
    retention_db.add(pcap_rec)
    retention_db.commit()

    config = RetentionConfig(pcaps_days=14, batch_size=5)
    engine = TieredRetentionEngine(config=config)
    res = engine.run_retention_cycle(retention_db, dry_run=False)

    assert res["purged"]["pcap_captures"] == 1
    assert retention_db.query(PcapCapture).count() == 0
    assert not os.path.exists(temp_pcap), "PCAP file on disk was not removed during retention cycle"
