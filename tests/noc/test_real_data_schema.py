"""
tests/noc/test_real_data_schema.py
----------------------------------
Validates that database models, telemetry tables, and schema constraints
match the operational expectations of the Neural Operations Center.
"""
import pytest
from database.models import PacketLog
from services.stats_aggregator import StatsService


def test_packet_log_schema_attributes(noc_engine):
    """Verify PacketLog model contains all telemetry fields required by NOC."""
    required_columns = {
        "id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
        "protocol", "length", "attack_type", "threat_score", "threat_level"
    }
    actual_columns = {col.name for col in PacketLog.__table__.columns}
    missing = required_columns - actual_columns
    assert not missing, f"Missing required columns in PacketLog: {missing}"


def test_stats_aggregator_schema_consumption(TestingSessionLocal, seed_packets):
    """Verify StatsService runs without error against seeded telemetry and returns proper schema."""
    session = TestingSessionLocal()
    service = StatsService(session)
    stats = service.calculate_stats(mode="all")
    session.close()

    assert "totalEvents" in stats
    assert "uniqueIPs" in stats
    assert "avgThreatScore" in stats
    assert "critical_alerts" in stats or "criticalAlerts" in stats
    assert stats["totalEvents"] == 3
    assert stats["uniqueIPs"] == 2
