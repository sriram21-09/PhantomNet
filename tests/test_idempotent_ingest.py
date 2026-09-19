"""
Test Suite: Idempotent Ingestion & Deduplication (DUR-02)
Verifies:
1. Primary deduplication by producer UUIDv7 via PostgreSQL / SQLite unique constraint.
2. Secondary deduplication by canonical event fingerprint sliding window.
3. Event persistence integrity in PacketLog.
"""
import pytest
import time
from datetime import datetime, timedelta
import fakeredis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from database.models import Base, PacketLog
from schemas.event_envelope import EventEnvelope, generate_uuidv7, compute_canonical_fingerprint
from services.event_consumer import EventConsumer


@pytest.fixture
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


@pytest.fixture
def fake_redis():
    return fakeredis.FakeRedis()


def test_primary_dedup_by_uuidv7(test_db, fake_redis):
    """
    Submitting duplicate event envelopes with the exact same UUIDv7 must be
    detected as duplicates and result in only 1 database row.
    """
    consumer = EventConsumer(
        redis_client=fake_redis,
        stream_key="events:stream",
        group_name="test-group",
        consumer_name="test-worker",
    )

    shared_uuid = generate_uuidv7()
    env1 = EventEnvelope(
        event_id=shared_uuid,
        honeypot_id="ssh-01",
        event_type="SSH",
        src_ip="203.0.113.5",
        dst_port=2222,
        protocol="TCP",
        payload={"command": "cat /etc/passwd"},
    )
    env2 = EventEnvelope(
        event_id=shared_uuid,
        honeypot_id="ssh-01",
        event_type="SSH",
        src_ip="203.0.113.5",
        dst_port=2222,
        protocol="TCP",
        payload={"command": "cat /etc/passwd"},
    )

    # First attempt: successfully inserted
    inserted1, outcome1 = consumer.process_envelope(env1, test_db)
    test_db.commit()
    assert inserted1 is True
    assert outcome1 == "INSERTED"

    # Second attempt: identified as primary duplicate (UUID match)
    inserted2, outcome2 = consumer.process_envelope(env2, test_db)
    assert inserted2 is False
    assert outcome2 == "DEDUP_UUID"

    # Verify only 1 row exists in database
    rows = test_db.query(PacketLog).filter(PacketLog.event_id == shared_uuid).all()
    assert len(rows) == 1
    assert rows[0].src_ip == "203.0.113.5"


def test_secondary_dedup_by_canonical_fingerprint_window(test_db, fake_redis):
    """
    If a producer generates a new UUID for a retransmitted event within the
    deduplication window, the canonical fingerprint deduplicates it.
    """
    consumer = EventConsumer(
        redis_client=fake_redis,
        stream_key="events:stream",
        group_name="test-group",
        consumer_name="test-worker",
        dedup_window_seconds=60,
    )

    now_ns = time.time_ns()
    payload = {"query": "SELECT * FROM users WHERE '1'='1'"}

    # Two distinct envelopes with distinct UUIDs but identical canonical parameters
    env1 = EventEnvelope(
        event_id=generate_uuidv7(),
        timestamp_ns=now_ns,
        honeypot_id="http-01",
        event_type="HTTP",
        src_ip="198.51.100.99",
        dst_port=8080,
        protocol="TCP",
        payload=payload,
    )
    env2 = EventEnvelope(
        event_id=generate_uuidv7(),
        timestamp_ns=now_ns + 1_000_000,  # 1ms later
        honeypot_id="http-01",
        event_type="HTTP",
        src_ip="198.51.100.99",
        dst_port=8080,
        protocol="TCP",
        payload=payload,
    )

    # Both envelopes should have identical canonical fingerprints
    assert env1.canonical_fingerprint == env2.canonical_fingerprint

    # First insertion succeeds
    inserted1, outcome1 = consumer.process_envelope(env1, test_db)
    test_db.commit()
    assert inserted1 is True
    assert outcome1 == "INSERTED"

    # Second insertion caught by sliding window fingerprint deduplication
    inserted2, outcome2 = consumer.process_envelope(env2, test_db)
    assert inserted2 is False
    assert outcome2 == "DEDUP_FINGERPRINT"

    # Verify only 1 record exists in database
    records = test_db.query(PacketLog).filter(
        PacketLog.canonical_fingerprint == env1.canonical_fingerprint
    ).all()
    assert len(records) == 1


def test_distinct_events_are_not_deduplicated(test_db, fake_redis):
    """
    Events with different source IPs or different payload queries must never be deduplicated.
    """
    consumer = EventConsumer(
        redis_client=fake_redis,
        stream_key="events:stream",
        group_name="test-group",
        consumer_name="test-worker",
    )

    env1 = EventEnvelope(
        event_id=generate_uuidv7(),
        honeypot_id="http-01",
        event_type="HTTP",
        src_ip="198.51.100.10",
        dst_port=8080,
        protocol="TCP",
    )
    env2 = EventEnvelope(
        event_id=generate_uuidv7(),
        honeypot_id="http-01",
        event_type="HTTP",
        src_ip="198.51.100.20",  # Different IP!
        dst_port=8080,
        protocol="TCP",
    )

    ins1, _ = consumer.process_envelope(env1, test_db)
    ins2, _ = consumer.process_envelope(env2, test_db)
    test_db.commit()

    assert ins1 is True
    assert ins2 is True

    total = test_db.query(PacketLog).count()
    assert total == 2
