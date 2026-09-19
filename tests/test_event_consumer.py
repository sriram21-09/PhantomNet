"""
Test Suite: Consumer Group, PEL Claim, and Dead Letter Queue (DUR-04)
Validates:
1. Consumer group XREADGROUP reads and commits to DB.
2. XACK occurs only AFTER successful database transaction commit.
3. Crashed / unacknowledged messages remain in Pending Entries List (PEL).
4. Orphaned messages in PEL are reclaimed after idle timeout.
5. Poison pills (poisonous payloads / persistent failures) route to DLQ ('events:dlq') after 3 delivery attempts.
"""
import os
import sys
import json
import pytest
import fakeredis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from database.models import Base, PacketLog
from schemas.event_envelope import EventEnvelope, generate_uuidv7
from services.event_consumer import EventConsumer
from services.event_retry_scheduler import EventRetryScheduler


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


def test_consumer_reads_batch_and_xacks_after_commit(test_db, fake_redis):
    """
    Standard happy path: consumer reads from stream, inserts into DB, commits, and XACKs.
    """
    stream_key = "events:stream"
    group_name = "phantomnet-workers"
    consumer = EventConsumer(
        redis_client=fake_redis,
        stream_key=stream_key,
        group_name=group_name,
        consumer_name="worker-01",
    )

    # Publish 3 valid events into stream
    for i in range(3):
        env = EventEnvelope(
            event_id=generate_uuidv7(),
            honeypot_id=f"ssh-{i}",
            event_type="SSH",
            src_ip=f"192.0.2.{i + 1}",
            dst_port=2222,
            protocol="TCP",
        )
        fake_redis.xadd(stream_key, env.to_stream_dict())

    # Verify stream length
    assert fake_redis.xlen(stream_key) == 3

    # Consumer reads and processes batch
    stats = consumer.consume_batch(db=test_db, count=10)
    assert stats["read_count"] == 3
    assert stats["inserted_count"] == 3
    assert stats["acked_count"] == 3

    # Verify database persistence
    db_count = test_db.query(PacketLog).count()
    assert db_count == 3

    # Verify PEL is now empty (all were acknowledged)
    pending = fake_redis.xpending(stream_key, group_name)
    # xpending returns {'pending': 0, ...} or (0, ...)
    pending_count = pending.get("pending") if isinstance(pending, dict) else pending[0]
    assert pending_count == 0


def test_uncommitted_messages_remain_in_pel(test_db, fake_redis, monkeypatch):
    """
    If the worker crashes or database commit raises an exception, the messages
    must NOT be acknowledged and must remain in the PEL.
    """
    stream_key = "events:stream"
    group_name = "phantomnet-workers"
    consumer = EventConsumer(
        redis_client=fake_redis,
        stream_key=stream_key,
        group_name=group_name,
        consumer_name="worker-02",
    )

    env = EventEnvelope(
        event_id=generate_uuidv7(),
        honeypot_id="http-01",
        event_type="HTTP",
        src_ip="192.0.2.55",
        dst_port=8080,
    )
    fake_redis.xadd(stream_key, env.to_stream_dict())

    # Simulate database transaction commit crash
    def mock_commit():
        raise RuntimeError("Simulated DB connection failure during commit")

    monkeypatch.setattr(test_db, "commit", mock_commit)

    # Consumption should raise the commit error
    with pytest.raises(RuntimeError, match="Simulated DB connection failure"):
        consumer.consume_batch(db=test_db, count=10)

    # Message must remain in PEL because commit failed!
    pending = fake_redis.xpending(stream_key, group_name)
    pending_count = pending.get("pending") if isinstance(pending, dict) else pending[0]
    assert pending_count == 1, "Uncommitted message must remain in PEL"


def test_pel_recovery_worker_reclaims_and_completes(test_db, fake_redis):
    """
    A message left in the PEL past idle_timeout is reclaimed by the scheduler
    and re-processed to completion.
    """
    stream_key = "events:stream"
    group_name = "phantomnet-workers"
    consumer = EventConsumer(
        redis_client=fake_redis,
        stream_key=stream_key,
        group_name=group_name,
        consumer_name="crashing-worker",
    )

    env = EventEnvelope(
        event_id=generate_uuidv7(),
        honeypot_id="ftp-01",
        event_type="FTP",
        protocol="FTP",
        src_ip="192.0.2.77",
        dst_port=2121,
    )
    msg_id = fake_redis.xadd(stream_key, env.to_stream_dict())

    # Read message into worker's PEL without acknowledging
    fake_redis.xreadgroup(
        groupname=group_name,
        consumername="crashing-worker",
        streams={stream_key: ">"},
        count=1,
    )

    # Worker "dies"; message sits unacknowledged in PEL
    scheduler = EventRetryScheduler(
        redis_client=fake_redis,
        stream_key=stream_key,
        group_name=group_name,
        idle_timeout_ms=0,  # 0ms for instantaneous test reclamation
        max_retries=3,
        consumer_engine=consumer,
    )

    reclaim_stats = scheduler.scan_and_reclaim(db=test_db)
    assert reclaim_stats["scanned_pending"] >= 1
    assert reclaim_stats["reclaimed_count"] >= 1
    assert reclaim_stats["reprocessed_acked"] >= 1

    # Verify saved in database
    row = test_db.query(PacketLog).filter(PacketLog.src_ip == "192.0.2.77").first()
    assert row is not None
    assert row.protocol == "FTP"

    # Verify PEL is now empty
    pending = fake_redis.xpending(stream_key, group_name)
    pending_count = pending.get("pending") if isinstance(pending, dict) else pending[0]
    assert pending_count == 0


def test_poison_pill_routes_to_dlq_after_max_retries(test_db, fake_redis):
    """
    A poison pill message that consistently fails delivery attempts is
    routed to the DLQ stream ('events:dlq') and acknowledged from main stream.
    """
    stream_key = "events:stream"
    dlq_stream_key = "events:dlq"
    group_name = "phantomnet-workers"

    scheduler = EventRetryScheduler(
        redis_client=fake_redis,
        stream_key=stream_key,
        group_name=group_name,
        dlq_stream_key=dlq_stream_key,
        idle_timeout_ms=0,
        max_retries=3,
    )

    # Insert a malformed/poison pill payload
    poison_payload = {"malformed_binary": "corrupt_data", "invalid_key": "crash"}
    msg_id = fake_redis.xadd(stream_key, poison_payload)

    # Read into PEL to simulate delivery attempts
    fake_redis.xreadgroup(
        groupname=group_name,
        consumername="worker-fail",
        streams={stream_key: ">"},
        count=1,
    )

    # In fakeredis/redis, simulate delivery attempts >= 3 directly via _route_to_dlq
    msg_id_str = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)
    scheduler._route_to_dlq(
        msg_id=msg_id,
        msg_id_str=msg_id_str,
        message_data=poison_payload,
        delivery_count=3,
        failure_reason="CORRUPT_SCHEMA_POISON_PILL",
    )

    # 1. Main stream PEL must be cleared (acknowledged)
    pending = fake_redis.xpending(stream_key, group_name)
    pending_count = pending.get("pending") if isinstance(pending, dict) else pending[0]
    assert pending_count == 0, "Poison pill must be acknowledged from main stream"

    # 2. DLQ stream must contain the failed message entry
    assert fake_redis.xlen(dlq_stream_key) == 1
    dlq_messages = fake_redis.xrange(dlq_stream_key, min="-", max="+")
    _, dlq_fields = dlq_messages[0]

    # Handle bytes decoding
    decoded_fields = {
        (k.decode() if isinstance(k, bytes) else str(k)): (v.decode() if isinstance(v, bytes) else str(v))
        for k, v in dlq_fields.items()
    }
    assert decoded_fields["failed_message_id"] == msg_id_str
    assert decoded_fields["delivery_attempts"] == "3"
    assert decoded_fields["dlq_reason"] == "CORRUPT_SCHEMA_POISON_PILL"
