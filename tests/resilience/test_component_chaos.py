"""
Test Suite: Component Chaos & Crash Recovery (DUR-07)
Validates:
1. PostgreSQL failure during batch commit: messages remain safe in Redis PEL,
   recovery worker reclaims and completes with 0 event loss once DB recovers.
2. Ingestion Gateway / Redis failure: producers automatically buffer in local disk spool,
   and drain into Redis stream once back online with 0 event loss.
"""
import os
import sys
import tempfile
import shutil
import pytest
import fakeredis
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from database.models import Base, PacketLog
from schemas.event_envelope import EventEnvelope, generate_uuidv7
from services.event_consumer import EventConsumer
from services.event_retry_scheduler import EventRetryScheduler
from honeypots.spooler import DiskSpooler
from services.ingestion_gateway import IngestionGateway


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


def test_database_crash_and_recovery_zero_event_loss(test_db, fake_redis, monkeypatch):
    """
    Scenario:
    1. 10 events published to Redis stream.
    2. Worker reads 10 events.
    3. PostgreSQL crashes during commit (throws Exception).
    4. Worker crashes; events are not ACKed and remain in PEL.
    5. PostgreSQL recovers.
    6. Recovery scheduler claims unacknowledged messages and persists to DB.
    7. Verify: Exactly 10 events in DB, 0 dropped, PEL empty.
    """
    stream_key = "events:stream"
    group_name = "phantomnet-workers"
    consumer = EventConsumer(
        redis_client=fake_redis,
        stream_key=stream_key,
        group_name=group_name,
        consumer_name="worker-primary",
    )

    published_ids = []
    for i in range(10):
        uuid_val = generate_uuidv7()
        published_ids.append(uuid_val)
        env = EventEnvelope(
            event_id=uuid_val,
            honeypot_id="ssh-edge",
            event_type="SSH",
            src_ip=f"198.51.100.{i + 1}",
            dst_port=2222,
        )
        fake_redis.xadd(stream_key, env.to_stream_dict())

    # Simulate database crash during commit
    original_commit = test_db.commit

    def crash_commit():
        raise ConnectionResetError("Database connection severed: ECONNRESET")

    monkeypatch.setattr(test_db, "commit", crash_commit)

    # Worker encounters database crash
    with pytest.raises(ConnectionResetError):
        consumer.consume_batch(db=test_db, count=10)

    # Verify: 0 events committed to DB; 10 events remain in PEL
    assert test_db.query(PacketLog).count() == 0
    pending = fake_redis.xpending(stream_key, group_name)
    pending_count = pending.get("pending") if isinstance(pending, dict) else pending[0]
    assert pending_count == 10

    # PostgreSQL recovers!
    monkeypatch.setattr(test_db, "commit", original_commit)

    # Recovery scheduler reclaims and commits
    scheduler = EventRetryScheduler(
        redis_client=fake_redis,
        stream_key=stream_key,
        group_name=group_name,
        idle_timeout_ms=0,
        consumer_engine=consumer,
    )

    stats = scheduler.scan_and_reclaim(db=test_db, count=10)
    assert stats["reclaimed_count"] == 10
    assert stats["reprocessed_acked"] == 10

    # Verify: Exactly 10 events now safely in DB!
    db_events = test_db.query(PacketLog).all()
    assert len(db_events) == 10
    persisted_uuids = {e.event_id for e in db_events}
    for pub_id in published_ids:
        assert pub_id in persisted_uuids

    # Verify PEL is completely clean
    pending_after = fake_redis.xpending(stream_key, group_name)
    pending_after_count = pending_after.get("pending") if isinstance(pending_after, dict) else pending_after[0]
    assert pending_after_count == 0


def test_end_to_end_outage_spool_to_db_zero_loss(test_db, fake_redis):
    """
    Scenario:
    1. Ingestion Gateway is unavailable (simulate failure).
    2. Honeypot writes 15 events to local disk spool.
    3. Ingestion Gateway comes online.
    4. Disk spool drains all 15 events to Ingestion Gateway -> Redis Stream.
    5. Consumer worker consumes from Redis Stream and persists to Database.
    6. Verify: Exactly 15 events in DB with full fidelity and zero data loss!
    """
    temp_spool = tempfile.mkdtemp(prefix="chaos_spool_")
    try:
        spooler = DiskSpooler(spool_dir=temp_spool)
        stream_key = "events:stream"
        group_name = "phantomnet-workers"

        # 1. Spool 15 events while gateway is down
        orig_events = []
        for i in range(15):
            ev = {
                "event_id": generate_uuidv7(),
                "honeypot_id": "http-trap",
                "event_type": "HTTP",
                "src_ip": f"203.0.113.{i + 1}",
                "dst_port": 8080,
                "protocol": "TCP",
                "payload": {"url": f"/admin/page_{i}.php"},
            }
            orig_events.append(ev)
            ok = spooler.write_event(ev)
            assert ok is True

        assert spooler.has_pending_events()

        # 2. Gateway comes online
        gateway = IngestionGateway(redis_client=fake_redis, stream_key=stream_key)

        # 3. Drain spool to gateway
        def gateway_batch_ingest(batch: list) -> bool:
            resp = gateway.ingest_batch(batch)
            return resp.get("status") == "accepted"

        drained = spooler.drain(gateway_batch_ingest, batch_size=5)
        assert drained == 15
        assert not spooler.has_pending_events()

        # Verify all 15 events made it to Redis stream
        assert fake_redis.xlen(stream_key) == 15

        # 4. Consumer worker consumes from Redis Stream to Database
        consumer = EventConsumer(
            redis_client=fake_redis,
            stream_key=stream_key,
            group_name=group_name,
            consumer_name="chaos-worker",
        )
        c_stats = consumer.consume_batch(db=test_db, count=20)
        assert c_stats["inserted_count"] == 15
        assert c_stats["acked_count"] == 15

        # 5. Verify database records
        db_records = test_db.query(PacketLog).all()
        assert len(db_records) == 15
        persisted_ips = {r.src_ip for r in db_records}
        for ev in orig_events:
            assert ev["src_ip"] in persisted_ips

    finally:
        shutil.rmtree(temp_spool, ignore_errors=True)
