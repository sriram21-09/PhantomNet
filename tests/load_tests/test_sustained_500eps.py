"""
Test Suite: Sustained 500 EPS Ingestion & Zero-Drop Guarantee (DUR-01)
Validates:
1. Ingestion Gateway handles sustained bursts at >= 500 events per second.
2. 100% of submitted events are accepted (0 rejected / dropped).
3. Consumer worker group drains and persists all events to database.
4. Total events submitted == Total events in stream == Total events persisted.
5. Ingestion latency meets p95 <= 100 ms SLO.
"""
import os
import sys
import time
import pytest
import fakeredis
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from database.models import Base, PacketLog
from schemas.event_envelope import EventEnvelope, generate_uuidv7
from services.ingestion_gateway import IngestionGateway
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


def test_sustained_500eps_ingestion_zero_drop(test_db, fake_redis, monkeypatch):
    """
    Simulates sustained ingestion of 1,000 events (2 full seconds at 500 eps),
    verifying 0 dropped events, high throughput, and complete persistence to database.
    """
    # Prevent slow external HTTP requests to ip-api.com during local load test
    monkeypatch.setattr(
        "services.event_consumer.geoip_service.lookup",
        lambda ip: {"country": "Testland", "city": "Testcity", "lat": 10.0, "lon": 20.0},
    )

    stream_key = "events:stream"
    group_name = "phantomnet-workers"
    gateway = IngestionGateway(redis_client=fake_redis, stream_key=stream_key)
    consumer = EventConsumer(
        redis_client=fake_redis,
        stream_key=stream_key,
        group_name=group_name,
        consumer_name="load-worker",
        batch_size=200,
    )

    total_events = 1000
    batch_size = 50  # 20 batches of 50 = 1,000 events
    num_batches = total_events // batch_size

    # Prepare batches
    batches = []
    all_uuids = set()
    for b in range(num_batches):
        batch_items = []
        for i in range(batch_size):
            u = generate_uuidv7()
            all_uuids.add(u)
            batch_items.append({
                "event_id": u,
                "honeypot_id": f"ssh-node-{b % 4}",
                "event_type": "SSH",
                "src_ip": f"198.51.100.{(b * batch_size + i) % 250 + 1}",
                "dst_port": 2222,
                "protocol": "TCP",
                "payload": {"seq": b * batch_size + i},
            })
        batches.append(batch_items)

    latencies = []
    accepted_count = 0

    # Execute ingestion
    start_time = time.perf_counter()
    for batch in batches:
        t0 = time.perf_counter()
        res = gateway.ingest_batch(batch)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)  # ms
        accepted_count += res.get("accepted_count", 0)

    total_duration = time.perf_counter() - start_time
    calculated_eps = total_events / total_duration

    # 1. Verify 100% acceptance (0 dropped)
    assert accepted_count == total_events, f"Expected {total_events} accepted, got {accepted_count}"
    assert fake_redis.xlen(stream_key) == total_events

    # 2. Check throughput meets or exceeds 500 eps
    print(f"\n[Load Test] Ingested {total_events} events in {total_duration:.3f}s -> {calculated_eps:.1f} eps")
    assert calculated_eps >= 500, f"Throughput {calculated_eps:.1f} eps lower than target 500 eps"

    # 3. Check p95 latency <= 100 ms
    latencies.sort()
    p95_latency = latencies[int(len(latencies) * 0.95)]
    print(f"[Load Test] p95 batch ingestion latency: {p95_latency:.2f} ms")
    assert p95_latency <= 100.0, f"p95 latency {p95_latency:.2f} ms exceeded 100 ms threshold"

    # 4. Drain with consumer worker
    total_persisted = 0
    while total_persisted < total_events:
        stats = consumer.consume_batch(db=test_db, count=200)
        if stats["read_count"] == 0:
            break
        total_persisted += stats["inserted_count"]

    # 5. Verify database matches exactly 100% of ingested events
    db_count = test_db.query(PacketLog).count()
    assert db_count == total_events, f"DB count {db_count} does not match ingested {total_events}"

    # Verify all UUIDs exist in database
    persisted_uuids = {r.event_id for r in test_db.query(PacketLog.event_id).all()}
    assert persisted_uuids == all_uuids
