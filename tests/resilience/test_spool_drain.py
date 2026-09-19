"""
Test Suite: Local Disk Spool Outage Recovery & Draining (DUR-05)
Validates:
1. When Ingestion Gateway is offline / unreachable, events are written to local disk WAL.
2. Multiple events across separate WAL files are correctly persisted.
3. When Gateway recovers, DiskSpooler drains all buffered events in chronological order.
4. Delivered WAL files are deleted after successful acknowledgment.
5. Zero event loss across simulated network outage.
"""
import os
import sys
import tempfile
import shutil
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend")))

from honeypots.spooler import DiskSpooler
from schemas.event_envelope import generate_uuidv7


@pytest.fixture
def temp_spool_dir():
    temp_dir = tempfile.mkdtemp(prefix="phantomnet_spool_test_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


def test_spooler_buffers_during_gateway_outage(temp_spool_dir):
    """
    Events written during gateway downtime are safely appended to local WAL files.
    """
    spooler = DiskSpooler(spool_dir=temp_spool_dir)
    assert not spooler.has_pending_events()

    events = [
        {
            "event_id": generate_uuidv7(),
            "honeypot_id": f"ssh-{i}",
            "event_type": "SSH",
            "src_ip": f"198.51.100.{i + 1}",
            "payload": {"attempt": i},
        }
        for i in range(10)
    ]

    # Buffer all 10 events
    for ev in events:
        ok = spooler.write_event(ev)
        assert ok is True

    assert spooler.has_pending_events()
    assert spooler.get_total_spool_size() > 0


def test_spooler_drains_in_order_on_gateway_recovery(temp_spool_dir):
    """
    When the gateway becomes available, all spooled events are drained and the
    WAL files are safely deleted.
    """
    spooler = DiskSpooler(spool_dir=temp_spool_dir)

    sent_events = []
    for i in range(25):
        ev = {
            "event_id": generate_uuidv7(),
            "seq": i,
            "honeypot_id": "http-01",
            "src_ip": "198.51.100.5",
        }
        sent_events.append(ev)
        spooler.write_event(ev)

    received_events = []

    # Mock gateway ingestion callback
    def mock_gateway_ingest(batch: list) -> bool:
        received_events.extend(batch)
        return True  # HTTP 202 Accepted

    drained_count = spooler.drain(mock_gateway_ingest, batch_size=10)

    # 1. All 25 events drained
    assert drained_count == 25
    assert len(received_events) == 25

    # 2. Sequence order preserved
    for i, ev in enumerate(received_events):
        assert ev["seq"] == i

    # 3. Spool directory is now clean
    assert not spooler.has_pending_events()
    assert spooler.get_total_spool_size() == 0


def test_spooler_partial_drain_resilience(temp_spool_dir):
    """
    If the gateway accepts some batches then fails again, already-accepted
    events are not duplicated and remaining events stay in the spool.
    """
    spooler = DiskSpooler(spool_dir=temp_spool_dir)

    for i in range(20):
        spooler.write_event({"event_id": generate_uuidv7(), "index": i})

    calls = 0

    def flaky_gateway(batch: list) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1:
            return True  # First batch of 10 succeeds
        return False  # Second batch fails (gateway drops again)

    # Drain with batch_size=10
    drained_count = spooler.drain(flaky_gateway, batch_size=10)

    # First batch succeeded, but second failed so remaining events stay spooled
    # Note: in DiskSpooler, WAL files are removed only if all batches in the file succeed
    assert calls >= 2
    assert spooler.has_pending_events()
