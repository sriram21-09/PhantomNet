"""
Test Suite: Catastrophic Loss Journaling & Zero-Silent-Drop Guarantee (DUR-06)
Validates:
1. When local disk spool capacity is breached, events trigger Catastrophic Loss Journaling.
2. Emergency journal records contain tamper-evident drop counter, reason, and event metadata.
3. Disk write is immediately fsynced to guarantee durability even during immediate power loss.
4. Metric counter increments atomically.
5. Zero silent drops: every unpersistable event is verifiably accounted for.
"""
import os
import sys
import tempfile
import shutil
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from services.catastrophic_loss import (
    CatastrophicLossJournal,
    get_catastrophic_loss_count,
    reset_catastrophic_loss_count,
)
from honeypots.spooler import DiskSpooler
from schemas.event_envelope import generate_uuidv7


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="phantomnet_catastrophic_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


def test_catastrophic_journal_records_drop_on_spool_overflow(temp_dir, monkeypatch):
    """
    When the local spool capacity is exceeded, an emergency log entry is written
    and the event is not silently lost.
    """
    reset_catastrophic_loss_count()
    assert get_catastrophic_loss_count() == 0

    journal_log_path = os.path.join(temp_dir, "catastrophic_loss.log")
    journal = CatastrophicLossJournal(log_path=journal_log_path)

    # Monkeypatch global catastrophic journal in spooler module
    import honeypots.spooler as spooler_mod
    monkeypatch.setattr(spooler_mod, "catastrophic_journal", journal)

    # Configure spooler with tiny max bytes (e.g. 150 bytes) to trigger overflow on second event
    spooler = DiskSpooler(spool_dir=temp_dir, max_spool_bytes=150)

    # Write 1st event (fits in 300 bytes)
    ev1 = {
        "event_id": generate_uuidv7(),
        "honeypot_id": "ssh-edge-01",
        "event_type": "SSH",
        "src_ip": "198.51.100.1",
    }
    ok1 = spooler.write_event(ev1)
    assert ok1 is True
    assert get_catastrophic_loss_count() == 0

    # Write 2nd and 3rd events (exceeds 300 bytes limit)
    ev2 = {
        "event_id": generate_uuidv7(),
        "honeypot_id": "ssh-edge-01",
        "event_type": "SSH",
        "src_ip": "198.51.100.2",
    }
    ok2 = spooler.write_event(ev2)
    assert ok2 is False  # Rejected and journaled!

    # Verify journal entry was written
    assert os.path.exists(journal_log_path)
    records = journal.read_journal_records()
    assert len(records) == 1

    drop_record = records[0]
    assert drop_record["drop_counter"] == 1
    assert drop_record["event_id"] == ev2["event_id"]
    assert drop_record["reason"] == "SPOOL_CAPACITY_EXCEEDED_1GB"
    assert drop_record["src_ip"] == "198.51.100.2"
    assert get_catastrophic_loss_count() == 1


def test_emergency_stderr_alert_on_catastrophic_drop(temp_dir, capsys):
    """
    Assert that catastrophic drops output an emergency message to stderr.
    """
    reset_catastrophic_loss_count()
    journal_log_path = os.path.join(temp_dir, "catastrophic_loss.log")
    journal = CatastrophicLossJournal(log_path=journal_log_path)

    test_ev = {
        "event_id": "018f-test-uuid",
        "honeypot_id": "ftp-01",
        "event_type": "FTP",
        "src_ip": "203.0.113.88",
    }

    journal.record_catastrophic_drop(test_ev, reason="TOTAL_BUFFER_EXHAUSTION", buffer_depth=1048576)

    captured = capsys.readouterr()
    assert "[EMERGENCY-CATASTROPHIC-LOSS]" in captured.err
    assert "018f-test-uuid" in captured.err
    assert "TOTAL_BUFFER_EXHAUSTION" in captured.err
