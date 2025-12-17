import json
from unittest.mock import MagicMock
from backend.ingestor.sshlog_ingestor import insert_log


def test_insert_log_success():
    # Mock database cursor
    mock_cursor = MagicMock()

    # Sample SSH log (same format as honeypot)
    sample_log = {
        "timestamp": "2025-12-16T10:00:00+00:00",
        "source_ip": "127.0.0.1",
        "username": "admin",
        "password": "1234",
        "status": "attempt",
        "honeypot_type": "ssh",
        "port": 2222,
        "raw_data": "admin/1234"
    }

    # Call function
    insert_log(mock_cursor, sample_log)

    # Assert SQL execution happened once
    assert mock_cursor.execute.called
