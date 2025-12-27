import psycopg2
from backend.ingestor.sshlog_ingestor import insert_log

DB_CONFIG = {
    "host": "localhost",
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",
    "port": 5432
}

def test_ssh_log_ingestion():
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    # Clean table
    cur.execute("DELETE FROM ssh_logs;")
    conn.commit()

    log = {
        "timestamp": "2025-01-01T00:00:00Z",
        "source_ip": "1.2.3.4",
        "honeypot_type": "ssh",
        "port": 2222,
        "event": "login_attempt",
        "data": {
            "username": "attacker",
            "password": "badpass"
        }
    }

    insert_log(cur, log)
    conn.commit()

    cur.execute("""
        SELECT event, username, password, status
        FROM ssh_logs
    """)
    row = cur.fetchone()

    assert row is not None
    assert row[0] == "login_attempt"
    assert row[1] == "attacker"
    assert row[2] == "badpass"
    assert row[3] == "attempt"

    cur.close()
    conn.close()
