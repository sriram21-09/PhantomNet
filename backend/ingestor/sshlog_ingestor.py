import json
import psycopg2
import hashlib

LOG_FILE = "../logs/ssh.jsonl"

DB_CONFIG = {
    "host": "localhost",
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",
    "port": 5432
}

def compute_hash(log):
    return hashlib.sha256(json.dumps(log, sort_keys=True).encode()).hexdigest()

def insert_log(cur, log):
    event = log.get("event")
    data = log.get("data") or {}

    username = None
    password = None
    command = None
    status = None

    if event == "login_attempt":
        username = data.get("username")
        password = data.get("password")
        status = "attempt"

    elif event == "login_success":
        username = data.get("username")
        status = "success"

    elif event == "login_failed":
        username = data.get("username")
        status = "failed"

    elif event == "command":
        command = data.get("cmd")

    log_hash = compute_hash(log)

    cur.execute("""
        INSERT INTO ssh_logs (
            timestamp,
            source_ip,
            honeypot_type,
            port,
            event,
            username,
            password,
            command,
            status,
            raw_data,
            log_hash
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (log_hash) DO NOTHING
    """, (
        log.get("timestamp"),
        log.get("source_ip"),
        log.get("honeypot_type"),
        log.get("port"),
        event,
        username,
        password,
        command,
        status,
        json.dumps(log),
        log_hash
    ))

def main():
    print("[+] Connecting to PostgreSQL (SSH)...")
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    with open(LOG_FILE, "r") as f:
        for line in f:
            insert_log(cur, json.loads(line))

    conn.commit()
    cur.close()
    conn.close()
    print("[+] SSH logs ingested successfully")

if __name__ == "__main__":
    main()
