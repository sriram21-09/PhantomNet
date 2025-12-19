import json
import psycopg2
import hashlib
import os

LOG_FILE = os.path.abspath("../logs/http_logs.jsonl")

DB_CONFIG = {
    "host": "localhost",
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",
    "port": 5432
}

def compute_hash(log):
    normalized = json.dumps(log, sort_keys=True)
    return hashlib.sha256(normalized.encode()).hexdigest()

def insert_log(cur, log):
    log_hash = compute_hash(log)

    cur.execute("""
        INSERT INTO http_logs (
            timestamp,
            source_ip,
            honeypot_type,
            port,
            method,
            url,
            raw_data,
            log_hash
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (log_hash) DO NOTHING
    """, (
        log.get("timestamp"),
        log.get("source_ip"),
        log.get("honeypot_type"),
        log.get("port"),
        log.get("method"),
        log.get("url"),
        log.get("raw_data"),
        log_hash
    ))

def main():
    print("[+] Connecting to PostgreSQL (HTTP)...")
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    with open(LOG_FILE, "r") as f:
        for line in f:
            insert_log(cur, json.loads(line))

    conn.commit()
    cur.close()
    conn.close()
    print("[+] HTTP logs ingested successfully")

if __name__ == "__main__":
    main()
