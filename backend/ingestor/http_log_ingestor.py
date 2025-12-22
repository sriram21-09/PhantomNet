import json
import psycopg2
import hashlib
import os

# ---------------- PATH SETUP ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.abspath(os.path.join(BASE_DIR, "../logs/http_logs.jsonl"))

# ---------------- DB CONFIG ----------------
DB_CONFIG = {
    "host": "localhost",
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",
    "port": 5432
}

# ---------------- HASH ----------------
def compute_hash(log):
    normalized = json.dumps(log, sort_keys=True)
    return hashlib.sha256(normalized.encode()).hexdigest()

# ---------------- INSERT ----------------
def insert_log(cur, log):
    log_hash = compute_hash(log)

    cur.execute("""
        INSERT INTO http_logs (
            timestamp,
            source_ip,
            honeypot_type,
            port,
            method,
            path,
            event,
            level,
            user_agent,
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
        log.get("method"),
        log.get("path"),
        log.get("event"),
        log.get("level", "INFO"),
        log.get("user_agent"),
        json.dumps(log),
        log_hash
    ))

# ---------------- MAIN ----------------
def main():
    print("[+] Connecting to PostgreSQL (HTTP)...")

    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                log = json.loads(line.strip())
                insert_log(cur, log)
            except json.JSONDecodeError:
                print("[!] Skipping invalid JSON line")
            except Exception as e:
                print(f"[!] Error inserting log: {e}")

    conn.commit()
    cur.close()
    conn.close()

    print("[+] HTTP logs ingested successfully")

if __name__ == "__main__":
    main()
