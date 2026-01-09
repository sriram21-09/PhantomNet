import json
import psycopg2
import hashlib
import os

LOG_FILE = os.path.abspath("../logs/smtp_logs.jsonl")

DB_CONFIG = {
    "host": "localhost",
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",
    "port": 5432
}

def compute_hash(entry):
    normalized = json.dumps(entry, sort_keys=True)
    return hashlib.sha256(normalized.encode()).hexdigest()

def insert_log(cur, log):
    log_hash = compute_hash(log)

    cur.execute("""
        INSERT INTO smtp_logs (
            timestamp,
            source_ip,
            honeypot_type,
            event,
            helo,
            mail_from,
            rcpt_to,
            subject,
            body,
            raw_data,
            log_hash
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        ON CONFLICT (log_hash) DO NOTHING
    """, (
        log.get("timestamp"),
        log.get("source_ip"),
        log.get("honeypot_type"),
        log.get("event"),

        log.get("helo"),
        log.get("mail_from"),
        log.get("rcpt_to"),
        log.get("subject"),
        log.get("body"),

        json.dumps(log),
        log_hash
    ))


def main():
    print("[+] Ingesting SMTP logs...")
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            log = json.loads(line)
            if log.get("honeypot_type") == "smtp":
                insert_log(cur, log)

    conn.commit()
    cur.close()
    conn.close()
    print("[+] SMTP logs ingested successfully")

if __name__ == "__main__":
    main()
