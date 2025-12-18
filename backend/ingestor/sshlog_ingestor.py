import json
import psycopg2
import os

# -------------------------
# PostgreSQL configuration
# -------------------------
DB_CONFIG = {
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",     # keep empty if none
    "host": "localhost",
    "port": 5432
}

# -------------------------
# SSH log file path
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SSH_LOG_FILE = os.path.join(BASE_DIR, "../logs/ssh.jsonl")


def insert_log(cursor, log):
    cursor.execute(
        """
        INSERT INTO ssh_logs (
            timestamp,
            source_ip,
            username,
            password,
            status,
            honeypot_type,
            port,
            raw_data
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            log.get("timestamp"),
            log.get("source_ip"),
            log.get("username"),
            log.get("password"),
            log.get("status"),
            log.get("honeypot_type"),
            log.get("port"),
            log.get("raw_data"),
        )
    )


def main():
    print("[+] Connecting to PostgreSQL...")
    conn = psycopg2.connect(**DB_CONFIG)
    cursor = conn.cursor()

    print("[+] Reading SSH logs...")
    with open(SSH_LOG_FILE, "r") as f:
        for line in f:
            log = json.loads(line)
            insert_log(cursor, log)

    conn.commit()
    cursor.close()
    conn.close()

    print("[+] SSH logs successfully inserted into PostgreSQL")


if __name__ == "__main__":
    main()
