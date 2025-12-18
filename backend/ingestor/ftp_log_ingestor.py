import json
import psycopg2

LOG_FILE = "../logs/ftp_logs.jsonl"

DB_CONFIG = {
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",
    "host": "localhost",
    "port": 5432
}

def insert_log(cur, log):
    event = log.get("event")
    data = log.get("data") or {}

    cur.execute(
        """
        INSERT INTO ftp_logs (
            timestamp,
            source_ip,
            event,
            command,
            argument,
            raw_command,
            username,
            extra_data
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            log.get("timestamp"),
            log.get("source_ip"),
            event,
            data.get("command"),
            data.get("argument"),
            data.get("raw"),
            data.get("username"),
            json.dumps(data)
        )
    )

def main():
    print("[+] Connecting to PostgreSQL...")
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    with open(LOG_FILE, "r") as f:
        for line in f:
            log = json.loads(line)
            insert_log(cur, log)

    conn.commit()
    cur.close()
    conn.close()
    print("[+] FTP logs ingested successfully")

if __name__ == "__main__":
    main()
