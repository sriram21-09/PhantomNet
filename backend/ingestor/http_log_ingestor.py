import json
import psycopg2

LOG_FILE = "../logs/http_logs.jsonl"

DB_CONFIG = {
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "1234",
    "host": "localhost",
    "port": 5432
}

def insert_log(cur, log):
    cur.execute("""
        INSERT INTO http_logs (timestamp, source_ip, method, url, headers, raw_data)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        log.get("timestamp"),
        log.get("source_ip"),
        log.get("method"),
        log.get("url"),
        json.dumps(log.get("headers", {})),
        log.get("raw_data")
    ))

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
    print("[+] HTTP logs ingested successfully")

if __name__ == "__main__":
    main()
