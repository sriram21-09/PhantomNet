import json
import psycopg2

LOG_FILE = "../logs/ssh_async.jsonl"

DB_CONFIG = {
    "host": "localhost",
    "dbname": "phantomnet_logs",
    "user": "postgres",
    "password": "password@321",
    "port": 5432
}

def insert_log(cur, log):
    raw_data = f"{log.get('username')}:{log.get('password')}"

    cur.execute("""
        INSERT INTO asyncssh_logs
        (timestamp, source_ip, username, password, status, raw_data)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        log.get("timestamp"),
        log.get("source_ip"),
        log.get("username"),
        log.get("password"),
        log.get("status"),
        raw_data
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
    print("[+] Async SSH logs ingested successfully")

if __name__ == "__main__":
    main()
