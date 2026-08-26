import sqlite3
import os
import shutil

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "phantomnet.db")
BACKUP_PATH = os.path.join(PROJECT_ROOT, "phantomnet_backup.db")

def backup_and_clear_db():
    print(f"Checking database at: {DB_PATH}")
    if os.path.exists(DB_PATH):
        shutil.copyfile(DB_PATH, BACKUP_PATH)
        print(f"[OK] Created database backup at: {BACKUP_PATH}")
    else:
        print(f"[INFO] Database not found at {DB_PATH}, creating new connection...")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get list of all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall() if not row[0].startswith("sqlite_")]

    print(f"Found {len(tables)} tables: {tables}")

    tables_to_clear = [
        "sentinel_playbooks",
        "sentinel_audit_logs",
        "packet_logs",
        "alerts",
        "events",
        "attack_sessions",
        "iocs",
        "case_evidence",
        "investigation_cases",
        "pcap_captures",
        "traffic_stats",
        "honeypot_nodes",
        "search_history"
    ]

    cleared_counts = {}
    for table in tables_to_clear:
        if table in tables:
            cursor.execute(f"DELETE FROM {table};")
            cursor.execute(f"SELECT COUNT(*) FROM {table};")
            cleared_counts[table] = cursor.fetchone()[0]
            print(f"Cleared table: {table} (Remaining rows: {cleared_counts[table]})")

    conn.commit()
    conn.close()

    print("[SUCCESS] Database successfully cleared of all playbooks, rules, campaigns, and events!")

if __name__ == "__main__":
    backup_and_clear_db()
