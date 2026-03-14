import sqlite3
import os

db_path = "phantomnet.db"


def migrate():
    if not os.path.exists(db_path):
        print(f"Error: {db_path} not found.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Get current columns
    cursor.execute("PRAGMA table_info(packet_logs)")
    current_columns = [c[1] for c in cursor.fetchall()]

    new_columns = [
        ("src_port", "INTEGER DEFAULT 0"),
        ("dst_port", "INTEGER DEFAULT 0"),
        ("event", "TEXT"),
        ("country", "TEXT"),
        ("city", "TEXT"),
        ("latitude", "FLOAT"),
        ("longitude", "FLOAT"),
    ]

    for col_name, col_type in new_columns:
        if col_name not in current_columns:
            print(f"Adding column {col_name} to packet_logs...")
            try:
                cursor.execute(
                    f"ALTER TABLE packet_logs ADD COLUMN {col_name} {col_type}"
                )
            except Exception as e:
                print(f"Failed to add {col_name}: {e}")
        else:
            print(f"Column {col_name} already exists.")

    conn.commit()
    conn.close()
    print("Migration finished successfully.")


if __name__ == "__main__":
    migrate()
