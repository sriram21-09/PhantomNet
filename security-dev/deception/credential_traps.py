import sqlite3
import random
import string
import os
import datetime

DB_PATH = "data/honeytokens.db"


class CredentialTrapSystem:
    def __init__(self):
        self._init_db()

    def _init_db(self):
        if not os.path.exists("data"):
            os.makedirs("data")
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS honeytokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_type TEXT,
                username TEXT,
                password TEXT,
                source_honeypot TEXT,
                first_seen TIMESTAMP,
                last_used TIMESTAMP,
                usage_count INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def generate_honeytoken(self, token_type="generic", source="honeypot-1"):
        usernames = [
            "admin",
            "root",
            "ubuntu",
            "ec2-user",
            "dbadmin",
            "svc_account",
            "backup_user",
        ]
        username = (
            random.choice(usernames)
            + "_"
            + "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
        )
        password = "".join(
            random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=12)
        )

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO honeytokens (token_type, username, password, source_honeypot, first_seen)
            VALUES (?, ?, ?, ?, ?)
        """,
            (token_type, username, password, source, datetime.datetime.now()),
        )
        conn.commit()
        conn.close()
        return username, password

    def monitor_usage(self, username, password):
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, usage_count FROM honeytokens WHERE username = ? AND password = ?",
            (username, password),
        )
        token = cursor.fetchone()

        if token:
            token_id, count = token
            cursor.execute(
                """
                UPDATE honeytokens 
                SET last_used = ?, usage_count = ? 
                WHERE id = ?
            """,
                (datetime.datetime.now(), count + 1, token_id),
            )
            conn.commit()
            conn.close()
            print(f"ALERT: Honeytoken {username} used! Source tracked.")
            return True
        conn.close()
        return False

    def seed_config_file(self, file_path, token_type="config"):
        username, password = self.generate_honeytoken(
            token_type=token_type, source=file_path
        )
        content = f"# Configuration file\nDB_USER={username}\nDB_PASS={password}\n"
        with open(file_path, "w") as f:
            f.write(content)
        print(f"Seeded {file_path} with honeytoken.")


if __name__ == "__main__":
    trap_system = CredentialTrapSystem()
    u, p = trap_system.generate_honeytoken(token_type="ssh", source="ssh_honeypot")
    print(f"Generated Token: {u} / {p}")
    trap_system.seed_config_file(
        "C:/Users/vivekananda reddy/PhantomNet/data/fake_db_config.ini"
    )
