import asyncio
import asyncssh
import json
import os
from datetime import datetime, timezone

# -----------------------------
# Configuration
# -----------------------------
HOST = ""        # IPv4 + IPv6
PORT = 2222

VALID_USER = "admin"
VALID_PASS = "admin123"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_DIR = os.path.abspath(
    os.path.join(BASE_DIR, "../../logs")
)

os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "ssh_async.jsonl")

HOST_KEY = os.path.join(BASE_DIR, "honeypot_host_key")

# Ensure log file exists
open(LOG_FILE, "a").close()


# -----------------------------
# SSH Session (REQUIRED)
# -----------------------------
class HoneypotSession(asyncssh.SSHServerSession):
    def connection_made(self, chan):
        self.chan = chan
        self.chan.write("Welcome to Ubuntu 20.04 LTS\r\n")
        self.chan.write("Connection will be closed.\r\n")
        self.chan.exit(0)

    def shell_requested(self):
        return True


# -----------------------------
# SSH Server
# -----------------------------
class SSHHoneypot(asyncssh.SSHServer):

    def connection_made(self, conn):
        self.conn = conn
        peer = conn.get_extra_info("peername")
        self.ip = peer[0] if peer else "unknown"
        print(f"[+] Connection from {self.ip}")

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.ip,
            "honeypot_type": "ssh",
            "port": PORT,
            "username": username,
            "password": password,
            "status": "attempt"
        }

        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        print(f"[!] Login attempt {username}:{password} from {self.ip}")

        # Allow only default credentials
        if username == VALID_USER and password == VALID_PASS:
            print(f"[+] Valid login for {username}")
            return True

        # Invalid → immediate disconnect
        raise asyncssh.DisconnectError(
            asyncssh.DisconnectReason.AUTH_FAILED,
            "Invalid credentials"
        )

    def session_requested(self):
        return HoneypotSession()


# -----------------------------
# Start Server
# -----------------------------
async def start_server():
    await asyncssh.create_server(
        SSHHoneypot,
        HOST,
        PORT,
        server_host_keys=[HOST_KEY]
    )

    print(f"[+] AsyncSSH Honeypot running on port {PORT} (IPv4 + IPv6)")
    await asyncio.Future()


# -----------------------------
# Entry Point
# -----------------------------
if __name__ == "__main__":
    asyncio.run(start_server())
