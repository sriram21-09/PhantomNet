import asyncio
import asyncssh
import json
import os
from datetime import datetime, timezone

# -----------------------------
# Configuration
# -----------------------------
HOST = ""
PORT = 2222

VALID_USER = "PhantomNet"
VALID_PASS = "1234"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../logs"))
LOG_FILE = os.path.join(LOG_DIR, "ssh_async.jsonl")
HOST_KEY = os.path.join(BASE_DIR, "honeypot_host_key")

os.makedirs(LOG_DIR, exist_ok=True)
open(LOG_FILE, "a").close()


def log_event(data):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")


# -----------------------------
# SSH Session (COMMAND LOGGING)
# -----------------------------
class HoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, ip, username):
        self.ip = ip
        self.username = username
        self.chan = None

    def connection_made(self, chan):
        self.chan = chan
        self.chan.write("Welcome to Ubuntu 20.04 LTS\r\n")
        self.chan.write(f"{self.username}@honeypot:$ ")

    def shell_requested(self):
        return True

    def data_received(self, data, datatype):
        command = data.strip()

        if command:
            log_event({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": self.ip,
                "honeypot_type": "ssh",
                "port": PORT,
                "username": self.username,
                "event": "command",
                "command": command
            })

        if command in ("exit", "logout"):
            self.chan.write("logout\r\n")
            self.chan.exit(0)
            return

        self.chan.write(f"{command}: command not found\r\n")
        self.chan.write(f"{self.username}@honeypot:$ ")


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
        # Log ATTEMPT
        log_event({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.ip,
            "honeypot_type": "ssh",
            "port": PORT,
            "username": username,
            "password": password,
            "status": "attempt"
        })

        # SUCCESS
        if username == VALID_USER and password == VALID_PASS:
            log_event({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": self.ip,
                "honeypot_type": "ssh",
                "port": PORT,
                "username": username,
                "status": "success"
            })
            return True

        # FAILED
        log_event({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.ip,
            "honeypot_type": "ssh",
            "port": PORT,
            "username": username,
            "status": "failed"
        })

        raise asyncssh.DisconnectError(
            asyncssh.DisconnectReason.AUTH_FAILED,
            "Invalid credentials"
        )

    def session_requested(self):
        return HoneypotSession(self.ip, self.conn.get_extra_info("username"))


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

    print(f"[+] AsyncSSH Honeypot running on port {PORT}")
    await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(start_server())
