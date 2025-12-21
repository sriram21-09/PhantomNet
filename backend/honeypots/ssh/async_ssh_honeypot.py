import asyncio
import asyncssh
import json
import os
from datetime import datetime, timezone

# ---------------- CONFIG ----------------
HOST = ""
PORT = 2222

VALID_USER = "PhantomNet"
VALID_PASS = "1234"

MAX_CONNECTIONS_PER_IP = 3
SESSION_TIMEOUT = 120

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../logs"))

LOG_FILE = os.path.join(LOG_DIR, "ssh_async.jsonl")
ERROR_LOG = os.path.join(LOG_DIR, "ssh_async_error.log")
HOST_KEY = os.path.join(BASE_DIR, "honeypot_host_key")

os.makedirs(LOG_DIR, exist_ok=True)
open(LOG_FILE, "a").close()

IP_CONNECTIONS = {}

# ---------------- LOG HELPERS ----------------
def log_event(data):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

def log_error(msg, context=""):
    with open(ERROR_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | {context} | {msg}\n")

# ---------------- SESSION ----------------
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
        cmd = data.strip()

        if cmd:
            log_event({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": self.ip,
                "honeypot_type": "ssh",
                "port": PORT,
                "event": "command",
                "data": {"cmd": cmd},
                "level": "INFO"
            })

        if cmd in ("exit", "logout"):
            self.chan.exit(0)
            return

        self.chan.write(f"{cmd}: command not found\r\n")
        self.chan.write(f"{self.username}@honeypot:$ ")

# ---------------- SERVER ----------------
class SSHHoneypot(asyncssh.SSHServer):

    def connection_made(self, conn):
        self.conn = conn
        peer = conn.get_extra_info("peername")
        self.ip = peer[0] if peer else "unknown"

        IP_CONNECTIONS[self.ip] = IP_CONNECTIONS.get(self.ip, 0) + 1
        if IP_CONNECTIONS[self.ip] > MAX_CONNECTIONS_PER_IP:
            log_error("Connection limit exceeded", self.ip)
            raise asyncssh.DisconnectError(
                asyncssh.DisconnectReason.BY_APPLICATION,
                "Too many connections"
            )

    def connection_lost(self, exc):
        IP_CONNECTIONS[self.ip] -= 1

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        log_event({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.ip,
            "honeypot_type": "ssh",
            "port": PORT,
            "event": "login_attempt",
            "data": {"username": username, "password": password},
            "level": "WARN"
        })

        if username == VALID_USER and password == VALID_PASS:
            log_event({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": self.ip,
                "honeypot_type": "ssh",
                "port": PORT,
                "event": "login_success",
                "data": {"username": username},
                "level": "INFO"
            })
            return True

        log_event({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.ip,
            "honeypot_type": "ssh",
            "port": PORT,
            "event": "login_failed",
            "data": {"username": username},
            "level": "ERROR"
        })

        raise asyncssh.DisconnectError(
            asyncssh.DisconnectReason.AUTH_FAILED,
            "Invalid credentials"
        )

    def session_requested(self):
        asyncio.get_event_loop().call_later(SESSION_TIMEOUT, self.conn.close)
        return HoneypotSession(self.ip, self.conn.get_extra_info("username"))

# ---------------- START ----------------
async def start_server():
    await asyncssh.create_server(
        SSHHoneypot,
        HOST,
        PORT,
        server_host_keys=[HOST_KEY]
    )
    print(f"[+] AsyncSSH Honeypot running on {PORT}")
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(start_server())
