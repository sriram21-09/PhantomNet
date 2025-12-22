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

# ---------------- REALISTIC SSH BANNER (Week 3 Day 1 - Task 2) ----------------
class SSHHoneypot(asyncssh.SSHServer):

    def get_server_banner(self):
        return "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"


# ---------------- LOG HELPERS ----------------
def log_event(data):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as e:
        log_error(str(e), "log_event")

def log_error(msg, context=""):
    with open(ERROR_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | {context} | {msg}\n")

# ---------------- FAKE SHELL OUTPUT ----------------
def fake_command_output(cmd):
    if cmd.startswith("cd "):
        return ""

    if cmd.startswith("mkdir "):
        return ""

    responses = {
        "ls": "bin boot dev etc home lib lib64 usr var\n",
        "pwd": "/home/ubuntu\n",
        "whoami": "ubuntu\n",
        "uname -a": "Linux ip-172-31-12-45 5.15.0-84-generic x86_64 GNU/Linux\n",
        "id": "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu)\n"
    }
    return responses.get(cmd, f"bash: {cmd}: command not found\n")

# ---------------- SESSION ----------------
class HoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, ip, username):
        self.ip = ip
        self.username = username or "ubuntu"
        self.chan = None

    def connection_made(self, chan):
        self.chan = chan
        self.chan.write("Welcome to Ubuntu 20.04 LTS\r\n")
        self.chan.write(f"{self.username}@honeypot:~$ ")

    def shell_requested(self):
        return True

    def data_received(self, data, datatype):
        try:
            cmd = data.strip()

            if not cmd:
                self.chan.write(f"{self.username}@honeypot:~$ ")
                return

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
                self.chan.write("logout\n")
                self.chan.exit(0)
                return

            self.chan.write(fake_command_output(cmd))
            self.chan.write(f"{self.username}@honeypot:~$ ")

        except Exception as e:
            log_error(str(e), "session_command")

# ---------------- SERVER ----------------
class SSHHoneypot(asyncssh.SSHServer):

    def connection_made(self, conn):
        self.conn = conn
        peer = conn.get_extra_info("peername")
        self.ip = peer[0] if peer else "unknown"

        IP_CONNECTIONS[self.ip] = IP_CONNECTIONS.get(self.ip, 0) + 1

        if IP_CONNECTIONS[self.ip] > MAX_CONNECTIONS_PER_IP:
            log_error("Connection limit exceeded", self.ip)
            IP_CONNECTIONS[self.ip] -= 1
            raise asyncssh.DisconnectError(
                asyncssh.DisconnectReason.BY_APPLICATION,
                "Too many connections"
            )

    def connection_lost(self, exc):
        if self.ip in IP_CONNECTIONS:
            IP_CONNECTIONS[self.ip] = max(0, IP_CONNECTIONS[self.ip] - 1)

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        try:
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

        except Exception as e:
            log_error(str(e), "auth")
            raise

    def session_requested(self):
        asyncio.get_event_loop().call_later(
            SESSION_TIMEOUT,
            self._timeout_close
        )
        return HoneypotSession(self.ip, self.conn.get_extra_info("username"))

    def _timeout_close(self):
        try:
            log_error("Session timeout", self.ip)
            self.conn.close()
        except Exception:
            pass

# ---------------- START ----------------
async def start_server():
    try:
        await asyncssh.create_server(
            SSHHoneypot,
            HOST,
            PORT,
            server_host_keys=[HOST_KEY]
        )
        print(f"[+] AsyncSSH Honeypot running on port {PORT}")
        await asyncio.Future()
    except Exception as e:
        log_error(str(e), "server_start")

if __name__ == "__main__":
    asyncio.run(start_server())
