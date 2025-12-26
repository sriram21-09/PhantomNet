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
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(data) + "\n")
    except Exception as e:
        log_error(str(e), "log_event")

def log_error(msg, context=""):
    with open(ERROR_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | {context} | {msg}\n")

# ---------------- FAKE FILESYSTEM ----------------
BASE_FS = {
    "/": ["bin", "etc", "home"],
    "/home": ["ubuntu"],
    "/home/ubuntu": ["notes.txt"],
}

FILE_CONTENTS = {
    "/home/ubuntu/notes.txt": "remember to backup server configs\n"
}

# ---------------- SESSION ----------------
class HoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, ip, username):
        self.ip = ip
        self.username = username or "ubuntu"
        self.cwd = "/home/ubuntu"
        self.chan = None

    def connection_made(self, chan):
        self.chan = chan
        self.chan.write("Welcome to Ubuntu 20.04 LTS\r\n")
        self._prompt()

    def _prompt(self):
        self.chan.write(f"{self.username}@honeypot:{self.cwd}$ ")

    def shell_requested(self):
        return True

    def data_received(self, data, datatype):
        try:
            cmd = data.strip()
            if not cmd:
                self._prompt()
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

            output = self.handle_command(cmd)
            if output:
                self.chan.write(output)

            self._prompt()

        except Exception as e:
            log_error(str(e), "session_command")

    # ---------------- COMMAND HANDLER ----------------
    def handle_command(self, cmd):
        parts = cmd.split()
        command = parts[0]

        if command == "pwd":
            return f"{self.cwd}\n"

        if command == "ls":
            return " ".join(BASE_FS.get(self.cwd, [])) + "\n"

        if command == "cd":
            target = parts[1] if len(parts) > 1 else "/home/ubuntu"
            new_path = target if target.startswith("/") else f"{self.cwd}/{target}"
            if new_path in BASE_FS:
                self.cwd = new_path
            return ""

        if command == "mkdir" and len(parts) > 1:
            new_dir = f"{self.cwd}/{parts[1]}"
            BASE_FS[new_dir] = []
            BASE_FS[self.cwd].append(parts[1])
            return ""

        if command == "touch" and len(parts) > 1:
            file_path = f"{self.cwd}/{parts[1]}"
            FILE_CONTENTS[file_path] = ""
            BASE_FS[self.cwd].append(parts[1])
            return ""

        if command == "cat" and len(parts) > 1:
            file_path = f"{self.cwd}/{parts[1]}"
            return FILE_CONTENTS.get(file_path, "cat: file not found\n")

        if command == "rm" and len(parts) > 1:
            target = f"{self.cwd}/{parts[1]}"
            FILE_CONTENTS.pop(target, None)
            if parts[1] in BASE_FS.get(self.cwd, []):
                BASE_FS[self.cwd].remove(parts[1])
            return ""

        if command == "whoami":
            return f"{self.username}\n"

        if command == "clear":
            return "\033c"

        return f"bash: {cmd}: command not found\n"

# ---------------- SERVER ----------------
class SSHHoneypot(asyncssh.SSHServer):

    def get_server_banner(self):
        return "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"

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
        asyncio.get_event_loop().call_later(
            SESSION_TIMEOUT,
            self.conn.close
        )
        return HoneypotSession(self.ip, self.conn.get_extra_info("username"))

# ---------------- START ----------------
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
