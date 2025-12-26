import os
import json
from datetime import datetime, timezone
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# ======================
# CONFIG
# ======================
MAX_SESSIONS_PER_IP = 2
SESSION_TIMEOUT = 180

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FTP_ROOT = os.path.join(BASE_DIR, "ftp_root")
LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../logs"))

LOG_FILE = os.path.join(LOG_DIR, "ftp_logs.jsonl")
ERROR_LOG = os.path.join(LOG_DIR, "ftp_error.log")

os.makedirs(FTP_ROOT, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

IP_SESSIONS = {}

# ======================
# FAKE FILE METADATA
# ======================
FAKE_FILE_SIZES = {
    "readme.txt": 128,
    "db_backup.sql": 20480,
    "config.tar.gz": 102400
}

# ======================
# LOGGING
# ======================
def log_event(ip, event, data=None, level="INFO"):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": ip,
            "honeypot_type": "ftp",
            "event": event,
            "data": data,
            "level": level
        }) + "\n")

def log_error(msg, ip):
    with open(ERROR_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | {ip} | {msg}\n")

# ======================
# HANDLER
# ======================
class HoneypotFTPHandler(FTPHandler):

    def on_connect(self):
        ip = self.remote_ip
        IP_SESSIONS[ip] = IP_SESSIONS.get(ip, 0) + 1

        if IP_SESSIONS[ip] > MAX_SESSIONS_PER_IP:
            log_error("FTP connection limit exceeded", ip)
            self.respond("421 Too many connections.")
            self.close_when_done()
            return

        self.timeout = SESSION_TIMEOUT
        log_event(ip, "connect")

    def on_login(self, username):
        log_event(self.remote_ip, "login_success", {"username": username})

    def on_login_failed(self, username, password):
        log_event(
            self.remote_ip,
            "login_failed",
            {"username": username, "password": password},
            "WARN"
        )

    # ======================
    # SAFE COMMAND EXTENSIONS
    # ======================
    def ftp_CWD(self, path):
        log_event(self.remote_ip, "command", {"command": "CWD", "path": path})
        return super().ftp_CWD(path)

    def ftp_SIZE(self, path):
        log_event(self.remote_ip, "command", {"command": "SIZE", "file": path})

        filename = os.path.basename(path)
        size = FAKE_FILE_SIZES.get(filename)

        if size:
            self.respond(f"213 {size}")
        else:
            self.respond("550 Could not get file size.")

    def ftp_RETR(self, file):
        """
        Honeypot behavior:
        - Log exfiltration attempt
        - Block transfer
        - Do NOT open data channel
        """
        log_event(
            self.remote_ip,
            "command",
            {"command": "RETR", "file": file},
            "WARN"
        )

        self.respond("550 Permission denied.")

    def pre_process_command(self, line, cmd, arg):
        log_event(
            self.remote_ip,
            "command",
            {"command": cmd, "arg": arg}
        )
        return super().pre_process_command(line, cmd, arg)

    def on_disconnect(self):
        ip = self.remote_ip
        IP_SESSIONS[ip] = max(0, IP_SESSIONS.get(ip, 1) - 1)
        log_event(ip, "disconnect")

# ======================
# SERVER SETUP
# ======================
authorizer = DummyAuthorizer()
authorizer.add_user("PhantomNet", "1234", FTP_ROOT, perm="elradfmw")
authorizer.add_anonymous(FTP_ROOT, perm="elr")

handler = HoneypotFTPHandler
handler.authorizer = authorizer

server = FTPServer(("0.0.0.0", 2121), handler)
print("[+] FTP Honeypot running on port 2121")
server.serve_forever()
