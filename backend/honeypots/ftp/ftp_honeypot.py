import os
import json
from datetime import datetime, timezone
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

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
# FAKE FTP CONTENT
# ======================
FAKE_FILES = {
    "readme.txt": b"Welcome to the FTP server\n",
    "backup.zip": b"PK\x03\x04FakeZipData",
    "config.conf": b"user=admin\npassword=secret\n"
}

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
    # TASK 4: ENHANCED COMMANDS
    # ======================
    def ftp_LIST(self, path):
        """Fake directory listing"""
        try:
            ip = self.remote_ip
            log_event(ip, "command", {"command": "LIST", "path": path})

            for name in FAKE_FILES.keys():
                line = f"-rw-r--r-- 1 ftp ftp {len(FAKE_FILES[name])} Jan 01 00:00 {name}\r\n"
                self.push(line.encode())

            self.respond("226 Directory send OK.")
        except Exception as e:
            log_error(str(e), self.remote_ip)

    def ftp_RETR(self, file):
        """Fake file download"""
        try:
            ip = self.remote_ip
            log_event(ip, "command", {"command": "RETR", "file": file}, "WARN")

            filename = os.path.basename(file)

            if filename in FAKE_FILES:
                self.respond("150 Opening binary mode data connection.")
                self.push(FAKE_FILES[filename])
                self.respond("226 Transfer complete.")
            else:
                self.respond("550 File not found.")
        except Exception as e:
            log_error(str(e), self.remote_ip)

    def pre_process_command(self, line, cmd, arg):
        try:
            log_event(
                self.remote_ip,
                "command",
                {"command": cmd, "arg": arg}
            )
        except Exception as e:
            log_error(str(e), self.remote_ip)

        return super().pre_process_command(line, cmd, arg)

    def on_disconnect(self):
        ip = self.remote_ip
        if ip in IP_SESSIONS:
            IP_SESSIONS[ip] = max(0, IP_SESSIONS[ip] - 1)

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
