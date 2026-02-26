import os
import json
import sys
from datetime import datetime, timezone
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Database logger for accurate last_seen
try:
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from db_logger import log_ftp_activity
    DB_ENABLED = True
except ImportError:
    DB_ENABLED = False
    print("[FTP] Database logger not available, using file-only logging")

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
import logging
from logging.handlers import RotatingFileHandler

# Configure Logger for FTP Logs
ftp_logger = logging.getLogger("phantom_ftp")
ftp_logger.setLevel(logging.INFO)
# Use RotatingFileHandler to prevent huge files (10MB limit, 5 backups)
handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
# Raw message formatter - no prefixes, just JSON
handler.setFormatter(logging.Formatter('%(message)s'))
ftp_logger.addHandler(handler)

# Configure Error Logger
error_logger = logging.getLogger("phantom_ftp_error")
error_logger.setLevel(logging.ERROR)
err_handler = RotatingFileHandler(ERROR_LOG, maxBytes=10*1024*1024, backupCount=3, encoding='utf-8')
err_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
error_logger.addHandler(err_handler)

def log_event(ip, event, data=None, level="INFO"):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip,
        "honeypot_type": "ftp",
        "event": event,
        "data": data,
        "level": level
    }
    # Clean JSON dump + threading/process safety via logging module
    try:
        ftp_logger.info(json.dumps(entry))
    except (TypeError, ValueError) as e:
        error_logger.error(f"JSON serialization failed for {ip}: {e}")
    
    # Also log to database for accurate last_seen
    if DB_ENABLED:
        try:
            is_malicious = event in ["login_failed", "exfiltration_attempt"]
            log_ftp_activity(ip, event, is_malicious=is_malicious)
        except Exception as e:
            print(f"[FTP] DB logging failed: {e}")

def log_error(msg, ip):
    error_logger.error(f"{ip} | {msg}")

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
    # COMMAND HANDLING
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

    def ftp_LIST(self, path):
        """
        Allow LIST so pytest passes.
        No sensitive data exposed.
        """
        log_event(
            self.remote_ip,
            "command",
            {"command": "LIST", "path": path}
        )
        return super().ftp_LIST(path)

    def ftp_RETR(self, file):
        """
        Honeypot behavior:
        - Log exfiltration attempt
        - Block transfer
        - Raise proper FTP error (pytest expects this)
        """
        log_event(
            self.remote_ip,
            "command",
            {"command": "RETR", "file": file},
            "WARN"
        )
        self.respond("550 Permission denied.")
        return

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

# 🔴 CRITICAL FIX FOR WINDOWS + PYTEST + FTPLIB
handler.passive_ports = range(30000, 30020)
handler.permit_foreign_addresses = True
handler.masquerade_address = "127.0.0.1"

server = FTPServer(("0.0.0.0", 2121), handler)

# 🔐 FIX: Passive FTP for Docker
server.passive_ports = range(30000, 30020)


print("[+] FTP Honeypot running on port 2121")
server.serve_forever()
