import os
import json
from datetime import datetime, timezone
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# -------------------------
# Paths
# -------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FTP_ROOT = os.path.join(BASE_DIR, "ftp_root")
LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../logs"))
LOG_FILE = os.path.join(LOG_DIR, "ftp_logs.jsonl")

os.makedirs(FTP_ROOT, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# -------------------------
# Logging helper
# -------------------------
def log_event(ip, event, data=None):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip,
        "honeypot_type": "ftp",
        "event": event,
        "data": data
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# -------------------------
# Custom FTP Handler
# -------------------------
class HoneypotFTPHandler(FTPHandler):

    def on_connect(self):
        log_event(self.remote_ip, "connect")

    def on_login(self, username):
        log_event(self.remote_ip, "login_success", {"username": username})

    def on_login_failed(self, username, password):
        log_event(
            self.remote_ip,
            "login_failed",
            {"username": username, "password": password}
        )

    def on_disconnect(self):
        log_event(self.remote_ip, "disconnect")

    # 🔥 CAPTURE ALL FTP COMMANDS
    def pre_process_command(self, line, cmd, arg):
        log_event(
            self.remote_ip,
            "command",
            {
                "command": cmd,
                "argument": arg,
                "raw": line
            }
        )
        return super().pre_process_command(line, cmd, arg)

    def on_file_received(self, file):
        log_event(self.remote_ip, "file_upload", {"file": file})

    def on_file_sent(self, file):
        log_event(self.remote_ip, "file_download", {"file": file})

# -------------------------
# Server Setup
# -------------------------
authorizer = DummyAuthorizer()

# Fake credentials
authorizer.add_user("PhantomNet", "1234", FTP_ROOT, perm="elradfmw")
authorizer.add_anonymous(FTP_ROOT, perm="elr")

handler = HoneypotFTPHandler
handler.authorizer = authorizer

server = FTPServer(("0.0.0.0", 2121), handler)

print("[+] FTP Honeypot running on port 2121")
server.serve_forever()
