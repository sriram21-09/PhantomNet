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
import socket
import json
from datetime import datetime
import requests

BACKEND_API = "http://127.0.0.1:8000/api/logs"
PORT = 2121  # avoid real FTP port conflicts

def send_event(ip, raw):
    payload = {
        "source_ip": ip,
        "honeypot_type": "ftp",
        "port": PORT,
        "raw_data": raw
    }
    try:
        requests.post(BACKEND_API, json=payload, timeout=2)
    except:
        pass

def start_ftp():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", PORT))
    server.listen(5)

    print(f"[+] FTP Honeypot running on port {PORT}")

    while True:
        client, addr = server.accept()
        ip = addr[0]

        send_event(ip, "FTP connection attempt")
        client.send(b"220 FTP Server Ready\r\n")

        try:
            user = client.recv(1024).decode(errors="ignore").strip()
            send_event(ip, f"USER command: {user}")
            client.send(b"331 Username OK, need password\r\n")

            pwd = client.recv(1024).decode(errors="ignore").strip()
            send_event(ip, f"PASS command: {pwd}")
            client.send(b"530 Login incorrect\r\n")

        except Exception as e:
            send_event(ip, f"FTP error: {str(e)}")

        client.close()

if __name__ == "__main__":
    start_ftp()
