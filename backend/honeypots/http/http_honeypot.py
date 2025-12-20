import http.server
import socketserver
import json
import os
import time
from datetime import datetime, timezone
from collections import defaultdict

# ======================
# CONFIG
# ======================
PORT = 8080
REQUEST_TIMEOUT = 5          # seconds
MAX_CONN_PER_IP = 10

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.abspath(os.path.join(BASE_DIR, "../../logs"))

LOG_FILE = os.path.join(LOG_DIR, "http_logs.jsonl")
ERROR_LOG = os.path.join(LOG_DIR, "http_error.log")

os.makedirs(LOG_DIR, exist_ok=True)

ip_connections = defaultdict(int)

# ======================
# LOGGING
# ======================
def log(level, data):
    data["level"] = level
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

def log_error(exc, context):
    with open(ERROR_LOG, "a") as f:
        f.write(
            f"{datetime.now(timezone.utc).isoformat()} | {context} | {repr(exc)}\n"
        )

# ======================
# FAKE PAGE
# ======================
LOGIN_PAGE = b"""
<html><body>
<h2>Admin Panel</h2>
<form method="POST" action="/admin">
Username: <input name="username"><br>
Password: <input type="password" name="password"><br>
<button>Login</button>
</form>
</body></html>
"""

# ======================
# HANDLER
# ======================
class HoneypotHandler(http.server.BaseHTTPRequestHandler):

    def setup(self):
        super().setup()
        self.request.settimeout(REQUEST_TIMEOUT)

    def _log_request(self, level, method):
        log(level, {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.client_address[0],
            "honeypot_type": "http",
            "port": PORT,
            "method": method,
            "path": self.path
        })

    def _check_ip_limit(self):
        ip = self.client_address[0]
        ip_connections[ip] += 1

        if ip_connections[ip] > MAX_CONN_PER_IP:
            self._log_request("WARN", "BLOCKED")
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b"Too Many Requests")
            return False

        return True

    def finish(self):
        try:
            ip_connections[self.client_address[0]] -= 1
            if ip_connections[self.client_address[0]] < 0:
                ip_connections[self.client_address[0]] = 0
        except:
            pass
        super().finish()

    # ======================
    # METHODS
    # ======================
    def do_GET(self):
        try:
            if not self._check_ip_limit():
                return

            self._log_request("INFO", "GET")

            if self.path == "/admin":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(LOGIN_PAGE)
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"404 Not Found")

        except Exception as e:
            log_error(e, "GET")
            self.send_response(500)
            self.end_headers()

    def do_POST(self):
        try:
            if not self._check_ip_limit():
                return

            self._log_request("WARN", "POST")

            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Invalid credentials")

        except Exception as e:
            log_error(e, "POST")
            self.send_response(500)
            self.end_headers()

    def do_PUT(self):
        try:
            if not self._check_ip_limit():
                return

            self._log_request("WARN", "PUT")

            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"403 Forbidden")

        except Exception as e:
            log_error(e, "PUT")
            self.send_response(500)
            self.end_headers()

    def do_DELETE(self):
        try:
            if not self._check_ip_limit():
                return

            self._log_request("WARN", "DELETE")

            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

        except Exception as e:
            log_error(e, "DELETE")
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        return  # disable default console logs

# ======================
# START SERVER
# ======================
if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), HoneypotHandler) as server:
        print(f"[+] HTTP Honeypot running on port {PORT}")
        server.serve_forever()
