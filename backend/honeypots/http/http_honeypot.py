import http.server
import socketserver
import json
import os
import requests
from datetime import datetime, timezone

# ======================
# CONFIG
# ======================
PORT = 8080
BACKEND_API = "http://127.0.0.1:8000/api/logs"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "http_logs.jsonl")
ERROR_LOG = os.path.join(LOG_DIR, "http_error.log")

# ======================
# HELPERS
# ======================
def log_error(exc, context=""):
    with open(ERROR_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | {context} | {repr(exc)}\n")

def send_to_backend(ip, method, path, headers, body=""):
    payload = {
        "source_ip": ip,
        "honeypot_type": "http",
        "port": PORT,
        "raw_data": f"{method} {path} | UA={headers.get('User-Agent')} | BODY={body}"
    }
    try:
        requests.post(BACKEND_API, json=payload, timeout=2)
    except Exception as e:
        log_error(e, "send_to_backend")

def log_http(ip, method, path, headers, body=""):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip,
        "honeypot_type": "http",
        "port": PORT,
        "raw_data": f"{method} {path} | UA={headers.get('User-Agent')} | BODY={body}"
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ======================
# FAKE LOGIN PAGE
# ======================
LOGIN_PAGE = b"""
<html>
<body>
<h2>Admin Panel</h2>
<form method="POST" action="/admin">
Username: <input name="username"><br>
Password: <input type="password" name="password"><br>
<button>Login</button>
</form>
</body>
</html>
"""

# ======================
# HANDLER
# ======================
class HoneypotHandler(http.server.BaseHTTPRequestHandler):

    def _set_headers(self, code=200, content="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content)
        self.end_headers()

    def do_GET(self):
        try:
            ip = self.client_address[0]
            headers = dict(self.headers)

            log_http(ip, "GET", self.path, headers)
            send_to_backend(ip, "GET", self.path, headers)

            if self.path == "/admin":
                self._set_headers(200)
                self.wfile.write(LOGIN_PAGE)
            else:
                self._set_headers(404)
                self.wfile.write(b"404 Not Found")

        except Exception as e:
            log_error(e, "GET")
            self._set_headers(500)

    def do_POST(self):
        try:
            ip = self.client_address[0]
            headers = dict(self.headers)

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore")

            log_http(ip, "POST", self.path, headers, body)
            send_to_backend(ip, "POST", self.path, headers, body)

            self._set_headers(403, "text/plain")
            self.wfile.write(b"Invalid credentials")

        except Exception as e:
            log_error(e, "POST")
            self._set_headers(400)

    def do_PUT(self):
        try:
            ip = self.client_address[0]
            headers = dict(self.headers)

            log_http(ip, "PUT", self.path, headers)
            send_to_backend(ip, "PUT", self.path, headers)

            self._set_headers(403)
            self.wfile.write(b"403 Forbidden")

        except Exception as e:
            log_error(e, "PUT")
            self._set_headers(500)

    def do_DELETE(self):
        try:
            ip = self.client_address[0]
            headers = dict(self.headers)

            log_http(ip, "DELETE", self.path, headers)
            send_to_backend(ip, "DELETE", self.path, headers)

            self._set_headers(404)
            self.wfile.write(b"404 Not Found")

        except Exception as e:
            log_error(e, "DELETE")
            self._set_headers(500)

# ======================
# START SERVER
# ======================
if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), HoneypotHandler) as server:
        print(f"[+] HTTP Honeypot running on port {PORT}")
        server.serve_forever()
