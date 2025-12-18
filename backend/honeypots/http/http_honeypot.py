import http.server
import socketserver
import json
import os
from datetime import datetime, timezone

LOG_DIR = "/logs"
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "http_logs.jsonl")
ERROR_LOG = os.path.join(LOG_DIR, "http_error.log")

def log_error(exc, context=""):
    with open(ERROR_LOG, "a") as f:
        f.write(f"{datetime.now(timezone.utc).isoformat()} | {context} | {repr(exc)}\n")

def log_http(ip, method, path, extra=None):
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": ip,
        "honeypot_type": "http",
        "port": 8080,
        "method": method,
        "url": path,
        "raw_data": f"{method} {path}",
    }
    if extra:
        data.update(extra)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")

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

class HoneypotHandler(http.server.BaseHTTPRequestHandler):

    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def do_GET(self):
        try:
            log_http(self.client_address[0], "GET", self.path,
                     {"headers": dict(self.headers)})
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
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore")

            log_http(self.client_address[0], "POST", self.path, {
                "headers": dict(self.headers),
                "body": body
            })

            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Invalid credentials")

        except Exception as e:
            log_error(e, "POST")
            self._set_headers(400)

    def do_PUT(self):
        try:
            log_http(self.client_address[0], "PUT", self.path,
                     {"headers": dict(self.headers)})
            self._set_headers(403)
            self.wfile.write(b"403 Forbidden")
        except Exception as e:
            log_error(e, "PUT")
            self._set_headers(500)

    def do_DELETE(self):
        try:
            log_http(self.client_address[0], "DELETE", self.path,
                     {"headers": dict(self.headers)})
            self._set_headers(404)
            self.wfile.write(b"404 Not Found")
        except Exception as e:
            log_error(e, "DELETE")
            self._set_headers(500)

if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", 8080), HoneypotHandler) as server:
        print("[+] HTTP Honeypot running on port 8080")
        server.serve_forever()
