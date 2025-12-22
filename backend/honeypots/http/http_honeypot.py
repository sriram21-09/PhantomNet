import http.server
import socketserver
import json
import os
from datetime import datetime, timezone
from collections import defaultdict
from urllib.parse import parse_qs

# ======================
# CONFIG
# ======================
PORT = 8080
REQUEST_TIMEOUT = 5
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
# FAKE PAGES (NO BYTES LITERALS)
# ======================
INDEX_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h2>Internal Portal</h2>
<a href="/admin">Admin Login</a>
</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
<h2>Login</h2>
<form method="POST" action="/login">
Username: <input name="username"><br>
Password: <input type="password" name="password"><br>
<button>Login</button>
</form>
</body>
</html>
"""

ADMIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Admin Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f6f8;
        }
        .container {
            width: 360px;
            margin: 120px auto;
            background: #ffffff;
            padding: 25px;
            border-radius: 6px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.15);
        }
        h2 {
            text-align: center;
            margin-bottom: 20px;
            color: #333;
        }
        input {
            width: 100%;
            padding: 10px;
            margin-top: 8px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        button {
            width: 100%;
            padding: 10px;
            background-color: #2f80ed;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 15px;
            cursor: pointer;
        }
        button:hover {
            background-color: #256fd1;
        }
        .footer {
            margin-top: 15px;
            font-size: 12px;
            text-align: center;
            color: #888;
        }
    </style>
</head>
<body>
<div class="container">
    <h2>Admin Dashboard</h2>
    <form method="POST" action="/admin">
        <input type="text" name="username" placeholder="Username" required />
        <input type="password" name="password" placeholder="Password" required />
        <button type="submit">Sign in</button>
    </form>
    <div class="footer">
        © 2025 Internal Admin System
    </div>
</div>
</body>
</html>
"""

# ======================
# HANDLER
# ======================
class HoneypotHandler(http.server.BaseHTTPRequestHandler):

    def setup(self):
        super().setup()
        self.request.settimeout(REQUEST_TIMEOUT)

    def _base_log(self, level, event, extra=None):
        data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": self.client_address[0],
            "honeypot_type": "http",
            "port": PORT,
            "event": event,
            "method": self.command,
            "path": self.path,
            "user_agent": self.headers.get("User-Agent")
        }
        if extra:
            data["data"] = extra
        log(level, data)

    def _check_ip_limit(self):
        ip = self.client_address[0]
        ip_connections[ip] += 1

        if ip_connections[ip] > MAX_CONN_PER_IP:
            self._base_log("WARN", "rate_limited")
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
        except Exception:
            pass
        super().finish()

    # ======================
    # METHODS
    # ======================
    def do_GET(self):
        try:
            if not self._check_ip_limit():
                return

            self._base_log("INFO", "page_view")

            if self.path == "/":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(INDEX_PAGE.encode())

            elif self.path == "/login":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(LOGIN_PAGE.encode())

            elif self.path == "/admin":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(ADMIN_PAGE.encode())

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

            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore")
            params = parse_qs(body)

            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            self._base_log(
                "WARN",
                "login_attempt",
                {"username": username, "password": password}
            )

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

            self._base_log("WARN", "put_attempt")
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

            self._base_log("WARN", "delete_attempt")
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

        except Exception as e:
            log_error(e, "DELETE")
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        return

# ======================
# START SERVER
# ======================
if __name__ == "__main__":
    with socketserver.TCPServer(("0.0.0.0", PORT), HoneypotHandler) as server:
        print(f"[+] HTTP Honeypot running on port {PORT}")
        server.serve_forever()
