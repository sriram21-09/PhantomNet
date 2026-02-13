from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from datetime import datetime, timezone
from collections import defaultdict
from urllib.parse import parse_qs

# Database logger for accurate last_seen
try:
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from db_logger import log_http_activity
    DB_ENABLED = True
except Exception as e:
    DB_ENABLED = False
    print(f"[HTTP] Database logger not available, using file-only logging. Error: {e}")

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
def log(level, payload):
    payload["level"] = level
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(payload) + "\n")
    
    # Also log to database for accurate last_seen
    if DB_ENABLED:
        try:
            src_ip = payload.get("src_ip", "unknown")
            event_type = payload.get("event", "activity")
            is_malicious = level == "ERROR"  # SQLi attempts are errors
            log_http_activity(src_ip, event_type, is_malicious=is_malicious)
        except Exception as e:
            print(f"[HTTP] DB logging failed: {e}")

def log_error(msg, context):
    with open(ERROR_LOG, "a") as f:
        f.write(
            f"{datetime.now(timezone.utc).isoformat()} | {context} | {msg}\n"
        )

# ======================
# SQLi DETECTION
# ======================
SQLI_PATTERNS = [
    "' or 1=1",
    "\" or \"1\"=\"1",
    "union select",
    "--",
    ";--",
    "'--",
    "\"--"
]

def is_sqli(value):
    if not value:
        return False
    value = value.lower()
    return any(p in value for p in SQLI_PATTERNS)

# ======================
# FAKE PAGES
# ======================
ADMIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Admin Dashboard</title>
<style>
body { font-family: Arial; background:#f2f4f7; }
.container {
  width:420px; margin:80px auto; background:#fff;
  padding:25px; border-radius:6px;
  box-shadow:0 3px 10px rgba(0,0,0,.15);
}
.notice {
  background:#fff3cd; padding:10px; font-size:13px;
  border-left:4px solid #ff9800; margin-bottom:15px;
}
.ad {
  background:#e3f2fd; padding:10px; font-size:12px;
  border-left:4px solid #2196f3; margin-bottom:15px;
}
input,button { width:100%; padding:10px; margin-top:8px; }
button { background:#2f80ed; color:white; border:none; }
a { display:block; text-align:center; margin-top:10px; font-size:13px; }
</style>
</head>
<body>
<div class="container">
<h2>Admin Dashboard</h2>

<div class="notice">---------------- WELCOME TO PHANTOMNET ---------------</div>
<div class="ad">Upgrade to Admin Pro for enhanced security.</div>

<form method="POST" action="/admin">
<input name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button>Sign in</button>
</form>

<a href="/forgot-password">Forgot password?</a>

<p style="text-align:center;font-size:12px;color:#888;">
© 2025 Internal Admin System
</p>
</div>
</body>
</html>
"""

FORGOT_PAGE = """
<!DOCTYPE html>
<html>
<head>
<title>Password Recovery</title>
</head>
<body>
<h3>Password Recovery</h3>
<form method="POST" action="/forgot-password">
<input name="email" placeholder="Email address" required>
<button>Reset Password</button>
</form>
</body>
</html>
"""

# ======================
# HANDLER
# ======================
class HoneypotHandler(BaseHTTPRequestHandler):

    def setup(self):
        super().setup()
        self.request.settimeout(REQUEST_TIMEOUT)

    def _log_event(self, event, level, data=None):
        log(level, {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": self.client_address[0],
            "honeypot_type": "http",
            "port": PORT,
            "event": event,
            "method": self.command,
            "path": self.path,
            "user_agent": self.headers.get("User-Agent"),
            "data": data or {}
        })

    def _check_ip_limit(self):
        ip = self.client_address[0]
        ip_connections[ip] += 1
        if ip_connections[ip] > MAX_CONN_PER_IP:
            self._log_event("rate_limited", "WARN")
            self.send_response(429)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Too Many Requests")
            return False
        return True

    def finish(self):
        try:
            ip_connections[self.client_address[0]] = max(
                0, ip_connections[self.client_address[0]] - 1
            )
        except Exception:
            pass
        super().finish()

    # ======================
    # HTTP METHODS
    # ======================
    def do_GET(self):
        if not self._check_ip_limit():
            return

        if self.path == "/admin":
            self._log_event("page_view", "INFO")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(ADMIN_PAGE.encode())

        elif self.path == "/forgot-password":
            self._log_event("forgot_password_view", "INFO")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(FORGOT_PAGE.encode())

        else:
            self._log_event("scan_attempt", "INFO")
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        if not self._check_ip_limit():
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="ignore")
        params = parse_qs(body)

        if self.path == "/admin":
            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            if is_sqli(username) or is_sqli(password):
                self._log_event(
                    "sqli_attempt", "ERROR",
                    {"username": username, "password": password}
                )
            else:
                self._log_event(
                    "login_attempt", "WARN",
                    {"username": username, "password": password}
                )

            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Invalid credentials")

        elif self.path == "/forgot-password":
            email = params.get("email", [""])[0]
            self._log_event(
                "password_reset_request", "WARN",
                {"email": email}
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Password reset link sent")

        else:
            self.send_response(404)
            self.end_headers()

    def do_PUT(self):
        self._log_event("put_attempt", "WARN")
        self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"403 Forbidden")

    def do_DELETE(self):
        self._log_event("delete_attempt", "WARN")
        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def log_message(self, format, *args):
        return

# ======================
# START SERVER
# ======================
if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), HoneypotHandler)
    print(f"[+] HTTP Honeypot running on port {PORT}")
    server.serve_forever()
