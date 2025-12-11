import http.server
import socketserver
import json
import os
from datetime import datetime, timezone

# --------------------------
# Log file path
# --------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "../../http_logs.json")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

# --------------------------
# Logging Helper
# --------------------------
def log_http(source_ip, method, url, extra=None):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": source_ip,
        "honeypot_type": "http",
        "port": 8080,
        "raw_data": f"{method} {url}",
        "method": method,
        "url": url
    }
    if extra and isinstance(extra, dict):
        entry.update(extra)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# --------------------------
# Fake Admin Page
# --------------------------
LOGIN_PAGE = """
<html>
<head><title>Admin Login</title></head>
<body>
<h2>Admin Panel</h2>
<form method="POST" action="/admin">
    Username: <input name="username" type="text" /><br><br>
    Password: <input name="password" type="password" /><br><br>
    <button type="submit">Login</button>
</form>
</body>
</html>
"""

# --------------------------
# Request Handler
# --------------------------
class HoneypotHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return  # disable console logging

    def do_GET(self):
        log_http(self.client_address[0], "GET", self.path, extra={"headers": dict(self.headers)})
        if self.path == "/admin":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(LOGIN_PAGE.encode())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        # Parse POST data
        form_data = {}
        try:
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    form_data[k] = v
        except:
            pass

        log_http(
            self.client_address[0],
            "POST",
            self.path,
            extra={
                "headers": dict(self.headers),
                "submitted_data": form_data
            }
        )

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Invalid credentials. Try again.")

# --------------------------
# Run Server
# --------------------------
if __name__ == "__main__":
    PORT = 8080
    server = socketserver.TCPServer(("0.0.0.0", PORT), HoneypotHandler)
    print(f"[+] HTTP Honeypot running on port {PORT}")
    server.serve_forever()
