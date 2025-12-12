import http.server
import socketserver
import json
import os
from datetime import datetime, timezone

# --------------------------
# Log file paths
# --------------------------
LOG_DIR = "/logs"
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "http_logs.jsonl")
ERROR_LOG = os.path.join(LOG_DIR, "http_error.log")

# --------------------------
# Logging helpers
# --------------------------
def log_error(exc: Exception, context: str = ""):
    try:
        with open(ERROR_LOG, "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} - {context} - {repr(exc)}\n")
    except Exception as e:
        print("Error writing to error log:", e)

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
# Honeypot Request Handler
# --------------------------
class HoneypotHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return  # Disable default console logging

    def do_GET(self):
        try:
            #raise ValueError("Test error")

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

        except Exception as e:
            log_error(e, f"do_GET error from {self.client_address[0]} path={self.path}")
            print("🔥 ERROR CAUGHT:", e)
            try:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Server error")
            except:
                pass

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode(errors="ignore")

            # Parse key=value pairs from form
            form_data = {}
            for pair in body.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    form_data[k] = v

            # Log the POST request
            log_http(self.client_address[0], "POST", self.path, extra={
                "headers": dict(self.headers),
                "submitted_data": form_data
            })

            # Respond with fake "Invalid credentials" message
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Invalid credentials. Try again.")

        except Exception as e:
            log_error(e, f"do_POST error from {self.client_address[0]} path={self.path}")
            print("🔥 ERROR CAUGHT in POST:", e)
            try:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Bad request")
            except:
                pass

# --------------------------
# Run HTTP Honeypot
# --------------------------
if __name__ == "__main__":
    PORT = 8080
    server = socketserver.TCPServer(("0.0.0.0", PORT), HoneypotHandler)
    print(f"[+] HTTP Honeypot running on port {PORT}")
    server.serve_forever()
