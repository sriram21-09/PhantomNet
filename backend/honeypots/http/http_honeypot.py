import http.server
import socketserver
import json
import os
from datetime import datetime, timezone

# Your correct log directory
LOG_DIR = "../../logs/http/"
os.makedirs(LOG_DIR, exist_ok=True)

# Daily log file
LOG_FILE = LOG_DIR + f"http_{datetime.now().date()}.log"


def log_request(data):
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(data) + "\n")


# Fake admin page
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


class HoneypotHandler(http.server.SimpleHTTPRequestHandler):

    def log_message(self, format, *args):
        return  # disable default logging

    def do_GET(self):
        log_request({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": self.client_address[0],
            "method": "GET",
            "url": self.path,
            "headers": dict(self.headers),
            "honeypot_type": "http",
            "port": 8080
        })

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

        # Convert "key=value" format to dict
        data = dict(item.split("=") for item in body.split("&"))

        log_request({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": self.client_address[0],
            "method": "POST",
            "url": self.path,
            "headers": dict(self.headers),
            "honeypot_type": "http",
            "port": 8080,
            "submitted_data": data
        })

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Invalid credentials. Try again.")


if __name__ == "__main__":
    PORT = 8080
    server = socketserver.TCPServer(("0.0.0.0", PORT), HoneypotHandler)
    print("[+] HTTP Honeypot running on port 8080")
    server.serve_forever()