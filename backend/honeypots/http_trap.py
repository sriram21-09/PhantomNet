from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import psycopg2

# --- CONFIG ---
# We use the socket path because Mininet isolates the network
DB_CONFIG = {
    "dbname": "phantomnet", 
    "user": "phantom", 
    "password": "securepass", 
    "host": "/var/run/postgresql"
}

def log_attack(ip, user, password):
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("INSERT INTO attack_logs (attacker_ip, target_node, service_type, username, password) VALUES (%s, %s, %s, %s, %s)",
                    (ip, "h3", "HTTP", user, password))
        conn.commit()
        conn.close()
        print(f"✅ LOGGED: {user}/{password}")
    except Exception as e:
        print(f"❌ DB ERROR: {e}")

class PhishingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Serve a fake login page
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = """
        <html><head><title>Admin Login</title></head>
        <body style='background-color:#111; color:#0f0; font-family:monospace; text-align:center; margin-top:50px;'>
            <h1>⚠ RESTRICTED AREA ⚠</h1>
            <form method='POST'>
                <input type='text' name='username' placeholder='Username' style='padding:10px;'><br><br>
                <input type='password' name='password' placeholder='Password' style='padding:10px;'><br><br>
                <button type='submit'>LOGIN</button>
            </form>
        </body></html>
        """
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self):
        # Capture the credentials
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = urllib.parse.parse_qs(post_data)
        
        username = data.get('username', [''])[0]
        password = data.get('password', [''])[0]
        
        log_attack(self.client_address[0], username, password)
        
        self.send_response(403)
        self.end_headers()
        self.wfile.write(b"ACCESS DENIED. INCIDENT LOGGED.")

if __name__ == "__main__":
    print("🕸️ HTTP Trap Active on Port 80...")
    HTTPServer(('0.0.0.0', 80), PhishingHandler).serve_forever()
