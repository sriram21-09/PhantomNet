from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import os

# Add deception module to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../security-dev')))
from deception.adaptive_behavior import AdaptiveEngine

engine = AdaptiveEngine(profile="Vulnerable")

class DeceptiveHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"HTTP Probe from: {self.client_address}")
        
        # Apply adaptive delay
        engine.apply_delay()
        
        if self.path in ['/admin', '/wp-admin', '/phpmyadmin']:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.send_header('Server', engine.get_spoofed_banner("HTTP"))
            self.send_header('X-Powered-By', 'PHP/7.4.3')
            self.end_headers()
            self.wfile.write(f"<html><body><h1>Admin Login</h1><form>User: <input><br>Pass: <input type='password'></form></body></html>".encode())
            return

        if self.path == '/files/':
            self.send_response(200)
            self.send_header('Server', engine.get_spoofed_banner("HTTP"))
            self.end_headers()
            self.wfile.write(b"Index of /files/<br><a href='backup.sql'>backup.sql</a><br><a href='config.php.bak'>config.php.bak</a>")
            return

        self.send_response(404)
        self.send_header('Server', engine.get_spoofed_banner("HTTP"))
        self.end_headers()
        self.wfile.write(b'404 Not Found')

def run(server_class=HTTPServer, handler_class=DeceptiveHTTPHandler, port=8080):
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    print(f'HTTP Honeypot (Enhanced) listening on {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()
