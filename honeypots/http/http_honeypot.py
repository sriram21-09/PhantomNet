from http.server import BaseHTTPRequestHandler, HTTPServer

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"Attack Detected from: {self.client_address}")
        self.send_response(404) # Fake 404
        self.end_headers()
        self.wfile.write(b'404 Not Found')

def run(server_class=HTTPServer, handler_class=SimpleHandler, port=8080):
    server_address = ('0.0.0.0', port)
    httpd = server_class(server_address, handler_class)
    print(f'HTTP Honeypot listening on {port}...')
    httpd.serve_forever()

if __name__ == "__main__":
    run()
