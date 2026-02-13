import socket
import datetime
import threading

# CONFIGURATION
BIND_IP = '0.0.0.0'
BIND_PORT = 5000

# The Fake Response (Standard HTTP 200 OK with HTML)
HTML_PAGE = """HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <title>Corporate Login</title>
    <style>
        body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; background: #f0f2f5; }
        .box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        input { display: block; width: 100%; margin: 10px 0; padding: 10px; }
        button { width: 100%; padding: 10px; background: #0056b3; color: white; border: none; cursor: pointer; }
    </style>
</head>
<body>
    <div class="box">
        <h2>🔒 Secure Employee Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
"""

def handle_client(client_socket, addr):
    try:
        # 1. Receive the Request
        request = client_socket.recv(1024).decode('utf-8', errors='ignore')
        
        # 2. Check if it's a POST (Login Attempt)
        if "POST" in request:
            # Simple parsing to grab the credentials from the raw body
            # Body usually looks like: username=admin&password=123
            body = request.split('\r\n\r\n')[-1]
            
            print(f"\n🚨 WEB ATTACK DETECTED!")
            print(f"   📅 Time: {datetime.datetime.now()}")
            print(f"   📍 IP:   {addr[0]}")
            print(f"   📦 Data: {body}")
            
            # Send a "Forbidden" error to frustrate them
            response = "HTTP/1.1 403 Forbidden\r\n\r\nAccount Locked."
            client_socket.send(response.encode())
        
        else:
            # 3. If it's just a GET (Viewing the page), show the login form
            client_socket.send(HTML_PAGE.encode())
            
    except Exception as e:
        print(f"⚠️ Error: {e}")
    finally:
        client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((BIND_IP, BIND_PORT))
    server.listen(5)
    
    print(f"🪤 HTTP Honeypot Active on Port {BIND_PORT}")
    print("   (Go to http://phantomnet_postgres:5000 to test)")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

if __name__ == "__main__":
    start_server()
