import socket
import threading
import paramiko
import time
import os

# CONFIGURATION
# We use port 2222 locally because Port 22 is usually blocked on Windows
BIND_IP = '0.0.0.0'
BIND_PORT = 2222

# Generate a temporary Host Key (Simulating a real server)
HOST_KEY = paramiko.RSAKey.generate(2048)

class HoneypotServer(paramiko.ServerInterface):
    """
    This fake server interface intercepts login attempts.
    """
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """
        🔥 TRAP TRIGGERED: This runs whenever someone tries a password.
        """
        print(f"🚨 ATTACK DETECTED! IP: {self.client_ip} | User: {username} | Pass: {password}")
        
        # We removed the API logging for now to fix the crash
        # Always reject login (Frustrate the attacker)
        return paramiko.AUTH_FAILED

def handle_connection(client, addr):
    transport = paramiko.Transport(client)
    transport.add_server_key(HOST_KEY)
    
    server = HoneypotServer(addr[0])
    try:
        transport.start_server(server=server)
        
        # Keep connection open briefly to simulate handshake
        channel = transport.accept(20)
        if channel is None:
            # Client didn't ask for a shell, just disconnected
            return
        
        server.event.wait(10)
        channel.close()
        
    except Exception as e:
        print(f"⚠️  Connection Error: {e}")
    finally:
        transport.close()

def start_honeypot():
    print(f"🪤 SSH Honeypot Active on {BIND_IP}:{BIND_PORT}")
    print("   (Waiting for attackers...)")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((BIND_IP, BIND_PORT))
    sock.listen(100)
    
    while True:
        try:
            client, addr = sock.accept()
            print(f"🔌 Connection from: {addr[0]}")
            threading.Thread(target=handle_connection, args=(client, addr)).start()
        except Exception as e:
            print(f"❌ Server Error: {e}")

if __name__ == "__main__":
    start_honeypot()