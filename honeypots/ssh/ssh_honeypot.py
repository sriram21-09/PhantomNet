import socket
import sys
import os

# Add deception module to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../security-dev')))
from deception.adaptive_behavior import AdaptiveEngine
from deception.credential_traps import CredentialTrapSystem

def start_honeypot(host='0.0.0.0', port=2222):
    engine = AdaptiveEngine(profile="Interactive")
    trap_system = CredentialTrapSystem()
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f'SSH Honeypot listening on {port}...')
    
    while True:
        conn, addr = s.accept()
        print(f'SSH Probe from {addr}')
        
        # Apply adaptive delay
        engine.apply_delay()
        
        banner = engine.get_spoofed_banner("SSH")
        conn.send(f"{banner}\r\n".encode())
        
        # Fake login prompt
        conn.send(b"login as: ")
        user = conn.recv(1024).strip().decode(errors='ignore')
        conn.send(f"{user}@password: ".encode())
        password = conn.recv(1024).strip().decode(errors='ignore')
        
        # Monitor for honeytokens
        trap_system.monitor_usage(user, password)
        
        # Fake Auth Delay & Failure
        engine.tarpit(1) # Simulate first attempt delay
        conn.send(b"Access denied\r\n")
        conn.close()

if __name__ == "__main__":
    start_honeypot()
