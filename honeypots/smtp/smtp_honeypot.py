import socket
import sys
import os

# Add deception module to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../security-dev')))
from deception.adaptive_behavior import AdaptiveEngine

def start_honeypot(host='0.0.0.0', port=2525):
    engine = AdaptiveEngine(profile="Hardened")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f'SMTP Honeypot (Enhanced) listening on {port}...')
    
    while True:
        conn, addr = s.accept()
        print(f'SMTP Probe from {addr}')
        
        # Apply adaptive delay
        engine.apply_delay()
        
        banner = engine.get_spoofed_banner("SMTP")
        conn.send(f"220 {banner} ESMTP\r\n".encode())
        
        try:
            data = conn.recv(1024).strip().decode(errors='ignore')
            if data.startswith("HELO") or data.startswith("EHLO"):
                conn.send(b"250-OK\r\n250-AUTH LOGIN PLAIN\r\n250-SIZE 15728640\r\n250-8BITMIME\r\n250 STARTTLS\r\n")
            elif data.startswith("MAIL FROM"):
                conn.send(b"250 2.1.0 Ok\r\n")
            elif data.startswith("RCPT TO"):
                # Simulate relay denial or acceptance based on profile
                conn.send(b"554 5.7.1 Service unavailable; Client host blocked using zen.spamhaus.org\r\n")
            else:
                conn.send(b"500 5.5.1 Command unrecognized\r\n")
        except Exception:
            pass
            
        conn.close()

if __name__ == "__main__":
    start_honeypot()
