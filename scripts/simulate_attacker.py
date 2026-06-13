#!/usr/bin/env python3
"""
PhantomNet - Attacker Simulation Script
---------------------------------------
This script runs pure-Python simulated cyber attacks from your host machine
against the running PhantomNet Docker honeypots (localhost).

Features:
- Zero external dependencies (uses standard socket and urllib libraries).
- Simulates HTTP Port Scanning & SQL Injection exploits.
- Simulates SSH Connection Bruteforcing.
- Simulates FTP Credential Ingestion.
- Simulates SMTP Malware/Spam Campaign (EICAR string).
"""

import socket
import time
import urllib.request
import urllib.parse
import sys

# Targets
HOST = "127.0.0.1"
HTTP_PORT = 8080
SSH_PORT = 2222
FTP_PORT = 2121
SMTP_PORT = 2525

def print_header(title):
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

def simulate_http_attacks():
    print_header("Stage 1: Web Reconnaissance & SQL Injection (HTTP)")
    
    # 1. Directory scanning
    paths = ["/config.php.bak", "/database.sql", "/backup.zip"]
    print(f"[*] Scanning HTTP directories on port {HTTP_PORT}...")
    for path in paths:
        url = f"http://{HOST}:{HTTP_PORT}{path}"
        try:
            print(f"    -> GET {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "PhantomScan/1.0"})
            with urllib.request.urlopen(req, timeout=2) as response:
                response.read()
        except Exception as e:
            # We expect 404s; the honeypot logs them
            pass
        time.sleep(0.5)

    # 2. SQL Injection attempt
    admin_url = f"http://{HOST}:{HTTP_PORT}/admin"
    print(f"\n[*] Executing SQL Injection (SQLi) payload against {admin_url}...")
    post_data = urllib.parse.urlencode({
        "username": "admin' or '1'='1",
        "password": "password123"
    }).encode("utf-8")
    
    try:
        req = urllib.request.Request(
            admin_url, 
            data=post_data, 
            headers={"User-Agent": "SQLMap/1.5-stable"}
        )
        with urllib.request.urlopen(req, timeout=2) as response:
            html = response.read().decode("utf-8")
            print("    <- Server Response Code: 200 OK")
    except urllib.error.HTTPError as e:
        print(f"    <- Server Response Code: {e.code} (Honeypot successfully trapped/blocked request)")
    except Exception as e:
        print(f"    [-] Connection failed: {e}")

def simulate_ssh_bruteforce():
    print_header("Stage 2: SSH Connection Bruteforcing (Port 2222)")
    print(f"[*] Sending simulated SSH authentication connections to {HOST}:{SSH_PORT}...")
    
    users = ["root", "admin", "support"]
    for user in users:
        try:
            print(f"    -> Simulating SSH connection request for user: '{user}'...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((HOST, SSH_PORT))
            
            # Read server banner
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            print(f"       <- Received SSH Banner: {banner}")
            
            # Send client banner to simulate SSH connection handshake
            sock.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
            
            sock.close()
        except Exception as e:
            print(f"       [-] SSH simulation attempt failed: {e}")
        time.sleep(0.5)

def simulate_ftp_bruteforce():
    print_header("Stage 3: FTP Login & Exploit Attempt (Port 2121)")
    print(f"[*] Simulating FTP credentials harvest on {HOST}:{FTP_PORT}...")
    
    credentials = [("admin", "admin123"), ("anonymous", "guest@target.org")]
    for user, password in credentials:
        try:
            print(f"    -> Logging into FTP as {user}:{password}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((HOST, FTP_PORT))
            
            # Welcome banner
            sock.recv(1024)
            
            # Send USER
            sock.sendall(f"USER {user}\r\n".encode())
            sock.recv(1024)
            
            # Send PASS
            sock.sendall(f"PASS {password}\r\n".encode())
            sock.recv(1024)
            
            # Quit connection
            sock.sendall(b"QUIT\r\n")
            sock.close()
            print("       <- Handshake Completed.")
        except Exception as e:
            print(f"       [-] FTP simulation attempt failed: {e}")
        time.sleep(0.5)

def simulate_smtp_malware():
    print_header("Stage 4: SMTP Malware Payload Delivery (Port 2525)")
    print(f"[*] Transmitting simulated APT malware headers to SMTP honeypot on {HOST}:{SMTP_PORT}...")
    
    # EICAR standard antivirus test string (mimics threat payload)
    eicar = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    smtp_commands = [
        b"HELO attacker.com\r\n",
        b"MAIL FROM:<apt@cyberthreat.org>\r\n",
        b"RCPT TO:<victim@phantomnet.local>\r\n",
        b"DATA\r\n",
        f"Subject: URGENT: Critical Security Warning\r\n\r\nSystem compromised. Payload included:\r\n{eicar}\r\n.\r\n".encode("utf-8"),
        b"QUIT\r\n"
    ]
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((HOST, SMTP_PORT))
        
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        print(f"    <- Server banner: {banner}")
        
        for cmd in smtp_commands:
            sock.sendall(cmd)
            resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            print(f"    -> {cmd.decode('utf-8').strip()}")
            print(f"    <- {resp}")
        sock.close()
    except Exception as e:
        print(f"    [-] SMTP simulation failed: {e}")

if __name__ == "__main__":
    print("""
    ======================================================
           PhantomNet Attack Simulation Framework
           -> Target: Live Docker Honeypot Containers
    ======================================================
    """)
    
    simulate_http_attacks()
    simulate_ssh_bruteforce()
    simulate_ftp_bruteforce()
    simulate_smtp_malware()
    
    print("\n" + "=" * 60)
    print(" [+] SIMULATION COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print("Open the PhantomNet Dashboard: http://localhost:3000")
    print("Check the threat metrics, recent logs, and ML alerts.")
    print("=" * 60 + "\n")
