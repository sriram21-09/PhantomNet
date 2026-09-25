"""
PhantomNet Honeypot Tester & Attack Simulator
Tests all 4 honeypot protocols using Python standard libraries (no external dependencies required).
"""
import socket
import urllib.request
import urllib.parse
import smtplib
import ftplib
import time

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def print_header(title):
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{CYAN}>>> {title}{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")

def test_http():
    print_header("1. Testing HTTP Honeypot (Port 8080)")
    
    # Test 1: Admin page view
    try:
        url = "http://localhost:8080/"
        print(f"[*] Requesting {url} ...")
        req = urllib.request.urlopen(url, timeout=5)
        html = req.read().decode('utf-8', errors='ignore')
        if "PhantomNet Admin" in html or req.status == 200:
            print(f"{GREEN}[+] HTTP Honeypot root portal accessible (Status: {req.status}){RESET}")
        else:
            print(f"{YELLOW}[!] HTTP response received (Status: {req.status}){RESET}")
    except Exception as e:
        print(f"{RED}[-] Failed to connect to HTTP honeypot: {e}{RESET}")

    # Test 2: SQL Injection Attack simulation
    try:
        url = "http://localhost:8080/admin"
        data = urllib.parse.urlencode({
            "username": "admin' OR '1'='1' --",
            "password": "password123"
        }).encode("utf-8")
        print(f"[*] Simulating SQL Injection against {url} ...")
        post_req = urllib.request.Request(url, data=data, method="POST")
        try:
            with urllib.request.urlopen(post_req, timeout=5) as resp:
                print(f"{GREEN}[+] SQL Injection payload delivered (Status: {resp.status}) - check Dashboard!{RESET}")
        except urllib.error.HTTPError as he:
            print(f"{GREEN}[+] Honeypot handled SQLi payload (Status: {he.code}) - check Dashboard!{RESET}")
    except Exception as e:
        print(f"{RED}[-] SQLi test failed: {e}{RESET}")

def test_ssh():
    print_header("2. Testing SSH Honeypot (Port 2722)")
    print("[*] Connecting to SSH honeypot at localhost:2722 ...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("localhost", 2722))
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        print(f"{GREEN}[+] SSH Banner received from honeypot: {banner}{RESET}")
        
        # Send fake SSH client handshake
        s.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
        time.sleep(0.5)
        s.close()
        print(f"{GREEN}[+] SSH handshake attempt recorded by honeypot!{RESET}")
    except Exception as e:
        print(f"{RED}[-] Failed to connect to SSH honeypot: {e}{RESET}")

def test_ftp():
    print_header("3. Testing FTP Honeypot (Port 2721)")
    print("[*] Connecting to FTP honeypot at localhost:2721 ...")
    try:
        ftp = ftplib.FTP()
        ftp.connect("localhost", 2721, timeout=5)
        banner = ftp.getwelcome()
        print(f"{GREEN}[+] FTP Banner received: {banner.strip()}{RESET}")
        
        # Attempt unauthorized login
        print("[*] Simulating unauthorized login attempt (user: anonymous) ...")
        try:
            ftp.login("anonymous", "guest@attacker.com")
            print(f"{GREEN}[+] Login recorded by honeypot!{RESET}")
        except ftplib.error_perm as fe:
            print(f"{GREEN}[+] Honeypot challenged login: {fe}{RESET}")
        ftp.quit()
    except Exception as e:
        print(f"{RED}[-] Failed to connect to FTP honeypot: {e}{RESET}")

def test_smtp():
    print_header("4. Testing SMTP Honeypot (Port 2725)")
    print("[*] Connecting to SMTP honeypot at localhost:2725 ...")
    try:
        smtp = smtplib.SMTP("localhost", 2725, timeout=5)
        print(f"{GREEN}[+] Connected to SMTP honeypot!{RESET}")
        
        # Send fake spam attempt
        print("[*] Sending test spam email payload (HELO attacker.local) ...")
        smtp.ehlo("attacker.local")
        smtp.mail("spammer@evil.org")
        smtp.rcpt("victim@target.internal")
        smtp.data("Subject: URGENT: Wire Transfer\r\n\r\nPlease send funds immediately.\r\n")
        smtp.quit()
        print(f"{GREEN}[+] Spam email payload trapped and logged by honeypot!{RESET}")
    except Exception as e:
        print(f"{RED}[-] Failed to connect to SMTP honeypot: {e}{RESET}")

if __name__ == "__main__":
    print(f"\n{YELLOW}{'='*60}")
    print("   PHANTOMNET HONEYPOT MULTI-PROTOCOL ATTACK SIMULATOR")
    print(f"{'='*60}{RESET}")
    test_http()
    test_ssh()
    test_ftp()
    test_smtp()
    print(f"\n{GREEN}{'='*60}")
    print("All tests completed! Check your PhantomNet Dashboard:")
    print("  -> http://localhost:3000")
    print(f"{'='*60}\n{RESET}")
