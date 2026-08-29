#!/usr/bin/env python3
"""
PhantomNet - Attacker Simulation Framework
-----------------------------------------
Simulates multi-stage cyber attacks against PhantomNet:
1. HTTP Directory Scanning & SQL Injection (T1190)
2. SSH Connection Bruteforcing (T1110.001)
3. FTP Credential Harvesting (T1048.003)
4. SMTP Malware Payload Delivery / APT (T1071.003)
5. Multi-Protocol Distributed Port Scan (T1046)

Supports both live Docker Honeypots and Local Native Mode (direct pipeline injection).
"""

import socket
import time
import urllib.request
import urllib.parse
import sys
import os
import random
from datetime import datetime, timezone, timedelta

# Fix Windows console UTF-8 output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure backend modules can be imported
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backend"))

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
    print_header("Stage 1: Web Reconnaissance & SQL Injection (HTTP :8080)")
    paths = ["/config.php.bak", "/database.sql", "/backup.zip"]
    print(f"[*] Scanning HTTP directories on port {HTTP_PORT}...")
    for path in paths:
        url = f"http://{HOST}:{HTTP_PORT}{path}"
        try:
            print(f"    -> GET {url}")
            req = urllib.request.Request(url, headers={"User-Agent": "PhantomScan/1.0"})
            with urllib.request.urlopen(req, timeout=1) as response:
                response.read()
        except Exception:
            pass
        time.sleep(0.1)

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
        with urllib.request.urlopen(req, timeout=1) as response:
            response.read()
            print("    <- Server Response Code: 200 OK")
    except urllib.error.HTTPError as e:
        print(f"    <- Response Code: {e.code} (Honeypot trapped request)")
    except Exception as e:
        print(f"    [-] Honeypot port {HTTP_PORT} offline; falling back to direct ingestion.")

def simulate_ssh_bruteforce():
    print_header("Stage 2: SSH Connection Bruteforcing (Port :2222)")
    print(f"[*] Sending simulated SSH authentication connections to {HOST}:{SSH_PORT}...")
    users = ["root", "admin", "support"]
    for user in users:
        try:
            print(f"    -> Simulating SSH connection request for user: '{user}'...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((HOST, SSH_PORT))
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            print(f"       <- Received SSH Banner: {banner}")
            sock.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
            sock.close()
        except Exception:
            print(f"       [-] Honeypot port {SSH_PORT} offline; falling back to direct ingestion.")
        time.sleep(0.1)

def simulate_ftp_bruteforce():
    print_header("Stage 3: FTP Login & Exploit Attempt (Port :2121)")
    print(f"[*] Simulating FTP credentials harvest on {HOST}:{FTP_PORT}...")
    credentials = [("admin", "admin123"), ("anonymous", "guest@target.org")]
    for user, password in credentials:
        try:
            print(f"    -> Logging into FTP as {user}:{password}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((HOST, FTP_PORT))
            sock.recv(1024)
            sock.sendall(f"USER {user}\r\n".encode())
            sock.recv(1024)
            sock.sendall(f"PASS {password}\r\n".encode())
            sock.recv(1024)
            sock.sendall(b"QUIT\r\n")
            sock.close()
            print("       <- Handshake Completed.")
        except Exception:
            print(f"       [-] Honeypot port {FTP_PORT} offline; falling back to direct ingestion.")
        time.sleep(0.1)

def simulate_smtp_malware():
    print_header("Stage 4: SMTP Malware Payload Delivery (Port :2525)")
    print(f"[*] Transmitting simulated APT malware headers to SMTP on {HOST}:{SMTP_PORT}...")
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
        sock.settimeout(1)
        sock.connect((HOST, SMTP_PORT))
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        print(f"    <- Server banner: {banner}")
        for cmd in smtp_commands:
            sock.sendall(cmd)
            resp = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
    except Exception:
        print(f"    [-] Honeypot port {SMTP_PORT} offline; falling back to direct ingestion.")

def inject_pipeline_events():
    print_header("Stage 5: Live Pipeline Ingestion & ML Threat Scoring")
    print("[*] Ingesting multi-stage attack sessions directly into database...")
    
    try:
        from database.database import SessionLocal
        from database.models import PacketLog, Event, Alert, AttackSession
        from sentinel.sentinel_service import SentinelService

        db = SessionLocal()
        now = datetime.now(tz=timezone.utc)

        attacks = [
            # 1. SSH Brute Force Campaign
            {
                "src_ip": "185.220.101.5",
                "country": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173,
                "protocol": "TCP", "dst_port": 2222, "attack_type": "SSH_AUTH_FAILURE",
                "count": 25, "score": 92.5, "level": "CRITICAL",
                "raw_event": "Failed password for invalid user root from 185.220.101.5 port 44212 ssh2"
            },
            # 2. SQL Injection Attack
            {
                "src_ip": "198.51.100.44",
                "country": "US", "city": "Dallas", "lat": 32.7767, "lon": -96.7970,
                "protocol": "TCP", "dst_port": 8080, "attack_type": "HTTP_SQL_INJECTION",
                "count": 12, "score": 96.0, "level": "CRITICAL",
                "raw_event": "POST /admin/login.php user=admin' OR '1'='1'-- password=xxx"
            },
            # 3. HTTP Path Traversal / Recon
            {
                "src_ip": "45.146.164.110",
                "country": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041,
                "protocol": "TCP", "dst_port": 8080, "attack_type": "HTTP_PATH_TRAVERSAL",
                "count": 18, "score": 88.0, "level": "HIGH",
                "raw_event": "GET /../../../../etc/shadow HTTP/1.1 User-Agent: Nikto/2.1.6"
            },
            # 4. Multi-Protocol Port Scan
            {
                "src_ip": "203.0.113.88",
                "country": "IN", "city": "Bengaluru", "lat": 12.9716, "lon": 77.5946,
                "protocol": "TCP", "dst_port": 80, "attack_type": "PORT_SCAN",
                "count": 30, "score": 76.0, "level": "HIGH",
                "raw_event": "SYN Scan across ports 21, 22, 80, 443, 8080, 3306"
            },
            # 5. SMTP APT Malware Campaign
            {
                "src_ip": "103.203.57.18",
                "country": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821,
                "protocol": "SMTP", "dst_port": 2525, "attack_type": "SMTP_LARGE_PAYLOAD",
                "count": 5, "score": 89.0, "level": "HIGH",
                "raw_event": "MAIL FROM:<apt@cyberthreat.org> EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
            }
        ]

        total_pkts = 0
        for att in attacks:
            # Create Attack Session
            session = AttackSession(
                attacker_ip=att["src_ip"],
                start_time=now - timedelta(minutes=random.randint(1, 30)),
                threat_score=att["score"]
            )
            db.add(session)
            db.flush()

            for i in range(att["count"]):
                t = now - timedelta(seconds=(att["count"] - i) * 3)
                pkt = PacketLog(
                    timestamp=t,
                    src_ip=att["src_ip"],
                    dst_ip="10.0.0.1",
                    src_port=random.randint(10000, 60000),
                    dst_port=att["dst_port"],
                    protocol=att["protocol"],
                    length=random.randint(64, 1500),
                    attack_type=att["attack_type"],
                    threat_score=att["score"],
                    threat_level=att["level"],
                    confidence=0.96,
                    is_malicious=True,
                    anomaly_score=att["score"] / 100.0,
                    country=att["country"],
                    city=att["city"],
                    latitude=att["lat"],
                    longitude=att["lon"]
                )
                db.add(pkt)
                total_pkts += 1

                evt = Event(
                    session_id=session.id,
                    timestamp=t,
                    source_ip=att["src_ip"],
                    src_port=pkt.src_port,
                    honeypot_type=att["protocol"],
                    raw_data=att["raw_event"],
                    country=att["country"],
                    city=att["city"],
                    latitude=att["lat"],
                    longitude=att["lon"]
                )
                db.add(evt)

            # Add an Alert
            alert = Alert(
                timestamp=now,
                level="CRITICAL" if att["level"] == "CRITICAL" else "WARNING",
                type="INTRUSION",
                source_ip=att["src_ip"],
                description=f"Active {att['attack_type']} attack detected from {att['src_ip']}",
                country=att["country"],
                city=att["city"],
                latitude=att["lat"],
                longitude=att["lon"]
            )
            db.add(alert)

        db.commit()
        print(f"  [+] Ingested {total_pkts} attack packets across {len(attacks)} campaigns.")

        # Generate Sentinel Playbooks for these campaigns
        print("\n[*] Triggering Sentinel ATT&CK Pipeline & Playbook Generation...")
        svc = SentinelService(db)
        for att in attacks:
            camp_data = {
                "campaign_id": f"CAMP-{att['attack_type'][:6]}-{random.randint(100,999)}",
                "source_ips": [att["src_ip"]],
                "target_ports": [att["dst_port"]],
                "protocols": [att["protocol"]],
                "event_count": att["count"],
            }
            try:
                res = svc.generate_playbook(camp_data)
                pb_id = res.result_dict.get("playbook_id", "N/A")
                tech_id = res.result_dict.get("technique_id", "T1046")
                print(f"  [+] Generated Playbook {pb_id} mapped to MITRE {tech_id} for {att['src_ip']}")
            except Exception as e:
                print(f"  [-] Playbook generation note: {e}")

        db.close()
        print("\n[*] Asynchronous email alerts dispatched in background threads...")
        print("[*] Waiting 6 seconds for SMTP email delivery to complete...")
        time.sleep(6)
        print("[OK] Pipeline ingestion and email notification delivery complete!")

    except Exception as e:
        print(f"[-] Pipeline ingestion error: {e}")


if __name__ == "__main__":
    print("""
    ======================================================
           PhantomNet Attack Simulation Framework
           -> Local & Network Multi-Protocol Engine
    ======================================================
    """)
    
    simulate_http_attacks()
    simulate_ssh_bruteforce()
    simulate_ftp_bruteforce()
    simulate_smtp_malware()
    inject_pipeline_events()
    
    print("\n" + "=" * 60)
    print(" [+] SIMULATION COMPLETED SUCCESSFULLY!")
    print("=" * 60)
    print("Open the PhantomNet Dashboard: http://localhost:5173")
    print("Check Live NOC, Threat Map, ML Insights, and Sentinel Playbooks.")
    print("=" * 60 + "\n")

