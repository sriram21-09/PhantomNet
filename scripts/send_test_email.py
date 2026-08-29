#!/usr/bin/env python3
"""
PhantomNet - Test Sentinel Email Alert Dispatcher
------------------------------------------------
Sends a live test security alert email to the configured recipients in .env.
"""

import sys
import os
from dotenv import load_dotenv

# Fix Windows console UTF-8 output
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "backend"))
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("email_test")

from sentinel.email_notifier import SentinelEmailNotifier
from database.models import PacketLog
from sentinel.models import SentinelPlaybook

def test_live_email():
    print("=" * 65)
    print(" 📧 PhantomNet Sentinel Email Alert Dispatcher Test")
    print("=" * 65)

    notifier = SentinelEmailNotifier()

    print(f"[*] Enabled:            {notifier.enabled}")
    print(f"[*] SMTP Host:          {notifier.smtp_host}:{notifier.smtp_port}")
    print(f"[*] Use STARTTLS:       {notifier.use_tls}")
    print(f"[*] SMTP Username:      {notifier.smtp_user or '(none)'}")
    print(f"[*] From Address:       {notifier.from_address}")
    print(f"[*] Recipients:         {notifier.recipients}")
    print(f"[*] Severity Threshold: {notifier.severity_threshold}")
    print("-" * 65)

    if not notifier.enabled:
        print("[!] ERROR: SENTINEL_EMAIL_ALERTS_ENABLED is set to 'false' in .env.")
        print("    Please set SENTINEL_EMAIL_ALERTS_ENABLED=true in your .env file.")
        return

    if not notifier.recipients:
        print("[!] ERROR: No recipients configured in SENTINEL_EMAIL_RECIPIENTS in .env.")
        return

    print("\n[*] Creating sample CRITICAL security playbook for testing...")
    # Mock Playbook object
    class MockPlaybook:
        id = 999
        playbook_id = "PB-TEST-LIVE-ALERT"
        playbook_name = "Automated SQL Injection & Credential Exfiltration Response"
        src_ip = "198.51.100.44"
        dst_port = 8080
        protocol = "TCP"
        attack_type = "HTTP_SQL_INJECTION"
        threat_score = 98.5
        confidence_score = 0.95
        severity = "CRITICAL"
        technique_id = "T1190"
        technique_name = "Exploit Public-Facing Application"
        tactic = "Initial Access"
        snort_rule = 'alert tcp 198.51.100.44 any -> $HOME_NET 8080 (msg:"PhantomNet SQLi Trapped"; sid:900001;)'
        sigma_rule = "title: SQL Injection Attempt\nstatus: high"
        status = "pending"
        created_at = "2026-08-29 10:25:00 UTC"
        mitre_url = "https://attack.mitre.org/techniques/T1190/"
        template_name = "sqli_attempt.md.j2"
        playbook_content = "# Incident Response Plan for SQL Injection"

    mock_pb = MockPlaybook()
    
    print("[*] Composing HTML & Plain-Text Security Alert Email...")
    context = notifier.build_email_context(mock_pb)
    msg = notifier.compose_email(context)

    print(f"[*] Connecting to SMTP server {notifier.smtp_host}:{notifier.smtp_port} and transmitting email...")
    success = notifier._send_smtp(msg)

    if success:
        print("\n" + "=" * 65)
        print(" [✅] SUCCESS: Email alert dispatched successfully!")
        print(f"      Check inbox for: {', '.join(notifier.recipients)}")
        print("=" * 65)
    else:
        print("\n" + "=" * 65)
        print(" [❌] FAILED: Could not send email via SMTP server.")
        print("      Check your SMTP server, port, username, or App Password.")
        print("=" * 65)

if __name__ == "__main__":
    test_live_email()
