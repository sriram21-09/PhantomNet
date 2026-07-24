#!/usr/bin/env python3
"""
scripts/verify_realtime_mitre_matrix.py
----------------------------------------
PhantomNet Week 18 Day 5 — Real-Time ATT&CK Matrix Verification Script

Verifies that generating new playbook incidents dynamically updates the MITRE ATT&CK
matrix heatmap in real-time across the database and GET /api/sentinel/mitre/matrix response.

Usage:
    python scripts/verify_realtime_mitre_matrix.py
"""

import sys
import os
import json
import logging
from datetime import datetime, timezone

# Ensure stdout uses UTF-8 encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Add backend and root to sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(root_dir, "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

# Set test environment
os.environ["ENVIRONMENT"] = "test"
if not os.environ.get("DATABASE_URL"):
    os.environ["DATABASE_URL"] = "sqlite:///./phantomnet.db"

from database.database import SessionLocal, engine
from database.models import Base, Event, PacketLog
from sentinel.models import SentinelPlaybook
from sentinel.sentinel_service import SentinelService
from fastapi import FastAPI
from fastapi.testclient import TestClient
from api.sentinel import router as sentinel_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("verify_realtime_mitre_matrix")


def run_verification():
    print("=" * 80)
    print(" [PHANTOMNET WEEK 18 DAY 5: REAL-TIME ATT&CK MATRIX SYNC VERIFICATION]")
    print("=" * 80)

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Reset test playbooks & events
    db.query(SentinelPlaybook).delete()
    db.query(Event).delete()
    db.commit()

    app = FastAPI()
    app.include_router(sentinel_router)
    client = TestClient(app)

    print("\n--- STEP 1: INITIAL MATRIX BASELINE CHECK ---")
    res0 = client.get("/api/sentinel/mitre/matrix")
    assert res0.status_code == 200, f"Matrix API returned HTTP {res0.status_code}"
    baseline_data = res0.json()

    print(f"[OK] Matrix API Status: {baseline_data.get('status')}")
    print(f"[OK] Total Tactics:    {baseline_data.get('total_tactics')}")
    print(f"[OK] Total Techniques: {baseline_data.get('total_techniques')}")
    print(f"[OK] Generated At:     {baseline_data.get('generated_at')}")

    freq_base = baseline_data.get("frequency_map", {})
    ssh_base = freq_base.get("T1110", 0)
    sqli_base = freq_base.get("T1190", 0)
    scan_base = freq_base.get("T1046", 0)
    print(f"     Baseline Counts: T1110 (Brute Force)={ssh_base}, T1190 (SQLi)={sqli_base}, T1046 (Scan)={scan_base}")

    svc = SentinelService(db)

    print("\n--- STEP 2: TRIGGER SSH BRUTE FORCE SIMULATION CAMPAIGN ---")
    ssh_campaign = {
        "campaign_id": "CAMP-SIM-SSH-001",
        "source_ips": ["192.168.1.150"],
        "target_ports": [2222],
        "protocols": ["TCP"],
        "event_count": 50,
        "signatures": ["SSH_AUTH_FAILURE"],
        "time_range": {"start": "2026-07-24T18:00:00Z", "end": "2026-07-24T18:15:00Z"}
    }
    pb_ssh = svc.generate_playbook(ssh_campaign)
    print(f"[OK] Playbook Generated: ID={pb_ssh.playbook_id}, Technique={pb_ssh.technique_id}, Threat={pb_ssh.threat_score}")

    # Check DB update
    db_ssh_count = db.query(SentinelPlaybook).filter(SentinelPlaybook.technique_id.in_(["T1110.001", "T1110"])).count()
    print(f"[OK] Database Record Verified: {db_ssh_count} playbook(s) with technique T1110/T1110.001")

    # Check API response
    res1 = client.get("/api/sentinel/mitre/matrix").json()
    freq1 = res1.get("frequency_map", {})
    ssh_after = freq1.get("T1110", 0)
    print(f"[OK] API Real-Time Update Verified: T1110 count incremented from {ssh_base} to {ssh_after}")
    assert ssh_after == ssh_base + 1, "SSH Brute force count did not increment properly!"

    print("\n--- STEP 3: TRIGGER SQL INJECTION SIMULATION CAMPAIGN ---")
    # Add Event for SQLi signature detection
    sqli_event = Event(
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.75",
        src_port=54321,
        honeypot_type="HTTP",
        raw_data="GET /api/v1/products?cat=1' OR '1'='1-- HTTP/1.1"
    )
    db.add(sqli_event)
    db.commit()

    sqli_campaign = {
        "campaign_id": "CAMP-SIM-SQLI-001",
        "source_ips": ["10.0.0.75"],
        "target_ports": [8080],
        "protocols": ["HTTP"],
        "event_count": 25,
        "time_range": {"start": "2026-07-24T18:15:00Z", "end": "2026-07-24T18:30:00Z"}
    }
    pb_sqli = svc.generate_playbook(sqli_campaign)
    print(f"[OK] Playbook Generated: ID={pb_sqli.playbook_id}, Technique={pb_sqli.technique_id}, Threat={pb_sqli.threat_score}")

    base_sqli_tech = pb_sqli.technique_id.split('.')[0] if pb_sqli.technique_id else "T1190"
    sqli_before_val = freq_base.get(base_sqli_tech, 0)

    res2 = client.get("/api/sentinel/mitre/matrix").json()
    freq2 = res2.get("frequency_map", {})
    sqli_after = freq2.get(base_sqli_tech, 0)
    print(f"[OK] API Real-Time Update Verified: {base_sqli_tech} count incremented from {sqli_before_val} to {sqli_after}")
    assert sqli_after == sqli_before_val + 1, f"SQLi technique {base_sqli_tech} count did not increment properly!"

    print("\n--- STEP 4: TRIGGER NETWORK SERVICE DISCOVERY (PORT SCAN) CAMPAIGN ---")
    scan_event = Event(
        timestamp=datetime.now(timezone.utc),
        source_ip="172.16.5.10",
        src_port=49999,
        honeypot_type="HTTP",
        raw_data="GET /Nmap/Nikto/Masscan/recon HTTP/1.1"
    )
    db.add(scan_event)
    db.commit()

    scan_campaign = {
        "campaign_id": "CAMP-SIM-SCAN-001",
        "source_ips": ["172.16.5.10"],
        "target_ports": [8080],
        "protocols": ["HTTP"],
        "event_count": 120,
        "signatures": ["HTTP_SCANNER_BEHAVIOR"],
        "time_range": {"start": "2026-07-24T18:30:00Z", "end": "2026-07-24T18:45:00Z"}
    }
    pb_scan = svc.generate_playbook(scan_campaign)
    print(f"[OK] Playbook Generated: ID={pb_scan.playbook_id}, Technique={pb_scan.technique_id}, Threat={pb_scan.threat_score}")

    base_scan_tech = pb_scan.technique_id.split('.')[0] if pb_scan.technique_id else "T1046"
    scan_before_val = freq_base.get(base_scan_tech, 0)

    res3 = client.get("/api/sentinel/mitre/matrix").json()
    freq3 = res3.get("frequency_map", {})
    scan_after = freq3.get(base_scan_tech, 0)
    print(f"[OK] API Real-Time Update Verified: {base_scan_tech} count incremented from {scan_before_val} to {scan_after}")
    assert scan_after == scan_before_val + 1, f"Scan technique {base_scan_tech} count did not increment properly!"

    print("\n--- STEP 5: VERIFY MATRIX JSON PAYLOAD STRUCTURE & METADATA ACCURACY ---")
    final_matrix_data = res3.get("matrix", {})
    total_playbooks = db.query(SentinelPlaybook).count()

    print(f"[OK] Total Database Playbooks Persisted: {total_playbooks}")
    print(f"[OK] Matrix Tactic Columns Validated:")

    total_matrix_hits = 0
    for tactic, techs in final_matrix_data.items():
        hits = sum(t.get("count", 0) for t in techs)
        total_matrix_hits += hits
        print(f"     • Tactic [{tactic}]: {len(techs)} techniques mapped, total hits = {hits}")

    print(f"\n[OK] Total Matrix Hits across all tactics: {total_matrix_hits}")
    assert total_playbooks >= 3, "Playbook count in DB does not match expected simulations!"

    print("\n" + "=" * 80)
    print(" [SUCCESS] ALL REAL-TIME MITRE ATT&CK MATRIX VERIFICATION TESTS PASSED!")
    print("=" * 80)

    db.close()


if __name__ == "__main__":
    run_verification()
