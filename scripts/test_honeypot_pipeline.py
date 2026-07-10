import os
import sys
import logging
import json
from datetime import datetime, timedelta, timezone

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from database.database import SessionLocal, engine
from database.models import Base, PacketLog, Event
from sentinel.sentinel_service import SentinelService
from sentinel.models import SentinelPlaybook

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("honeypot_test")

def setup_test_data(db):
    """Seed the database with realistic honeypot traffic data."""
    now = datetime.now(tz=timezone.utc)

    # 1. SSH Brute Force Data
    ssh_ip = "192.168.10.50"
    for i in range(15):
        pkt = PacketLog(
            timestamp=now - timedelta(minutes=5) + timedelta(seconds=i*2),
            src_ip=ssh_ip,
            dst_port=2222,
            protocol="TCP",
            threat_score=85.0
        )
        db.add(pkt)
        evt = Event(
            timestamp=now - timedelta(minutes=5) + timedelta(seconds=i*2),
            source_ip=ssh_ip,
            src_port=43521,
            honeypot_type="SSH",
            raw_data=f"Failed password for invalid user admin from {ssh_ip} port 43521 ssh2"
        )
        db.add(evt)

    # 2. HTTP SQL Injection Data
    http_ip = "10.0.5.101"
    for i in range(3):
        pkt = PacketLog(
            timestamp=now - timedelta(minutes=10) + timedelta(seconds=i*10),
            src_ip=http_ip,
            dst_port=8080,
            protocol="TCP",
            threat_score=95.0
        )
        db.add(pkt)
        evt = Event(
            timestamp=now - timedelta(minutes=10) + timedelta(seconds=i*10),
            source_ip=http_ip,
            src_port=52341,
            honeypot_type="HTTP",
            raw_data="GET /login?user=admin' OR 1=1-- HTTP/1.1\r\nHost: example.com\r\n"
        )
        db.add(evt)

    # 3. Port Scan Data
    scan_ip = "172.16.20.200"
    for port in [21, 22, 23, 25, 53, 80, 443, 8080, 3306]:
        pkt = PacketLog(
            timestamp=now - timedelta(minutes=15) + timedelta(seconds=port/1000.0),
            src_ip=scan_ip,
            dst_port=port,
            protocol="TCP",
            threat_score=60.0
        )
        db.add(pkt)

    db.commit()
    logger.info("Successfully seeded database with realistic test data.")
    return ssh_ip, http_ip, scan_ip

def run_pipeline_test():
    db = SessionLocal()
    
    # Ensure tables exist
    Base.metadata.create_all(bind=engine)
    
    # Seed data
    ssh_ip, http_ip, scan_ip = setup_test_data(db)
    
    svc = SentinelService(db)
    
    # Simulate clustering output
    campaigns = [
        {
            "campaign_id": "CAMP-SSH-BF-001",
            "source_ips": [ssh_ip],
            "target_ports": [2222],
            "protocols": ["TCP"],
            "event_count": 15,
            "attack_type": "ssh_brute_force"
        },
        {
            "campaign_id": "CAMP-HTTP-SQLI-001",
            "source_ips": [http_ip],
            "target_ports": [8080],
            "protocols": ["TCP"],
            "event_count": 3,
            "attack_type": "sqli_attempt"
        },
        {
            "campaign_id": "CAMP-PORT-SCAN-001",
            "source_ips": [scan_ip],
            "target_ports": [21, 22, 23, 25, 53, 80, 443, 8080, 3306],
            "protocols": ["TCP"],
            "event_count": 9,
            "attack_type": "port_scan"
        }
    ]

    results = []

    for camp in campaigns:
        logger.info(f"Running pipeline for campaign: {camp['campaign_id']}")
        playbook = svc.generate_playbook(camp)
        
        # Verify Playbook generated
        assert playbook is not None, f"Failed to generate playbook for {camp['campaign_id']}"
        assert playbook.playbook_id is not None
        assert playbook.src_ip == camp["source_ips"][0]
        
        # Verify Rules
        assert playbook.snort_rule is not None, f"Missing Snort rule for {camp['campaign_id']}"
        
        results.append({
            "campaign_id": camp["campaign_id"],
            "playbook_id": playbook.playbook_id,
            "playbook_name": playbook.playbook_name,
            "technique": f"{playbook.technique_id} - {playbook.technique_name}",
            "snort_rule": playbook.snort_rule,
            "sigma_rule": playbook.sigma_rule
        })

    # Save Results to JSON for the markdown report
    os.makedirs(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports")), exist_ok=True)
    report_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports", "pipeline_test_results.json"))
    with open(report_path, "w") as f:
        json.dump(results, f, indent=4)
        
    logger.info(f"Pipeline testing complete. Verified {len(results)} campaigns.")
    db.close()

if __name__ == "__main__":
    run_pipeline_test()
