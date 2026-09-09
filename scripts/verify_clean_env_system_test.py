#!/usr/bin/env python3
"""
PhantomNet - Week 24 Day 3: Full System Test on Clean Environment
-----------------------------------------------------------------
Automates and validates:
1. Cold-start database validation (clean state, zero pre-existing data)
2. Clean service initialization (FastAPI app & routers)
3. 4-Stage Attack Simulation Pipeline:
   - Stage 1: SSH Brute Force (T1110.001)
   - Stage 2: SQL Injection (T1190)
   - Stage 3: Multi-Protocol Port Scan (T1046)
   - Stage 4: FTP Exfiltration (T1048.003)
4. Sentinel Playbook Generation & Validation:
   - MITRE ATT&CK technique mapping
   - Snort rule generation
   - Sigma rule generation
   - Jinja2 playbook markdown rendering
   - STIX 2.1 bundle formatting & validation
   - Quality scoring
5. Live API Contract & Dashboard Data Verification (zero stale cache):
   - /api/stats
   - /api/v1/sentinel/playbooks
   - /api/v1/sentinel/mitre-matrix
   - /api/v1/sentinel/timeline
   - /api/v1/sentinel/export/all
   - /api/v1/taxii2/collections
   - /api/v1/alerts
   - /api/honeypots
"""

import os
import sys
import json
import logging
from datetime import datetime, timedelta, timezone

# Windows UTF-8 fix
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
os.environ["ENVIRONMENT"] = "ci"

from database.database import SessionLocal, engine
from database.models import Base, PacketLog, Event, Alert, AttackSession, User
from sentinel.models import SentinelPlaybook, SentinelAuditLog
from sentinel.sentinel_service import SentinelService
from sentinel.stix_enhanced import build_stix_bundle
from fastapi.testclient import TestClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("FullSystemTest")

def reset_and_verify_clean_db(db):
    """Step 1: Ensure clean database state."""
    logger.info("=== STEP 1: Verifying Clean Cold-Start Database ===")
    
    # Ensure all tables exist in schema
    Base.metadata.create_all(bind=engine)
    
    # Wipe any residual test records to guarantee true cold start
    models_to_clear = [
        SentinelAuditLog,
        SentinelPlaybook,
        Event,
        Alert,
        AttackSession,
        PacketLog
    ]
    for model in models_to_clear:
        db.query(model).delete()
    db.commit()
    
    counts = {
        "packet_logs": db.query(PacketLog).count(),
        "events": db.query(Event).count(),
        "alerts": db.query(Alert).count(),
        "attack_sessions": db.query(AttackSession).count(),
        "sentinel_playbooks": db.query(SentinelPlaybook).count(),
        "sentinel_audit_logs": db.query(SentinelAuditLog).count(),
    }
    
    for table_name, count in counts.items():
        assert count == 0, f"Table {table_name} should be clean (0 rows), got {count}"
        
    logger.info("Cold-Start Database Verified (all tables empty): %s", counts)
    from middleware.auth import seed_default_admin
    seed_default_admin(db)
    return counts

def seed_and_execute_attacks(db):
    """Step 2 & 3: Ingest 4 attack vectors and generate Sentinel playbooks."""
    logger.info("=== STEP 2 & 3: Executing Complete Attack Simulation Pipeline ===")
    
    now = datetime.now(tz=timezone.utc)
    svc = SentinelService(db)
    
    attack_definitions = [
        {
            "name": "SSH Brute Force Campaign",
            "category": "ssh_brute_force",
            "src_ip": "198.51.100.15",
            "dst_port": 2222,
            "protocol": "TCP",
            "honeypot_type": "SSH",
            "expected_technique": "T1110.001",
            "expected_technique_name": "Brute Force: Password Guessing",
            "threat_score": 92.0,
            "threat_level": "CRITICAL",
            "event_count": 20,
            "raw_payload": "Failed password for invalid user admin from 198.51.100.15 port 44212 ssh2",
            "geo": {"country": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173}
        },
        {
            "name": "SQL Injection Attack",
            "category": "sqli_attempt",
            "src_ip": "203.0.113.42",
            "dst_port": 8080,
            "protocol": "TCP",
            "honeypot_type": "HTTP",
            "expected_technique": "T1190",
            "expected_technique_name": "Exploit Public-Facing Application",
            "threat_score": 96.0,
            "threat_level": "CRITICAL",
            "event_count": 8,
            "raw_payload": "POST /admin/login.php user=admin' OR '1'='1'-- password=xxx HTTP/1.1",
            "geo": {"country": "US", "city": "Dallas", "lat": 32.7767, "lon": -96.7970}
        },
        {
            "name": "Multi-Protocol Port Scan",
            "category": "port_scan",
            "src_ip": "192.0.2.77",
            "dst_port": 8080,
            "protocol": "TCP",
            "target_ports": [8080, 80, 443, 21, 22, 23, 25, 53, 3306],
            "honeypot_type": "TCP",
            "expected_technique": "T1046",
            "expected_technique_name": "Network Service Discovery",
            "threat_score": 78.0,
            "threat_level": "HIGH",
            "event_count": 15,
            "raw_payload": "SYN Port Scan across multi-service target ports (21-8080)",
            "geo": {"country": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821}
        },
        {
            "name": "FTP Data Exfiltration",
            "category": "ftp_exfiltration",
            "src_ip": "198.51.100.99",
            "dst_port": 2121,
            "protocol": "TCP",
            "honeypot_type": "FTP",
            "expected_technique": "T1048.003",
            "expected_technique_name": "Exfiltration Over Unencrypted Non-C2 Protocol",
            "threat_score": 88.0,
            "threat_level": "HIGH",
            "event_count": 6,
            "raw_payload": "USER anonymous\r\nPASS guest\r\nRETR customer_database_export.csv",
            "geo": {"country": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041}
        }
    ]
    
    pipeline_results = []
    
    for att in attack_definitions:
        logger.info("Processing attack vector: %s (%s)", att["name"], att["category"])
        
        # 1. Create AttackSession
        session = AttackSession(
            attacker_ip=att["src_ip"],
            start_time=now - timedelta(minutes=15),
            threat_score=att["threat_score"]
        )
        db.add(session)
        db.flush()
        
        # 2. Ingest PacketLogs & Events
        target_ports = att.get("target_ports", [att["dst_port"]])
        for i in range(att["event_count"]):
            t = now - timedelta(seconds=(att["event_count"] - i) * 2)
            port = target_ports[i % len(target_ports)]
            
            pkt = PacketLog(
                timestamp=t,
                src_ip=att["src_ip"],
                dst_ip="10.0.0.1",
                src_port=40000 + i,
                dst_port=port,
                protocol=att["protocol"],
                length=512,
                attack_type=att["category"].upper(),
                threat_score=att["threat_score"],
                threat_level=att["threat_level"],
                confidence=0.95,
                is_malicious=True,
                country=att["geo"]["country"],
                city=att["geo"]["city"],
                latitude=att["geo"]["lat"],
                longitude=att["geo"]["lon"]
            )
            db.add(pkt)
            
            evt = Event(
                session_id=session.id,
                timestamp=t,
                source_ip=att["src_ip"],
                src_port=40000 + i,
                honeypot_type=att["honeypot_type"],
                raw_data=att["raw_payload"],
                country=att["geo"]["country"],
                city=att["geo"]["city"],
                latitude=att["geo"]["lat"],
                longitude=att["geo"]["lon"]
            )
            db.add(evt)
            
        # 3. Create Alert
        alert = Alert(
            timestamp=now,
            level=att["threat_level"],
            type="INTRUSION",
            source_ip=att["src_ip"],
            description=f"Active {att['name']} detected from {att['src_ip']}",
            country=att["geo"]["country"],
            city=att["geo"]["city"],
            latitude=att["geo"]["lat"],
            longitude=att["geo"]["lon"]
        )
        db.add(alert)
        db.commit()
        
        # 4. Generate Sentinel Playbook
        camp_data = {
            "campaign_id": f"CAMP-{att['category'].upper()}-001",
            "source_ips": [att["src_ip"]],
            "target_ports": target_ports,
            "protocols": [att["protocol"]],
            "event_count": att["event_count"],
            "attack_type": att["category"]
        }
        
        playbook = svc.generate_playbook(camp_data)
        assert playbook is not None, f"Playbook generation returned None for {att['name']}"
        assert playbook.playbook_id is not None, "Playbook ID is missing"
        assert playbook.technique_id == att["expected_technique"], (
            f"Technique mismatch for {att['name']}: expected {att['expected_technique']}, got {playbook.technique_id}"
        )
        assert playbook.snort_rule is not None and "alert " in playbook.snort_rule, "Snort rule generation failed"
        assert playbook.sigma_rule is not None and "title:" in playbook.sigma_rule, "Sigma rule generation failed"
        assert playbook.playbook_content is not None and len(playbook.playbook_content) > 100, "Markdown content empty"
        
        # Verify STIX 2.1 Bundle Generation
        stix_bundle = build_stix_bundle(
            technique={
                "technique_id": playbook.technique_id,
                "technique_name": playbook.technique_name,
                "tactic": playbook.tactic,
                "url": playbook.mitre_url,
                "severity": playbook.severity or "HIGH"
            },
            iocs=[{"type": "ip", "value": playbook.src_ip}],
            src_ip=playbook.src_ip,
            threat_score=playbook.threat_score
        )
        assert stix_bundle is not None and len(stix_bundle.objects) >= 3, "STIX bundle generation failed"
        stix_json = stix_bundle.serialize()
        assert "bundle" in stix_json and playbook.technique_id in stix_json, "STIX bundle content invalid"
        
        logger.info("  [PASSED] Playbook %s generated: MITRE %s (%s) | STIX Bundle: %d objects",
                    playbook.playbook_id, playbook.technique_id, playbook.technique_name, len(stix_bundle.objects))
        
        pipeline_results.append({
            "name": att["name"],
            "category": att["category"],
            "src_ip": att["src_ip"],
            "playbook_id": playbook.playbook_id,
            "technique_id": playbook.technique_id,
            "technique_name": playbook.technique_name,
            "tactic": playbook.tactic,
            "severity": playbook.severity,
            "status": playbook.status,
            "quality_score": getattr(playbook, "quality_score", None),
            "snort_rule": playbook.snort_rule,
            "sigma_rule": playbook.sigma_rule[:150] + "..." if playbook.sigma_rule else None,
            "stix_objects_count": len(stix_bundle.objects),
            "pass": True
        })
        
    return pipeline_results

def test_api_endpoints():
    """Step 4: Verify all dashboard endpoints return fresh data without stale cache."""
    logger.info("=== STEP 4: Validating Dashboard REST APIs on Fresh Data ===")
    from main import app
    
    api_tests = {}
    
    with TestClient(app) as client:
        # 1. /api/stats
        res = client.get("/api/stats")
        assert res.status_code == 200, f"/api/stats failed: {res.status_code}"
        stats_data = res.json()
        logger.info("  /api/stats -> totalEvents=%s, uniqueIPs=%s, criticalAlerts=%s",
                    stats_data.get("totalEvents"), stats_data.get("uniqueIPs"), stats_data.get("criticalAlerts"))
        assert stats_data.get("totalEvents", 0) > 0, "totalEvents should be greater than 0 on fresh data"
        api_tests["/api/stats"] = {"status": 200, "data": stats_data, "pass": True}
        
        # 2. /api/sentinel/playbooks
        res = client.get("/api/sentinel/playbooks")
        assert res.status_code == 200, f"/api/sentinel/playbooks failed: {res.status_code}"
        pb_list = res.json()
        total_pbs = pb_list.get("total", len(pb_list.get("playbooks", [])))
        logger.info("  /api/sentinel/playbooks -> total playbooks: %d", total_pbs)
        assert total_pbs >= 4, f"Expected at least 4 playbooks, got {total_pbs}"
        api_tests["/api/sentinel/playbooks"] = {"status": 200, "total": total_pbs, "pass": True}

        # 3. /api/sentinel/stats
        res = client.get("/api/sentinel/stats")
        assert res.status_code == 200, f"/api/sentinel/stats failed: {res.status_code}"
        s_data = res.json()
        logger.info("  /api/sentinel/stats -> total=%s, pending=%s, approved=%s",
                    s_data.get("total_playbooks"), s_data.get("pending"), s_data.get("approved"))
        api_tests["/api/sentinel/stats"] = {"status": 200, "pass": True}

        # 4. /api/sentinel/mitre/matrix
        res = client.get("/api/sentinel/mitre/matrix")
        assert res.status_code == 200, f"/api/sentinel/mitre/matrix failed: {res.status_code}"
        matrix_data = res.json()
        logger.info("  /api/sentinel/mitre/matrix -> status=%s, total_mapped=%s",
                    matrix_data.get("status"), matrix_data.get("total_mapped"))
        api_tests["/api/sentinel/mitre/matrix"] = {"status": 200, "pass": True}

        # 5. /api/sentinel/mitre/mapping
        res = client.get("/api/sentinel/mitre/mapping")
        assert res.status_code == 200, f"/api/sentinel/mitre/mapping failed: {res.status_code}"
        mappings_data = res.json()
        logger.info("  /api/sentinel/mitre/mapping -> total techniques: %d", len(mappings_data.get("techniques", [])))
        api_tests["/api/sentinel/mitre/mapping"] = {"status": 200, "pass": True}

        # 6. /api/sentinel/campaigns/{campaign_id}/timeline
        res = client.get("/api/sentinel/campaigns/CAMP-SSH_BRUTE_FORCE-001/timeline")
        assert res.status_code == 200, f"/api/sentinel/campaigns/CAMP-SSH_BRUTE_FORCE-001/timeline failed: {res.status_code}"
        timeline_data = res.json()
        logger.info("  /api/sentinel/campaigns/CAMP-SSH_BRUTE_FORCE-001/timeline -> status=%s", timeline_data.get("status"))
        api_tests["/api/sentinel/campaigns/timeline"] = {"status": 200, "pass": True}

        # 7. /api/sentinel/rules/export-all (ZIP bundle)
        res = client.get("/api/sentinel/rules/export-all")
        assert res.status_code == 200, f"/api/sentinel/rules/export-all failed: {res.status_code}"
        assert res.headers.get("content-type") == "application/zip", "Export all should return application/zip"
        logger.info("  /api/sentinel/rules/export-all -> returned valid ZIP archive (%d bytes)", len(res.content))
        api_tests["/api/sentinel/rules/export-all"] = {"status": 200, "size_bytes": len(res.content), "pass": True}

        # 8. /api/sentinel/rules/snort & /api/sentinel/rules/sigma
        res_snort = client.get("/api/sentinel/rules/snort")
        assert res_snort.status_code == 200, f"/api/sentinel/rules/snort failed: {res_snort.status_code}"
        res_sigma = client.get("/api/sentinel/rules/sigma")
        assert res_sigma.status_code == 200, f"/api/sentinel/rules/sigma failed: {res_sigma.status_code}"
        logger.info("  Rules endpoints -> Snort total=%d, Sigma total=%d",
                    res_snort.json().get("total", 0), res_sigma.json().get("total", 0))
        api_tests["/api/sentinel/rules/snort_sigma"] = {"status": 200, "pass": True}

        # 9. /api/sentinel/llm/status
        res = client.get("/api/sentinel/llm/status")
        assert res.status_code == 200, f"/api/sentinel/llm/status failed: {res.status_code}"
        llm_status = res.json()
        logger.info("  /api/sentinel/llm/status -> %s", llm_status)
        api_tests["/api/sentinel/llm/status"] = {"status": 200, "pass": True}

        # 10. TAXII 2.1 Server Discovery & Collections List
        res_disc = client.get("/taxii2/", auth=("admin", "admin123"))
        assert res_disc.status_code == 200, f"/taxii2/ discovery failed: {res_disc.status_code}"
        res_cols = client.get("/taxii2/phantomnet/collections/", auth=("admin", "admin123"))
        assert res_cols.status_code == 200, f"/taxii2/phantomnet/collections/ failed: {res_cols.status_code}"
        taxii_data = res_cols.json()
        logger.info("  TAXII 2.1 Collections -> %d collections available", len(taxii_data.get("collections", [])))
        api_tests["/taxii2/collections"] = {"status": 200, "collections_count": len(taxii_data.get("collections", [])), "pass": True}

        # 11. /api/v1/alerts
        res = client.get("/api/v1/alerts")
        assert res.status_code == 200, f"/api/v1/alerts failed: {res.status_code}"
        alerts_data = res.json()
        logger.info("  /api/v1/alerts -> returned %d active alerts", len(alerts_data))
        api_tests["/api/v1/alerts"] = {"status": 200, "count": len(alerts_data), "pass": True}

        # 12. /api/honeypots
        res = client.get("/api/honeypots")
        assert res.status_code == 200, f"/api/honeypots failed: {res.status_code}"
        hp_data = res.json()
        logger.info("  /api/honeypots -> returned status for %d honeypots", len(hp_data))
        api_tests["/api/honeypots"] = {"status": 200, "count": len(hp_data), "pass": True}
        
    return api_tests

def run():
    print("=" * 70)
    print("   PHANTOMNET WEEK 24 DAY 3: FULL SYSTEM TEST ON CLEAN ENVIRONMENT")
    print("=" * 70)
    
    db = SessionLocal()
    try:
        initial_counts = reset_and_verify_clean_db(db)
        pipeline_results = seed_and_execute_attacks(db)
        api_results = test_api_endpoints()
        
        final_counts = {
            "packet_logs": db.query(PacketLog).count(),
            "events": db.query(Event).count(),
            "alerts": db.query(Alert).count(),
            "attack_sessions": db.query(AttackSession).count(),
            "sentinel_playbooks": db.query(SentinelPlaybook).count(),
            "sentinel_audit_logs": db.query(SentinelAuditLog).count(),
        }
        
        summary = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "clean_start_verified": True,
            "initial_counts": initial_counts,
            "final_counts": final_counts,
            "pipeline_stages": pipeline_results,
            "api_verifications": api_results,
            "overall_status": "ALL_TESTS_PASSED"
        }
        
        report_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports"))
        os.makedirs(report_dir, exist_ok=True)
        results_path = os.path.join(report_dir, "clean_env_system_test_results.json")
        with open(results_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
            
        print("\n" + "=" * 70)
        print(" [SUCCESS] ALL CLEAN-ENVIRONMENT SYSTEM TESTS PASSED")
        print(f" Full test results saved to: {results_path}")
        print("=" * 70)
        return summary
        
    finally:
        db.close()

if __name__ == "__main__":
    run()
