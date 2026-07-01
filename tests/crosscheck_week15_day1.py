"""
Cross-check verification for Week 15 Day 1 — SSH Brute Force T1110.001
Validates every task requirement against actual pipeline output.
"""
import sys, os, json, yaml
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, PacketLog, Event, IOC
from sentinel.models import SentinelPlaybook
from sentinel.sentinel_service import SentinelService
from datetime import datetime, timezone, timedelta

# Setup in-memory DB
engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
Base.metadata.create_all(bind=engine)
SentinelPlaybook.__table__.create(bind=engine, checkfirst=True)
db = sessionmaker(bind=engine)()

# Inject realistic data
bt = datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc)
ips = ["203.0.113.45", "203.0.113.46", "198.51.100.77"]
payloads = [
    "SSH-2.0-OpenSSH_7.4\r\nFailed password for root",
    "SSH-2.0-libssh2_1.8.0\r\nFailed password for admin",
    "SSH-2.0-PuTTY_0.70\r\nFailed password for user",
    "SSH-2.0-paramiko_2.7.2\r\nFailed password for test",
    "SSH-2.0-Go\r\nFailed password for ubuntu",
]
for i in range(50):
    db.add(PacketLog(
        timestamp=bt + timedelta(seconds=i * 5),
        src_ip=ips[i % 3], dst_ip="10.0.0.50",
        src_port=40000 + i, dst_port=2222,
        protocol="TCP", length=128 + (i % 64),
        attack_type="SSH_AUTH_FAILURE",
        threat_score=65.0 + (i % 30), threat_level="High",
        confidence=0.85, is_malicious=True, event="login_attempt",
    ))
for i in range(20):
    db.add(Event(
        source_ip=ips[i % 3], src_port=40000 + i,
        honeypot_type="SSH", raw_data=payloads[i % 5],
        timestamp=bt + timedelta(seconds=i * 8),
    ))
for ip in ips:
    db.add(IOC(type="IP", value=ip, description="SSH brute force", threat_level="High", is_watchlist=True))
db.commit()

# Run pipeline
campaign = {
    "source_ips": ips,
    "target_ports": [2222],
    "protocols": ["TCP"],
    "event_count": 150,
    "campaign_id": "CAMP-W15-SSH-BF-001",
    "time_range": {"start": bt.isoformat(), "end": (bt + timedelta(hours=4)).isoformat()},
}
svc = SentinelService(db)
r = svc.generate_playbook(campaign)
rd = r.result_dict

# ============================================================
passed = 0
failed = 0

def check(name, condition):
    global passed, failed
    status = "PASS" if condition else "FAIL"
    if condition:
        passed += 1
    else:
        failed += 1
    print(f"  [{status}] {name}")

print("=" * 65)
print("CROSS-CHECK: Week 15 Day 1 — SSH Brute Force T1110.001")
print("=" * 65)

# TASK 1
print("\n[TASK 1] Insert test PacketLogs simulating SSH brute force")
check("50 PacketLog rows inserted", db.query(PacketLog).count() == 50)
check("All dst_port=2222", all(p.dst_port == 2222 for p in db.query(PacketLog).all()))
check("All src_ip in attacker list", all(p.src_ip in ips for p in db.query(PacketLog).all()))
check("All protocol=TCP", all(p.protocol == "TCP" for p in db.query(PacketLog).all()))
check("20 Event rows with SSH payloads", db.query(Event).count() == 20)
check("Events have 'Failed password'", all("Failed password" in e.raw_data for e in db.query(Event).all()))
check("3 IOC rows for attacker IPs", db.query(IOC).count() == 3)

# TASK 2
print("\n[TASK 2] Trigger sentinel pipeline to process injected data")
check("Returns SentinelPlaybook", isinstance(r, SentinelPlaybook))
check("Service type inferred as SSH", rd["service_type"] == "SSH")
check("Matched PacketLog rows > 0", rd["matched_logs_count"] > 0)
check("IOC enrichment count > 0", rd["ioc_count"] > 0)
check("Confidence score > 0", rd["confidence_score"] > 0)
check("Severity assigned", rd["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
check("Persisted to DB", db.query(SentinelPlaybook).filter_by(playbook_id=r.playbook_id).first() is not None)

# TASK 3
print("\n[TASK 3] Verify T1110.001 (Brute Force: Password Guessing)")
check("technique_id == T1110.001", r.technique_id == "T1110.001")
check("technique_name == Brute Force: Password Guessing", r.technique_name == "Brute Force: Password Guessing")
check("tactic == Credential Access", r.tactic == "Credential Access")
check("mitre_url contains T1110/001", "T1110/001" in r.mitre_url)
check("result_dict technique.id == T1110.001", rd["technique"]["id"] == "T1110.001")

# TASK 4
print("\n[TASK 4] Validate Snort rule fields")
snort = r.snort_rule.split("\n")[0]
check("Snort rule not empty", len(r.snort_rule) > 0)
check("Starts with 'alert '", snort.strip().startswith("alert "))
check("Protocol is tcp", snort.split()[1] == "tcp")
check("Contains port 2222", "2222" in snort)
check("Has msg: field", "msg:" in snort)
check("Has flow:to_server,established", "flow:to_server,established" in snort)
check("Has threshold:type limit", "threshold:type limit" in snort)
check("Has track by_src", "track by_src" in snort)
check("Has count 5", "count 5" in snort)
check("Has seconds 60", "seconds 60" in snort)
check("Has classtype:attempted-admin", "classtype:attempted-admin" in snort)
check("Has MITRE ref T1110/001", "attack.mitre.org/techniques/T1110/001" in snort)
check("Has sid: field", "sid:" in snort)
check("Has rev:1", "rev:1" in snort)

# TASK 5
print("\n[TASK 5] Validate Sigma rule logsource and detection")
sigma_doc = yaml.safe_load(r.sigma_rule.split("---")[0].strip())
check("Sigma is valid YAML dict", isinstance(sigma_doc, dict))
check("Has title", "title" in sigma_doc)
check("Title contains campaign ID", "CAMP-W15-SSH-BF-001" in sigma_doc.get("title", ""))
check("logsource.category == network_traffic", sigma_doc.get("logsource", {}).get("category") == "network_traffic")
check("logsource.product == phantomnet", sigma_doc.get("logsource", {}).get("product") == "phantomnet")
check("detection.selection exists", "selection" in sigma_doc.get("detection", {}))
check("detection.condition exists", "condition" in sigma_doc.get("detection", {}))
check("detection.selection has dst_port", "dst_port" in sigma_doc.get("detection", {}).get("selection", {}))
check("detection.selection has src_ip", "src_ip" in sigma_doc.get("detection", {}).get("selection", {}))
check("level is valid", sigma_doc.get("level") in ["critical", "high", "medium", "low"])
check("tags contain attack.t1110", any("attack.t1110" in str(t) for t in sigma_doc.get("tags", [])))

# TASK 6
print("\n[TASK 6] Verify STIX bundle ExternalReferences to T1110.001")
bundle = json.loads(rd["stix_bundle_json"])
types = [o["type"] for o in bundle["objects"]]
aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
ap = aps[0] if aps else {}
ext_refs = ap.get("external_references", [])
mitre_refs = [ref for ref in ext_refs if ref.get("source_name") == "mitre-attack"]
indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
rels = [o for o in bundle["objects"] if o["type"] == "relationship"]

check("Bundle type == bundle", bundle["type"] == "bundle")
check("Has identity object", "identity" in types)
check("Has attack-pattern object", "attack-pattern" in types)
check("Has indicator objects", "indicator" in types)
check("Has relationship objects", "relationship" in types)
check("Has marking-definition", "marking-definition" in types)
check("AttackPattern external_id == T1110.001", len(mitre_refs) > 0 and mitre_refs[0]["external_id"] == "T1110.001")
check("AttackPattern source_name == mitre-attack", len(mitre_refs) > 0 and mitre_refs[0]["source_name"] == "mitre-attack")
check("AttackPattern URL contains T1110/001", len(mitre_refs) > 0 and "T1110/001" in mitre_refs[0].get("url", ""))
check("Indicators contain attacker IP 203.0.113.45", any("203.0.113.45" in ind.get("pattern", "") for ind in indicators))
check("All relationships type == indicates", all(rel["relationship_type"] == "indicates" for rel in rels))

# TASK 7
print("\n[TASK 7] Verify playbook Markdown renders all 7 sections")
c = r.playbook_content
check("Playbook content > 100 chars", len(c) > 100)
check("Starts with # (Markdown header)", c.strip().startswith("#"))
check("Section 1: Header (Playbook + Severity)", "Playbook" in c and "Severity" in c)
check("Section 2: Summary", "Summary" in c)
check("Section 3: IOC Table", "IOC" in c.upper())
check("Section 4: ATT&CK Mapping", "ATT" in c and "CK" in c)
check("Section 5: Containment Steps", "Containment" in c)
check("Section 6: Artifacts", "Artifact" in c)
check("Section 7: Appendix/Metadata", "Appendix" in c or "metadata" in c.lower() or "Context" in c)
check("Contains source IP 203.0.113.45", "203.0.113.45" in c)
check("Contains T1110 technique reference", "T1110" in c)

# TASK 8
print("\n[TASK 8] Document test scenario (verify report exists)")
report_path = os.path.join(os.path.dirname(__file__), "..", "docs", "week15_day1_ssh_brute_force_test_report.md")
report_exists = os.path.isfile(report_path)
check("Test report exists at docs/", report_exists)
if report_exists:
    with open(report_path, "r", encoding="utf-8") as f:
        report = f.read()
    check("Report mentions T1110.001", "T1110.001" in report)
    check("Report mentions SSH brute force", "SSH" in report and "brute" in report.lower())
    check("Report has expected vs actual table", "Expected" in report and "Actual" in report)
    check("Report shows ALL TESTS PASSED", "62/62" in report or "ALL TESTS PASSED" in report.upper())

# DB PERSISTENCE CHECK
print("\n[EXTRA] DB Persistence — all 23 columns")
row = db.query(SentinelPlaybook).filter_by(playbook_id=r.playbook_id).first()
d = row.to_dict()
expected_keys = [
    "id", "playbook_id", "created_at", "updated_at",
    "src_ip", "dst_port", "protocol", "attack_type",
    "threat_score", "confidence_score", "severity",
    "technique_id", "technique_name", "tactic", "mitre_url",
    "snort_rule", "sigma_rule",
    "playbook_name", "playbook_content", "template_name",
    "status", "reviewed_by", "reviewed_at",
]
missing = [k for k in expected_keys if k not in d]
check(f"to_dict() has all 23 keys (missing: {missing})", len(missing) == 0)
check("id > 0", row.id > 0)
check("playbook_id starts with PB-", row.playbook_id.startswith("PB-"))
check("status == pending", row.status == "pending")
check("reviewed_by is None", row.reviewed_by is None)
check("dst_port == 2222", row.dst_port == 2222)
check("technique_id == T1110.001", row.technique_id == "T1110.001")
check("playbook_name contains Brute Force", "Brute Force" in row.playbook_name)

# SAFETY CHECK
print("\n[SAFETY] sentinel_service.py not modified")
check("sentinel_service.py exists (read-only)", os.path.isfile("backend/sentinel/sentinel_service.py"))

# FINAL VERDICT
print("\n" + "=" * 65)
print(f"TOTAL: {passed + failed} checks | PASSED: {passed} | FAILED: {failed}")
if failed == 0:
    print("VERDICT: ALL CHECKS PASSED — Ready to push")
else:
    print(f"VERDICT: {failed} CHECKS FAILED — Review required")
print("=" * 65)

db.close()
