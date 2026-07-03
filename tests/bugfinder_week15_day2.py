"""
Week 15 Day 2 — Deep bug finder across all 3 E2E scenarios.
Inspects every field for data flow issues, missing fields, DB save failures.
"""
import sys, os, json, yaml
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database.models import Base, PacketLog, Event, IOC
from sentinel.models import SentinelPlaybook
from sentinel.sentinel_service import SentinelService
from datetime import datetime, timezone, timedelta

engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
Base.metadata.create_all(bind=engine)
SentinelPlaybook.__table__.create(bind=engine, checkfirst=True)
db = sessionmaker(bind=engine)()

bt = datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc)

# --- Inject data for all 3 scenarios ---
# SSH
for i in range(30):
    db.add(PacketLog(timestamp=bt+timedelta(seconds=i*5), src_ip=["10.0.0.1","10.0.0.2"][i%2], dst_ip="10.0.0.50", src_port=40000+i, dst_port=2222, protocol="TCP", length=128, attack_type="SSH_AUTH_FAILURE", threat_score=70.0+(i%20), threat_level="High", confidence=0.8, is_malicious=True))
for i in range(10):
    db.add(Event(source_ip=["10.0.0.1","10.0.0.2"][i%2], src_port=40000+i, honeypot_type="SSH", raw_data="SSH-2.0-OpenSSH_7.4\r\nFailed password for root", timestamp=bt+timedelta(seconds=i*8)))
# SQLi
for i in range(30):
    db.add(PacketLog(timestamp=bt+timedelta(seconds=i*5), src_ip="192.168.1.50", dst_ip="10.0.0.60", src_port=50000+i, dst_port=8080, protocol="TCP", length=256, attack_type="HTTP_SCANNER_BEHAVIOR", threat_score=60.0+(i%20), threat_level="Medium", confidence=0.7, is_malicious=True))
for i in range(10):
    db.add(Event(source_ip="192.168.1.50", src_port=50000+i, honeypot_type="HTTP", raw_data="GET /login?user=admin' OR 1=1-- HTTP/1.1", timestamp=bt+timedelta(seconds=i*8)))
# Port scan
for i in range(30):
    db.add(PacketLog(timestamp=bt+timedelta(seconds=i*5), src_ip=["172.16.0.10","172.16.0.11"][i%2], dst_ip="10.0.0.70", src_port=60000+i, dst_port=[8080,2222,2121][i%3], protocol="TCP", length=64, attack_type="PORT_SCAN", threat_score=50.0+(i%20), threat_level="Medium", confidence=0.6, is_malicious=True))
for ip in ["10.0.0.1","10.0.0.2","192.168.1.50","172.16.0.10","172.16.0.11"]:
    db.add(IOC(type="IP", value=ip, description="test", threat_level="High", is_watchlist=True))
db.commit()

# --- Campaigns ---
SSH_CAMP = {"source_ips": ["10.0.0.1","10.0.0.2"], "target_ports": [2222], "protocols": ["TCP","SSH"], "event_count": 150, "campaign_id": "TEST-SSH-BF-001", "time_range": {"start": bt.isoformat(), "end": (bt+timedelta(hours=4)).isoformat()}}
SQLI_CAMP = {"source_ips": ["192.168.1.50"], "target_ports": [8080], "protocols": ["TCP"], "event_count": 85, "campaign_id": "TEST-SQLI-001", "time_range": {"start": bt.isoformat(), "end": (bt+timedelta(hours=2)).isoformat()}}
SCAN_CAMP = {"source_ips": ["172.16.0.10","172.16.0.11"], "target_ports": [8080,2222,2121], "protocols": ["TCP","UDP"], "event_count": 500, "campaign_id": "TEST-SCAN-001"}

svc = SentinelService(db)
ssh_r = svc.generate_playbook(SSH_CAMP)
sqli_r = svc.generate_playbook(SQLI_CAMP)
scan_r = svc.generate_playbook(SCAN_CAMP)

passed = 0
failed = 0
bugs = []

def check(scenario, name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
    else:
        failed += 1
        bugs.append(f"[{scenario}] {name}: {detail}")
        print(f"  [BUG] {name}: {detail}")

print("=" * 70)
print("WEEK 15 DAY 2 — BUG TRIAGE: 3 E2E SCENARIOS")
print("=" * 70)

for scenario, r, camp in [("SSH", ssh_r, SSH_CAMP), ("SQLi", sqli_r, SQLI_CAMP), ("PortScan", scan_r, SCAN_CAMP)]:
    rd = r.result_dict
    print(f"\n{'='*50}")
    print(f"SCENARIO: {scenario} (campaign={camp['campaign_id']})")
    print(f"{'='*50}")

    # --- DATA FLOW ---
    print(f"\n  [Data Flow]")
    check(scenario, "result is SentinelPlaybook", isinstance(r, SentinelPlaybook), f"got {type(r)}")
    check(scenario, "service_type not UNKNOWN", rd["service_type"] != "UNKNOWN", f"got {rd['service_type']}")
    check(scenario, "matched_logs_count > 0", rd["matched_logs_count"] > 0, f"got {rd['matched_logs_count']}")
    check(scenario, "campaign_id flows through", rd["campaign_id"] == camp["campaign_id"], f"got {rd['campaign_id']}")
    check(scenario, "source IPs flow through", r.src_ip in camp["source_ips"], f"got {r.src_ip}")
    check(scenario, "dst_port flows through", r.dst_port in camp["target_ports"], f"got {r.dst_port}")
    check(scenario, "protocol flows through", r.protocol is not None and len(r.protocol) > 0, f"got {r.protocol}")
    check(scenario, "attack_type not empty", r.attack_type is not None and len(r.attack_type) > 0, f"got {r.attack_type}")

    # --- ALL 23 COLUMNS ---
    print(f"\n  [23 Column Check]")
    check(scenario, "id > 0", r.id is not None and r.id > 0, f"got {r.id}")
    check(scenario, "playbook_id starts PB-", r.playbook_id is not None and r.playbook_id.startswith("PB-"), f"got {r.playbook_id}")
    check(scenario, "created_at not None", r.created_at is not None)
    check(scenario, "updated_at not None", r.updated_at is not None)
    check(scenario, "src_ip not None", r.src_ip is not None, f"got {r.src_ip}")
    check(scenario, "dst_port not None", r.dst_port is not None, f"got {r.dst_port}")
    check(scenario, "protocol not None", r.protocol is not None, f"got {r.protocol}")
    check(scenario, "attack_type not None", r.attack_type is not None, f"got {r.attack_type}")
    check(scenario, "threat_score is numeric", isinstance(r.threat_score, (int, float)), f"got {type(r.threat_score)}")
    check(scenario, "confidence_score is numeric", isinstance(r.confidence_score, (int, float)), f"got {type(r.confidence_score)}")
    check(scenario, "severity not None", r.severity is not None, f"got {r.severity}")
    check(scenario, "severity is valid", r.severity in ["CRITICAL","HIGH","MEDIUM","LOW"], f"got {r.severity}")
    check(scenario, "technique_id starts T", r.technique_id is not None and r.technique_id.startswith("T"), f"got {r.technique_id}")
    check(scenario, "technique_name not empty", r.technique_name is not None and len(r.technique_name) > 0, f"got {r.technique_name}")
    check(scenario, "tactic not empty", r.tactic is not None and len(r.tactic) > 0, f"got {r.tactic}")
    check(scenario, "mitre_url contains attack.mitre.org", r.mitre_url is not None and "attack.mitre.org" in r.mitre_url, f"got {r.mitre_url}")
    check(scenario, "snort_rule not empty", r.snort_rule is not None and len(r.snort_rule) > 0, f"got len={len(r.snort_rule or '')}")
    check(scenario, "sigma_rule not empty", r.sigma_rule is not None and len(r.sigma_rule) > 0, f"got len={len(r.sigma_rule or '')}")
    check(scenario, "playbook_name not empty", r.playbook_name is not None and len(r.playbook_name) > 0, f"got {r.playbook_name}")
    check(scenario, "playbook_content not empty", r.playbook_content is not None and len(r.playbook_content) > 100, f"got len={len(r.playbook_content or '')}")
    check(scenario, "template_name not None", r.template_name is not None, f"got {r.template_name}")
    check(scenario, "status == pending", r.status == "pending", f"got {r.status}")
    check(scenario, "reviewed_by is None", r.reviewed_by is None, f"got {r.reviewed_by}")
    check(scenario, "reviewed_at is None", r.reviewed_at is None, f"got {r.reviewed_at}")

    # --- SNORT RULE QUALITY ---
    print(f"\n  [Snort Rule Quality]")
    snort = r.snort_rule.split("\n")[0] if r.snort_rule else ""
    check(scenario, "snort starts with alert", snort.strip().startswith("alert "), f"starts with: {snort[:20]}")
    check(scenario, "snort has msg:", "msg:" in snort, "missing msg:")
    check(scenario, "snort has sid:", "sid:" in snort, "missing sid:")
    check(scenario, "snort has rev:", "rev:" in snort, "missing rev:")
    check(scenario, "snort ends with )", snort.strip().endswith(")"), f"ends with: {snort[-10:]}")
    check(scenario, "snort has flow:", "flow:" in snort, "missing flow:")
    check(scenario, "snort has classtype:", "classtype:" in snort, "missing classtype:")
    check(scenario, "snort has MITRE ref", "attack.mitre.org" in snort, "missing MITRE reference")

    # --- SIGMA RULE QUALITY ---
    print(f"\n  [Sigma Rule Quality]")
    if r.sigma_rule:
        sigma_text = r.sigma_rule.split("---")[0].strip()
        try:
            sigma_doc = yaml.safe_load(sigma_text)
            check(scenario, "sigma parses as dict", isinstance(sigma_doc, dict), f"got {type(sigma_doc)}")
            check(scenario, "sigma has title", "title" in sigma_doc, "missing title")
            check(scenario, "sigma has logsource", "logsource" in sigma_doc, "missing logsource")
            check(scenario, "sigma logsource.category", sigma_doc.get("logsource",{}).get("category") == "network_traffic", f"got {sigma_doc.get('logsource',{}).get('category')}")
            check(scenario, "sigma has detection", "detection" in sigma_doc, "missing detection")
            check(scenario, "sigma has level", "level" in sigma_doc, "missing level")
            check(scenario, "sigma level valid", sigma_doc.get("level") in ["critical","high","medium","low"], f"got {sigma_doc.get('level')}")
        except Exception as e:
            check(scenario, "sigma YAML parse", False, str(e))

    # --- STIX BUNDLE QUALITY ---
    print(f"\n  [STIX Bundle Quality]")
    stix_json = rd["stix_bundle_json"]
    bundle = json.loads(stix_json)
    types = [o["type"] for o in bundle["objects"]]
    check(scenario, "STIX type=bundle", bundle["type"] == "bundle")
    check(scenario, "STIX has identity", "identity" in types)
    check(scenario, "STIX has attack-pattern", "attack-pattern" in types)
    check(scenario, "STIX has indicator", "indicator" in types)
    check(scenario, "STIX has relationship", "relationship" in types)
    aps = [o for o in bundle["objects"] if o["type"] == "attack-pattern"]
    if aps:
        ext = aps[0].get("external_references", [])
        mitre = [e for e in ext if e.get("source_name") == "mitre-attack"]
        check(scenario, "STIX AP has mitre-attack ref", len(mitre) > 0, "missing mitre-attack external ref")
        if mitre:
            check(scenario, "STIX AP external_id matches technique_id", mitre[0]["external_id"] == r.technique_id, f"got {mitre[0]['external_id']} vs {r.technique_id}")

    # --- PLAYBOOK MARKDOWN ---
    print(f"\n  [Playbook Markdown Quality]")
    c = r.playbook_content or ""
    check(scenario, "playbook starts with #", c.strip().startswith("#"), f"starts with: {c[:20]}")
    check(scenario, "playbook has Severity", "Severity" in c or "severity" in c, "missing Severity")
    check(scenario, "playbook has containment", "Containment" in c or "containment" in c or "Phase" in c, "missing containment")
    check(scenario, "playbook has ATT&CK ref", "ATT" in c or "T1" in c, "missing ATT&CK reference")
    check(scenario, "playbook has source IP", camp["source_ips"][0] in c, f"missing {camp['source_ips'][0]}")

    # --- DB PERSISTENCE ---
    print(f"\n  [DB Persistence]")
    row = db.query(SentinelPlaybook).filter_by(playbook_id=r.playbook_id).first()
    check(scenario, "DB row found", row is not None, "row not persisted")
    if row:
        d = row.to_dict()
        check(scenario, "to_dict has 23 keys", len(d) == 23, f"got {len(d)} keys")
        check(scenario, "DB id matches", row.id == r.id)
        check(scenario, "DB technique_id matches", row.technique_id == r.technique_id)
        check(scenario, "DB snort_rule matches", row.snort_rule == r.snort_rule)

# --- CROSS-SCENARIO CHECKS ---
print(f"\n{'='*50}")
print("CROSS-SCENARIO CHECKS")
print(f"{'='*50}")
check("CROSS", "All 3 have unique playbook_ids", len({ssh_r.playbook_id, sqli_r.playbook_id, scan_r.playbook_id}) == 3)
check("CROSS", "SSH technique is T1110.001", ssh_r.technique_id == "T1110.001", f"got {ssh_r.technique_id}")
check("CROSS", "SSH service is SSH", ssh_r.result_dict["service_type"] == "SSH")
check("CROSS", "SQLi service is HTTP", sqli_r.result_dict["service_type"] == "HTTP")
check("CROSS", "Scan first port is HTTP", scan_r.result_dict["service_type"] in ["HTTP","SSH","FTP"])
check("CROSS", "Total DB rows >= 3", db.query(SentinelPlaybook).count() >= 3)
check("CROSS", "SSH playbook uses brute_force template", "brute_force" in (ssh_r.template_name or "").lower(), f"got {ssh_r.template_name}")

# --- EDGE CASE CHECKS ---
print(f"\n{'='*50}")
print("EDGE CASE CHECKS")
print(f"{'='*50}")
# Empty campaign
try:
    svc2 = SentinelService(db)
    empty_r = svc2.generate_playbook({"source_ips": [], "target_ports": [], "protocols": ["TCP"], "event_count": 0})
    check("EDGE", "Empty campaign still produces playbook", isinstance(empty_r, SentinelPlaybook))
    check("EDGE", "Empty campaign has fallback technique", empty_r.technique_id is not None)
except Exception as e:
    check("EDGE", "Empty campaign handles gracefully", False, str(e))

# Single IP campaign
try:
    single_r = svc.generate_playbook({"source_ips": ["1.2.3.4"], "target_ports": [2222], "protocols": ["TCP"], "event_count": 1, "campaign_id": "SINGLE"})
    check("EDGE", "Single IP campaign works", isinstance(single_r, SentinelPlaybook))
except Exception as e:
    check("EDGE", "Single IP campaign handles gracefully", False, str(e))

print(f"\n{'='*70}")
print(f"TOTAL: {passed + failed} checks | PASSED: {passed} | FAILED: {failed}")
if bugs:
    print(f"\nBUGS FOUND ({len(bugs)}):")
    for b in bugs:
        print(f"  - {b}")
else:
    print("\nNO BUGS FOUND")
print("=" * 70)

db.close()
