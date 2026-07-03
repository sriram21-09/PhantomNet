"""
Day 5 — FULL CROSS-CHECK VERIFICATION
Validates every task requirement against the actual implementation.
"""
import sys
sys.path.insert(0, "backend")

passed = 0
failed = 0

def check(label, condition):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {label}")
    else:
        failed += 1
        print(f"  [FAIL] {label}")

# ── Setup ──────────────────────────────────────────────────────────────────
from database.database import engine
from database.models import Base, PacketLog, Event
from sentinel.models import SentinelPlaybook
Base.metadata.create_all(bind=engine)

from database.database import SessionLocal
from sentinel.sentinel_service import (
    SentinelService,
    _PORT_SERVICE_MAP,
    _SERVICE_DEFAULT_SIGNATURE,
    _generate_playbook_id,
)
from sentinel import mitre_mapper
from sentinel import rule_generator
from sentinel import stix_enhanced

db = SessionLocal()
svc = SentinelService(db)

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TASK 1: Create sentinel/sentinel_service.py with SentinelService")
print("=" * 60)

check("File exists and imports cleanly", SentinelService is not None)
check("SentinelService is a class", isinstance(SentinelService, type))
check("Constructor accepts db session", svc.db is db)
check("Has SignatureEngine instance", svc.sig_engine is not None)

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TASK 2: Implement generate_playbook(campaign_data) method")
print("=" * 60)

check("generate_playbook exists", hasattr(svc, "generate_playbook"))
check("generate_playbook is callable", callable(svc.generate_playbook))

# Full pipeline test
result_obj = svc.generate_playbook({
    "source_ips": ["10.0.0.50"],
    "target_ports": [2222],
    "protocols": ["TCP"],
    "event_count": 100,
    "campaign_id": "VERIFY-001",
})

check("Returns SentinelPlaybook", isinstance(result_obj, SentinelPlaybook))
result = result_obj.result_dict
check("Has playbook_id", "playbook_id" in result)
check("Has campaign_id", result["campaign_id"] == "VERIFY-001")
check("Has service_type", "service_type" in result)
check("Has attack_type", "attack_type" in result)
check("Has technique dict", isinstance(result.get("technique"), dict))
check("Has snort_rule", "snort_rule" in result)
check("Has sigma_rule", "sigma_rule" in result)
check("Has stix_bundle_json", "stix_bundle_json" in result)
check("Has playbook_content", "playbook_content" in result)
check("Has playbook_name", "playbook_name" in result)
check("Has threat_score", "threat_score" in result)
check("Has matched_logs_count", "matched_logs_count" in result)
check("Has signatures_stored_count", "signatures_stored_count" in result)
check("Has detected_signatures list", isinstance(result.get("detected_signatures"), list))
check("Has db_record_id", result.get("db_record_id", 0) > 0)

# Cleanup this record
row = db.query(SentinelPlaybook).filter_by(playbook_id=result["playbook_id"]).first()
if row:
    db.delete(row)
    db.commit()

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TASK 3: Infer protocol from target_ports")
print("=" * 60)

check("2222 -> SSH", svc._infer_service([2222]) == "SSH")
check("22   -> SSH", svc._infer_service([22]) == "SSH")
check("8080 -> HTTP", svc._infer_service([8080]) == "HTTP")
check("80   -> HTTP", svc._infer_service([80]) == "HTTP")
check("2121 -> FTP", svc._infer_service([2121]) == "FTP")
check("21   -> FTP", svc._infer_service([21]) == "FTP")
check("2525 -> SMTP", svc._infer_service([2525]) == "SMTP")
check("25   -> SMTP", svc._infer_service([25]) == "SMTP")
check("9999 -> UNKNOWN", svc._infer_service([9999]) == "UNKNOWN")
check("Multi-port picks first known", svc._infer_service([9999, 2121]) == "FTP")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TASK 4: Query PacketLog for matching IPs+timestamps")
print("=" * 60)

check("_query_packet_logs method exists", hasattr(svc, "_query_packet_logs"))
check("_query_packet_logs is callable", callable(svc._query_packet_logs))

# Query with no matching data should return empty list
logs = svc._query_packet_logs(["99.99.99.99"], [2222])
check("Returns list (even if empty)", isinstance(logs, list))

check("_avg_threat_score returns float", isinstance(svc._avg_threat_score([]), float))
check("Empty logs -> score 0.0", svc._avg_threat_score([]) == 0.0)

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TASK 5: Use inferred signature name to call mitre_mapper")
print("=" * 60)

# SSH pipeline
r_ssh_obj = svc.generate_playbook({
    "source_ips": ["10.0.0.1"], "target_ports": [2222],
    "protocols": ["TCP"], "event_count": 10, "campaign_id": "V-SSH",
})
r_ssh = r_ssh_obj.result_dict
check("SSH -> technique T1110.001", r_ssh["technique"]["id"] == "T1110.001")
check("SSH -> tactic Credential Access", r_ssh["technique"]["tactic"] == "Credential Access")
check("SSH -> attack_type SSH_AUTH_FAILURE", r_ssh["attack_type"] == "SSH_AUTH_FAILURE")

# HTTP pipeline
r_http_obj = svc.generate_playbook({
    "source_ips": ["10.0.0.2"], "target_ports": [8080],
    "protocols": ["TCP"], "event_count": 10, "campaign_id": "V-HTTP",
})
r_http = r_http_obj.result_dict
check("HTTP -> technique T1046", r_http["technique"]["id"] == "T1046")
check("HTTP -> attack_type HTTP_SCANNER_BEHAVIOR", r_http["attack_type"] == "HTTP_SCANNER_BEHAVIOR")

# FTP pipeline
r_ftp_obj = svc.generate_playbook({
    "source_ips": ["10.0.0.3"], "target_ports": [2121],
    "protocols": ["TCP"], "event_count": 10, "campaign_id": "V-FTP",
})
r_ftp = r_ftp_obj.result_dict
check("FTP -> technique T1048.003", r_ftp["technique"]["id"] == "T1048.003")
check("FTP -> attack_type FTP_DATA_EXFILTRATION", r_ftp["attack_type"] == "FTP_DATA_EXFILTRATION")

# SMTP pipeline
r_smtp_obj = svc.generate_playbook({
    "source_ips": ["10.0.0.4"], "target_ports": [2525],
    "protocols": ["TCP"], "event_count": 10, "campaign_id": "V-SMTP",
})
r_smtp = r_smtp_obj.result_dict
check("SMTP -> technique T1071.003", r_smtp["technique"]["id"] == "T1071.003")
check("SMTP -> attack_type SMTP_LARGE_PAYLOAD", r_smtp["attack_type"] == "SMTP_LARGE_PAYLOAD")

# Cleanup test records
for pid in [r_ssh["playbook_id"], r_http["playbook_id"], r_ftp["playbook_id"], r_smtp["playbook_id"]]:
    row = db.query(SentinelPlaybook).filter_by(playbook_id=pid).first()
    if row:
        db.delete(row)
db.commit()

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TASK 6: Store results in PacketLog.detected_signatures")
print("=" * 60)

check("_store_signatures method exists", hasattr(svc, "_store_signatures"))
check("_store_signatures is callable", callable(svc._store_signatures))
check("Empty inputs -> 0 updated", svc._store_signatures([], ["SSH_AUTH_FAILURE"]) == 0)
check("Empty sigs -> 0 updated", svc._store_signatures([PacketLog()], []) == 0)

# Verify PacketLog.detected_signatures column exists
from sqlalchemy import inspect
mapper = inspect(PacketLog)
col_names = [c.key for c in mapper.column_attrs]
check("PacketLog has detected_signatures column", "detected_signatures" in col_names)

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("CRITICAL CONSTRAINT: threat_analyzer.py NOT modified")
print("=" * 60)

import subprocess
diff = subprocess.run(
    ["git", "diff", "HEAD", "--", "backend/threat_analyzer.py"],
    capture_output=True, text=True, cwd=r"c:\Users\srira\Project\PhantomNet"
)
check("threat_analyzer.py has zero diff", diff.stdout.strip() == "")

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("WIRING CHECK: All 4 sub-modules integrated")
print("=" * 60)

import sys
module_name = svc.__class__.__module__
module_obj = sys.modules[module_name]
check("mitre_mapper imported (map_signature)", "map_signature" in dir(module_obj))
check("rule_generator used (snort_rule populated)", bool(r_ssh.get("snort_rule")))
check("rule_generator used (sigma_rule populated)", bool(r_ssh.get("sigma_rule")))
check("stix_enhanced used (stix_bundle_json)", bool(r_ssh.get("stix_bundle_json")))
check("playbook_gen integrated (lazy property)", hasattr(svc, "playbook_gen"))

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("DELIVERABLE CHECK: sentinel/sentinel_service.py")
print("=" * 60)

import os
filepath = os.path.join("backend", "sentinel", "sentinel_service.py")
check("File exists on disk", os.path.isfile(filepath))

file_size = os.path.getsize(filepath)
check(f"File size is substantial ({file_size} bytes)", file_size > 10000)

with open(filepath, "r", encoding="utf-8") as f:
    content = f.read()
check("Contains class SentinelService", "class SentinelService" in content)
check("Contains generate_playbook method", "def generate_playbook" in content)
check("Contains _infer_service method", "def _infer_service" in content)
check("Contains _query_packet_logs method", "def _query_packet_logs" in content)
check("Contains _store_signatures method", "def _store_signatures" in content)
check("Contains _run_signature_analysis", "def _run_signature_analysis" in content)
check("Imports mitre_mapper", "from sentinel.mitre_mapper" in content)
check("Imports rule_generator", "from sentinel.rule_generator" in content)
check("Imports stix_enhanced", "from sentinel.stix_enhanced" in content)
check("Imports PacketLog", "from database.models import PacketLog" in content)
check("Imports SignatureEngine", "from ml.signatures import SignatureEngine" in content)

db.close()

# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print(f"FINAL RESULTS: {passed} PASSED / {failed} FAILED / {passed + failed} TOTAL")
print("=" * 60)
if failed == 0:
    print("\n ALL DAY 5 TASKS VERIFIED — ZERO FAILURES!")
else:
    print(f"\n WARNING: {failed} check(s) failed!")

