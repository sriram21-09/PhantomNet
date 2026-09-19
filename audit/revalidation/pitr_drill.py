import os
import sys
import subprocess
import time
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

def run_psql(sql_command: str):
    cmd = [
        "docker", "compose", "exec", "-T", "postgres",
        "psql", "-U", "postgres", "-d", "phantomnet", "-t", "-A", "-c", sql_command
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return proc.stdout.strip(), proc.stderr.strip(), proc.returncode

def test_pitr_drill():
    evidence = {
        "dimension": "GOV-02",
        "name": "Continuous Archiving & Point-in-Time Recovery (PITR)",
        "timestamp": datetime.utcnow().isoformat(),
        "steps": []
    }

    print("[+] Starting GOV-02 Point-in-Time Recovery (PITR) Drill...")

    # Step 1: Insert State 1
    s1_id = f"pitr_state_1_{int(time.time())}"
    run_psql(f"INSERT INTO packet_logs (event_id, src_ip, event, timestamp) VALUES ('{s1_id}', '198.51.100.111', 'STATE_1_BEFORE_CRASH', NOW());")
    t1_out, _, _ = run_psql("SELECT NOW();")
    print(f"[*] State 1 inserted. Timestamp T1 = {t1_out}")
    evidence["steps"].append({"step": "Insert State 1", "id": s1_id, "timestamp_t1": t1_out})

    time.sleep(3)

    # Step 2: Insert State 2
    s2_id = f"pitr_state_2_{int(time.time())}"
    run_psql(f"INSERT INTO packet_logs (event_id, src_ip, event, timestamp) VALUES ('{s2_id}', '198.51.100.222', 'STATE_2_AFTER_TARGET', NOW());")
    t2_out, _, _ = run_psql("SELECT NOW();")
    print(f"[*] State 2 inserted. Timestamp T2 = {t2_out}")
    evidence["steps"].append({"step": "Insert State 2", "id": s2_id, "timestamp_t2": t2_out})

    # Step 3: Force WAL Switch
    wal_out, wal_err, _ = run_psql("SELECT pg_switch_wal();")
    print(f"[*] Forced WAL switch: {wal_out}")
    evidence["steps"].append({"step": "Force WAL switch", "wal_file": wal_out})

    # Step 4: Check WAL archive directory in postgres container
    ls_cmd = ["docker", "compose", "exec", "-T", "postgres", "ls", "-la", "/var/lib/postgresql/archive"]
    ls_proc = subprocess.run(ls_cmd, capture_output=True, text=True, timeout=10)
    archive_files = ls_proc.stdout.strip()
    print(f"[*] Archive directory contents:\n{archive_files}")
    evidence["archive_directory_contents"] = archive_files

    # Step 5: Check if dr_pitr_restore.sh can be executed
    # In a true disaster recovery test, we check if automated recovery script exists and executes
    script_path = ROOT / "scripts" / "dr_pitr_restore.sh"
    has_script = script_path.exists()
    evidence["restore_script_exists"] = has_script

    # Step 6: Verify State 1 and State 2 currently exist in DB
    cnt_s1, _, _ = run_psql(f"SELECT COUNT(*) FROM packet_logs WHERE event_id = '{s1_id}';")
    cnt_s2, _, _ = run_psql(f"SELECT COUNT(*) FROM packet_logs WHERE event_id = '{s2_id}';")
    evidence["current_database_state"] = {
        "state_1_count": cnt_s1,
        "state_2_count": cnt_s2
    }

    # PITR Evaluation:
    # Does an automated PITR harness exist that restores to T1?
    # In docker-compose.yml, archive_mode is on and archive_command is configured.
    # However, automated end-to-end PITR restoration into an isolated container requires
    # orchestrating a separate postgres container with recovery.signal and restore_command.
    has_automated_drill = False
    evidence["automated_pitr_drill_supported"] = has_automated_drill
    evidence["status"] = "PARTIALLY_VERIFIED_ARCHIVING_OPERATIONAL" if "00000" in archive_files else "NOT_VERIFIED"

    with open(ROOT / "audit" / "revalidation" / "pitr_runtime_evidence.json", "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    print("[+] PITR Drill Evidence Recorded.")

if __name__ == "__main__":
    test_pitr_drill()
