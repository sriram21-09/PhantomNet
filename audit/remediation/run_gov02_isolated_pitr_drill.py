import subprocess
import time
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

def run_cmd(cmd, check=True):
    print(f"+ {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}):\nSTDOUT: {res.stdout}\nSTDERR: {res.stderr}")
    return res

def run_gov02_drill():
    print("=" * 60)
    print("PHANTOMNET V3 — GOV-02 ISOLATED POSTGRESQL PITR DRILL")
    print("=" * 60)

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "dimension": "GOV-02",
        "description": "Point-in-Time Recovery drill executed in fully isolated test container",
        "container_name": "phantomnet_pitr_isolated",
        "timeline": {},
        "measurements": {},
        "properties_verified": {}
    }

    CONTAINER = "phantomnet_pitr_isolated"
    VOL_DATA = "phantomnet_pitr_data_tmp"
    VOL_ARCHIVE = "phantomnet_pitr_archive_tmp"
    VOL_BACKUP = "phantomnet_pitr_backup_tmp"

    try:
        # Step 0: Clean up any leftover artifacts from prior runs
        print("\n--- Step 0: Environment Cleanup ---")
        run_cmd(["docker", "rm", "-f", CONTAINER], check=False)
        for v in [VOL_DATA, VOL_ARCHIVE, VOL_BACKUP]:
            run_cmd(["docker", "volume", "rm", "-f", v], check=False)

        # Create isolated volumes and ensure postgres user (UID 70) has write permissions
        for v in [VOL_DATA, VOL_ARCHIVE, VOL_BACKUP]:
            run_cmd(["docker", "volume", "create", v])

        run_cmd([
            "docker", "run", "--rm",
            "-v", f"{VOL_ARCHIVE}:/archive",
            "-v", f"{VOL_BACKUP}:/backups",
            "alpine", "sh", "-c", "chown -R 70:70 /archive /backups ; chmod -R 777 /archive /backups"
        ])

        # Step 1: Start Isolated PostgreSQL with Continuous WAL Archiving
        print("\n--- Step 1: Start Isolated PostgreSQL with WAL Archiving ---")
        start_cmd = [
            "docker", "run", "-d",
            "--name", CONTAINER,
            "-e", "POSTGRES_PASSWORD=postgres",
            "-e", "POSTGRES_DB=pitr_drill_db",
            "-v", f"{VOL_DATA}:/var/lib/postgresql/data",
            "-v", f"{VOL_ARCHIVE}:/archive",
            "-v", f"{VOL_BACKUP}:/backups",
            "postgres:15-alpine",
            "postgres",
            "-c", "wal_level=replica",
            "-c", "archive_mode=on",
            "-c", "archive_command=cp %p /archive/%f"
        ]
        run_cmd(start_cmd)

        # Wait for PostgreSQL to be ready (handle initial initdb startup/shutdown cycle)
        print("Waiting for PostgreSQL to be ready...")
        for _ in range(30):
            res = run_cmd(["docker", "exec", CONTAINER, "pg_isready", "-U", "postgres"], check=False)
            if res.returncode == 0:
                q_res = run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-c", "SELECT 1;"], check=False)
                if q_res.returncode == 0:
                    break
            time.sleep(2)
        else:
            raise RuntimeError("Isolated PostgreSQL failed to start!")
        print("PostgreSQL is ready and accepting queries.")

        # Step 2: Create Schema and Baseline Data
        print("\n--- Step 2: Insert Baseline Data (Rows 1 to 100) ---")
        init_sql = """
        CREATE TABLE pitr_events (
            id SERIAL PRIMARY KEY,
            event_code VARCHAR(50) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT clock_timestamp()
        );
        INSERT INTO pitr_events (event_code)
        SELECT 'BASELINE_' || i FROM generate_series(1, 100) AS i;
        """
        run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-c", init_sql])
        results["timeline"]["baseline_rows_inserted"] = 100

        # Step 3: Take Physical Base Backup
        print("\n--- Step 3: Take Base Backup ---")
        backup_start = time.time()
        run_cmd(["docker", "exec", CONTAINER, "pg_basebackup", "-U", "postgres", "-D", "/backups/base_backup", "-Fp", "-Xs", "-P"])
        backup_dur = time.time() - backup_start
        print(f"Base backup completed in {backup_dur:.2f}s")
        results["measurements"]["base_backup_duration_seconds"] = round(backup_dur, 2)

        # Step 4: WAL-Generating Writes Before Target Marker
        print("\n--- Step 4: WAL Writes Before Target Marker (Rows 101 to 200) ---")
        time.sleep(2)
        write_pre_target_sql = """
        INSERT INTO pitr_events (event_code)
        SELECT 'PRE_TARGET_' || i FROM generate_series(101, 200) AS i;
        """
        run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-c", write_pre_target_sql])

        # Record exact recovery target timestamp from PostgreSQL clock_timestamp()
        ts_res = run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-t", "-A", "-c", "SELECT clock_timestamp();"])
        target_timestamp = ts_res.stdout.strip()
        print(f"Recorded Recovery Target Timestamp Marker: {target_timestamp}")
        results["timeline"]["target_timestamp_marker"] = target_timestamp

        # Step 5: Post-Target Writes (Rows 201 to 300) - These MUST be rolled back / omitted after PITR!
        time.sleep(2)
        print("\n--- Step 5: Post-Target Writes (Rows 201 to 300) ---")
        write_post_target_sql = """
        INSERT INTO pitr_events (event_code)
        SELECT 'POST_TARGET_' || i FROM generate_series(201, 300) AS i;
        """
        run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-c", write_post_target_sql])

        # Step 6: Force WAL Switch to archive current WAL segment
        print("\n--- Step 6: Force WAL Switch ---")
        run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-c", "SELECT pg_switch_wal();"])
        time.sleep(2)

        # Check archived WAL count
        wal_res = run_cmd(["docker", "exec", CONTAINER, "sh", "-c", "ls -1 /archive | wc -l"])
        wal_count = int(wal_res.stdout.strip())
        print(f"Archived WAL segments in /archive: {wal_count}")
        results["measurements"]["archived_wal_segments"] = wal_count

        # Step 7: Stop Container and Perform Restoration to Target Timestamp
        print("\n--- Step 7: Stop Container and Restore Base Backup ---")
        restore_start = time.time()
        run_cmd(["docker", "stop", CONTAINER])

        # Use helper container to replace data directory with base backup and configure recovery
        restore_script = f"""
        rm -rf /data/*
        cp -a /backups/base_backup/* /data/
        touch /data/recovery.signal
        cat <<EOF >> /data/postgresql.auto.conf
restore_command = 'cp /archive/%f "%p"'
recovery_target_time = '{target_timestamp}'
recovery_target_action = 'promote'
EOF
        chown -R 70:70 /data
        chmod 700 /data
        """
        run_cmd([
            "docker", "run", "--rm",
            "-v", f"{VOL_DATA}:/data",
            "-v", f"{VOL_BACKUP}:/backups",
            "-v", f"{VOL_ARCHIVE}:/archive",
            "alpine", "sh", "-c", restore_script
        ])

        # Step 8: Start PostgreSQL and Measure RTO until promotion
        print("\n--- Step 8: Start PostgreSQL and Replay WAL to Target Marker ---")
        run_cmd(["docker", "start", CONTAINER])

        promoted = False
        for _ in range(60):
            check_ready = run_cmd(["docker", "exec", CONTAINER, "pg_isready", "-U", "postgres"], check=False)
            if check_ready.returncode == 0:
                # Check if recovery.signal is consumed (promotion complete)
                sig_check = run_cmd(["docker", "exec", CONTAINER, "sh", "-c", "[ -f /var/lib/postgresql/data/recovery.signal ] && echo 'exists' || echo 'promoted'"])
                if "promoted" in sig_check.stdout:
                    promoted = True
                    break
            time.sleep(1)

        rto_seconds = time.time() - restore_start
        print(f"Recovery and promotion completed in {rto_seconds:.2f}s (RTO)")
        results["measurements"]["rto_seconds"] = round(rto_seconds, 2)
        results["measurements"]["rpo_minutes"] = "< 1 minute (exact timestamp point-in-time recovery)"
        results["timeline"]["promoted_successfully"] = promoted

        # Step 9: Verify Row Counts and Data Equivalence
        print("\n--- Step 9: Verify Data Integrity at Recovery Target ---")
        count_res = run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-t", "-A", "-c", "SELECT count(*) FROM pitr_events;"])
        total_rows = int(count_res.stdout.strip())
        print(f"Total Rows Recovered: {total_rows} (Expected: 200)")

        pre_count_res = run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-t", "-A", "-c", "SELECT count(*) FROM pitr_events WHERE event_code LIKE 'PRE_TARGET_%';"])
        pre_count = int(pre_count_res.stdout.strip())
        print(f"Pre-Target Rows (101-200): {pre_count} (Expected: 100)")

        post_count_res = run_cmd(["docker", "exec", CONTAINER, "psql", "-U", "postgres", "-d", "pitr_drill_db", "-t", "-A", "-c", "SELECT count(*) FROM pitr_events WHERE event_code LIKE 'POST_TARGET_%';"])
        post_count = int(post_count_res.stdout.strip())
        print(f"Post-Target Rows (201-300): {post_count} (Expected: 0 - Must be omitted!)")

        results["measurements"]["total_rows_recovered"] = total_rows
        results["measurements"]["pre_target_rows_recovered"] = pre_count
        results["measurements"]["post_target_rows_recovered"] = post_count

        # Evaluate Properties
        p_backup = (backup_dur > 0)
        p_wal = (wal_count > 0)
        p_promoted = promoted
        p_pre_present = (pre_count == 100 and total_rows == 200)
        p_post_absent = (post_count == 0)

        results["properties_verified"] = {
            "base_backup_success": p_backup,
            "wal_archiving_success": p_wal,
            "recovery_promotion_success": p_promoted,
            "target_data_preserved": p_pre_present,
            "post_target_data_omitted": p_post_absent,
            "rto_under_5_minutes": (rto_seconds < 300)
        }

        all_passed = all(results["properties_verified"].values())
        results["overall_verdict"] = "VERIFIED" if all_passed else "NOT VERIFIED"

    finally:
        # Step 10: Clean up isolated drill container and temporary volumes
        print("\n--- Step 10: Clean up Isolated Drill Container ---")
        run_cmd(["docker", "rm", "-f", CONTAINER], check=False)
        for v in [VOL_DATA, VOL_ARCHIVE, VOL_BACKUP]:
            run_cmd(["docker", "volume", "rm", "-f", v], check=False)
        print("Isolated test container and temporary volumes cleaned up.")

    out_file = ROOT / "audit" / "remediation" / "gov02_pitr_drill_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nFinal Verdict for GOV-02: {results['overall_verdict']}")
    print(f"Saved evidence to {out_file}")

if __name__ == "__main__":
    run_gov02_drill()
