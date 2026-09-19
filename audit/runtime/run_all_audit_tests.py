"""
audit/runtime/run_all_audit_tests.py
------------------------------------
Executes all 39 test suites mapped to the 42 dimensions in PRODUCTION_READINESS_MATRIX.md.
Captures detailed test execution output, timings, and statuses into audit/logs/
and writes a consolidated summary JSON to audit/runtime/test_results.json.
"""
import subprocess
import sys
import os
import json
import time
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TESTS_TO_RUN = [
    # SEC-01 to SEC-11
    ("SEC-01", "tests/api/test_auth.py"),
    ("SEC-02", "tests/api/test_rbac.py"),
    ("SEC-03", "tests/api/test_websocket_auth.py"),
    ("SEC-04", "tests/api/test_active_defense.py"),
    ("SEC-05", "tests/api/test_origin_auth.py"),
    ("SEC-06", "tests/api/test_csrf.py"),
    ("SEC-07", "tests/api/test_token_lifecycle.py"),
    ("SEC-08", "tests/api/test_audit_ledger.py"),
    ("SEC-09", "tests/api/test_credential_redaction.py"),
    ("SEC-10", "tests/api/test_taxii.py"),
    ("SEC-11", "tests/ops/test_network_isolation.py"),
    # DUR-01 to DUR-07
    ("DUR-01", "tests/load_tests/test_sustained_500eps.py"),
    ("DUR-02", "tests/test_idempotent_ingest.py"),
    ("DUR-03", "tests/test_redis_durability.py"),
    ("DUR-04", "tests/test_event_consumer.py"),
    ("DUR-05", "tests/resilience/test_spool_drain.py"),
    ("DUR-06", "tests/test_catastrophic_loss.py"),
    ("DUR-07", "tests/resilience/test_component_chaos.py"),
    # GOV-01 to GOV-03
    ("GOV-01", "tests/test_alembic_migrations.py"),
    ("GOV-02", "tests/test_pitr_recovery.py"),
    ("GOV-03", "tests/test_retention.py"),
    # OBS-01 to OBS-04
    ("OBS-01", "tests/api/test_health_semantics.py"),
    ("OBS-02", "tests/resilience/test_degraded_mode.py"),
    ("OBS-03", "tests/api/test_health_semantics.py"),  # also covers Prometheus text
    ("OBS-04", "tests/test_latency_tracing.py"),
    # RT-01 to RT-03
    ("RT-01", "tests/api/test_realtime.py"),
    ("RT-02", "tests/test_ws_reconnect.py"),
    ("RT-03", "tests/api/test_ws_limits.py"),
    # PERF-01 to PERF-03
    ("PERF-01", "tests/load_tests/test_sustained_500eps.py"),
    ("PERF-02", "tests/load_tests/test_broadcast_slo.py"),
    ("PERF-03", "tests/load_tests/test_resource_saturation.py"),
    # ML-01 to ML-05
    ("ML-01", "tests/ml/test_walk_forward_benchmark.py"),
    ("ML-02", "tests/ml/test_walk_forward_benchmark.py"),
    ("ML-03", "tests/ml/test_adversarial.py"),
    ("ML-04", "tests/ml/test_shap_consistency.py"),
    ("ML-05", "tests/resilience/test_llm_isolation.py"),
    # OPS-01 to OPS-06
    ("OPS-01", "tests/ops/test_container_hardening.py"),
    ("OPS-02", "tests/ops/test_ci_security_gates.py"),
    ("OPS-03", "tests/ops/test_sbom_generation.py"),
    ("OPS-04", "tests/ops/test_backup_restore_e2e.py"),
    ("OPS-05", "tests/ops/test_secret_rotation.py"),
    ("OPS-06", "tests/ops/test_migration_rollback_e2e.py"),
]

PYTHON_EXE = ROOT_DIR / "backend" / "venv" / "Scripts" / "python.exe"
if not PYTHON_EXE.exists():
    PYTHON_EXE = "python"
else:
    PYTHON_EXE = str(PYTHON_EXE)

logs_dir = ROOT_DIR / "audit" / "logs"
logs_dir.mkdir(parents=True, exist_ok=True)

results = []

print(f"=== Starting Audit Test Suite Execution ({len(TESTS_TO_RUN)} tests) ===")
print(f"Python interpreter: {PYTHON_EXE}")

# Track unique test files already executed to avoid duplicate runs if identical
executed_files = {}

for dim_id, test_path in TESTS_TO_RUN:
    full_test_path = ROOT_DIR / test_path
    if not full_test_path.exists():
        print(f"[-] {dim_id} {test_path} NOT FOUND")
        results.append({
            "dimension": dim_id,
            "test_file": test_path,
            "status": "FILE_NOT_FOUND",
            "exit_code": -1,
            "duration_s": 0.0,
            "output_log": ""
        })
        continue

    log_filename = f"{dim_id}_{Path(test_path).stem}.log"
    log_path = logs_dir / log_filename

    # If already executed in this session, reuse result or re-run
    if test_path in executed_files:
        prior = executed_files[test_path]
        results.append({
            "dimension": dim_id,
            "test_file": test_path,
            "status": prior["status"],
            "exit_code": prior["exit_code"],
            "duration_s": prior["duration_s"],
            "output_log": prior["output_log"]
        })
        print(f"[REUSE] {dim_id} ({test_path}) -> {prior['status']}")
        continue

    start_time = time.time()
    cmd = [PYTHON_EXE, "-m", "pytest", str(full_test_path), "-v", "--tb=short"]
    
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(ROOT_DIR),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=180,
            encoding="utf-8",
            errors="replace"
        )
        duration = round(time.time() - start_time, 2)
        exit_code = proc.returncode
        status = "PASSED" if exit_code == 0 else "FAILED"
        output = proc.stdout
    except subprocess.TimeoutExpired as te:
        duration = round(time.time() - start_time, 2)
        exit_code = -9
        status = "TIMEOUT"
        output = (te.stdout or "") + "\n[AUDIT ERROR] Test timed out after 180 seconds."
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        exit_code = -1
        status = "ERROR"
        output = f"[AUDIT ERROR] Execution exception: {e}"

    with open(log_path, "w", encoding="utf-8") as f:
        f.write(output)

    res_entry = {
        "dimension": dim_id,
        "test_file": test_path,
        "status": status,
        "exit_code": exit_code,
        "duration_s": duration,
        "output_log": f"audit/logs/{log_filename}"
    }
    executed_files[test_path] = res_entry
    results.append(res_entry)
    print(f"[{status}] {dim_id}: {test_path} ({duration}s, exit code {exit_code})")

output_json = ROOT_DIR / "audit" / "runtime" / "test_results.json"
with open(output_json, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=2)

passed_count = sum(1 for r in results if r["status"] == "PASSED")
failed_count = sum(1 for r in results if r["status"] == "FAILED")
timeout_count = sum(1 for r in results if r["status"] == "TIMEOUT")
missing_count = sum(1 for r in results if r["status"] in ["FILE_NOT_FOUND", "ERROR"])

print(f"\n=== Audit Test Execution Complete ===")
print(f"Total: {len(results)} | Passed: {passed_count} | Failed: {failed_count} | Timeout: {timeout_count} | Missing/Error: {missing_count}")
