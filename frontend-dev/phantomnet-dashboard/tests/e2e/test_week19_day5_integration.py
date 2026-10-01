"""
PhantomNet Week 19 Day 5 - Integration Testing
==============================================
Validates:
1. Batch approve/reject workflows on dashboard.
2. Background scheduler generating playbooks and updating stats panel dynamically.
3. PDF download accuracy and error handling under concurrency.
"""
import os, sys, io, json, time, traceback, concurrent.futures
from datetime import datetime, timedelta
from pathlib import Path

# Fix Windows console encoding
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Ensure backend is importable
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

os.environ.setdefault("ENVIRONMENT", "test")

EXPORT_DIR = os.path.join(os.path.dirname(__file__), "exports")
os.makedirs(EXPORT_DIR, exist_ok=True)

from fastapi.testclient import TestClient

EVIDENCE: list[dict] = []
PASS_COUNT = 0
FAIL_COUNT = 0

def log_result(stage: str, passed: bool, details: str, data: dict | None = None):
    global PASS_COUNT, FAIL_COUNT
    ts = datetime.now().isoformat()
    status = "PASS" if passed else "FAIL"
    icon = "[OK]" if passed else "[FAIL]"
    if passed:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    entry = {"timestamp": ts, "stage": stage, "status": status, "details": details}
    if data:
        entry["data"] = data
    EVIDENCE.append(entry)
    print(f"\n{icon} [{status}] {stage}")
    print(f"   {details}")
    if data:
        for k, v in data.items():
            val_str = str(v)[:200]
            print(f"   • {k}: {val_str}")


def run_all_tests():
    global PASS_COUNT, FAIL_COUNT
    print("=" * 70)
    print("  PhantomNet Week 19 Day 5 E2E Test")
    print(f"  Started: {datetime.now().isoformat()}")
    print("=" * 70)

    # Setup DB and Client
    from database.database import SessionLocal, engine
    from database.models import Base
    from sentinel.models import SentinelPlaybook
    from main import app
    from services.scheduler_service import SchedulerService
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    client = TestClient(app)
    rejected_pbs = []

    # ==================================================================
    # STAGE 1: Background Scheduler Dynamic Generation
    # ==================================================================
    try:
        print("\n" + "-" * 70)
        print("  STAGE 1: Background Scheduler")
        print("-" * 70)
        
        # Run scheduler manually for test
        scheduler = SchedulerService()
        
        # Mock some packet logs for scheduler to process
        from database.models import PacketLog
        db.query(PacketLog).delete()
        
        now = datetime.utcnow()
        for i in range(15):
            log = PacketLog(
                timestamp=now,
                src_ip=f"10.99.9.{i}",
                dst_ip="10.0.0.50",
                src_port=40000 + i,
                dst_port=2222,
                protocol="TCP",
                length=64,
                threat_score=0.9,
                threat_level="HIGH",
                attack_type="SSH_AUTH_FAILURE",
                is_malicious=True,
                event="login_attempt",
            )
            db.add(log)
        db.commit()
        
        # This will trigger campaign clustering and playbook generation
        scheduler._run_sentinel_auto_gen_cycle()
        
        # Check if playbook generated
        playbooks = db.query(SentinelPlaybook).all()
        generated = len(playbooks) > 0
        log_result(
            "Stage 1a: Scheduler Playbook Generation",
            generated,
            f"Scheduler generated {len(playbooks)} playbooks from packet logs.",
            {"playbook_count": len(playbooks)}
        )
        
        # Check stats panel update
        stats_response = client.get("/api/sentinel/stats")
        stats_ok = stats_response.status_code == 200 and stats_response.json().get("total_playbooks", 0) >= 1
        log_result(
            "Stage 1b: Dynamic Stats Update",
            stats_ok,
            f"Stats panel returned {stats_response.status_code} OK and updated playbooks count.",
            {"stats": stats_response.json()} if stats_response.status_code == 200 else {"error": stats_response.text}
        )
    except Exception as e:
        log_result("Stage 1: Background Scheduler", False, f"Error: {e}")
        traceback.print_exc()

    # ==================================================================
    # STAGE 2: Batch Approve/Reject Workflows
    # ==================================================================
    try:
        print("\n" + "-" * 70)
        print("  STAGE 2: Batch Approve/Reject")
        print("-" * 70)
        
        playbooks = db.query(SentinelPlaybook).all()
        if len(playbooks) < 2:
            # Create dummy playbooks
            for i in range(3):
                pb = SentinelPlaybook(
                    playbook_id=f"PB-TEST-BATCH-{i}",
                    playbook_name=f"Batch Test {i}",
                    status="pending",
                    threat_score=0.8,
                    confidence_score=0.8,
                )
                db.add(pb)
            db.commit()
            playbooks = db.query(SentinelPlaybook).filter(SentinelPlaybook.playbook_id.like("PB-TEST-BATCH-%")).all()
        
        ids = [p.id for p in playbooks[:2]]
        
        # Batch Approve
        approve_resp = client.post("/api/sentinel/playbooks/batch/approve", json={"playbook_ids": ids, "reviewed_by": "test_user"})
        approve_ok = approve_resp.status_code == 200
        
        # Verify DB
        db.expire_all()
        approved_pbs = db.query(SentinelPlaybook).filter(SentinelPlaybook.id.in_(ids)).all()
        all_approved = all(p.status == "approved" for p in approved_pbs)
        
        log_result(
            "Stage 2a: Batch Approve",
            approve_ok and all_approved,
            f"Batch approve returned {approve_resp.status_code}. Verified in DB.",
            {"approved_ids": ids, "db_statuses": [p.status for p in approved_pbs]}
        )
        
        # Batch Reject
        reject_resp = client.post("/api/sentinel/playbooks/batch/reject", json={"playbook_ids": ids, "reviewed_by": "test_user"})
        reject_ok = reject_resp.status_code == 200
        
        db.expire_all()
        rejected_pbs = db.query(SentinelPlaybook).filter(SentinelPlaybook.id.in_(ids)).all()
        all_rejected = all(p.status == "rejected" for p in rejected_pbs)
        
        log_result(
            "Stage 2b: Batch Reject",
            reject_ok and all_rejected,
            f"Batch reject returned {reject_resp.status_code}. Verified in DB.",
            {"rejected_ids": ids, "db_statuses": [p.status for p in rejected_pbs]}
        )
        
    except Exception as e:
        log_result("Stage 2: Batch Approve/Reject", False, f"Error: {e}")
        traceback.print_exc()

    # ==================================================================
    # STAGE 3: Concurrent PDF Download Accuracy and Error Handling
    # ==================================================================
    try:
        print("\n" + "-" * 70)
        print("  STAGE 3: Concurrent PDF Download")
        print("-" * 70)
        
        if not rejected_pbs:
            log_result("Stage 3: PDF Concurrent Export", False, "No playbooks available")
        else:
            pb_id = rejected_pbs[0].id
            
            def fetch_pdf(worker_id):
                resp = client.post(f"/api/sentinel/playbooks/{pb_id}/export?format=pdf")
                return worker_id, resp.status_code, resp.content
            
            num_requests = 5
            results = []
            start = time.time()
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(fetch_pdf, i) for i in range(num_requests)]
                for future in concurrent.futures.as_completed(futures):
                    results.append(future.result())
            
            elapsed = time.time() - start
            
            success_count = sum(1 for r in results if r[1] == 200)
            valid_pdfs = sum(1 for r in results if r[1] == 200 and r[2].startswith(b"%PDF"))
            
            log_result(
                "Stage 3a: Concurrent PDF Requests",
                success_count == num_requests and valid_pdfs == num_requests,
                f"Sent {num_requests} concurrent PDF requests. {success_count} succeeded. {valid_pdfs} valid PDFs. Took {elapsed:.2f}s",
                {"success_count": success_count, "valid_pdfs": valid_pdfs, "latency_sec": elapsed}
            )
            
            # Error handling test - invalid ID
            err_resp = client.post("/api/sentinel/playbooks/999999/export?format=pdf")
            err_ok = err_resp.status_code == 404
            log_result(
                "Stage 3b: PDF Error Handling",
                err_ok,
                f"Requested invalid playbook ID, got status {err_resp.status_code}",
                {"expected": 404, "actual": err_resp.status_code}
            )
    except Exception as e:
        log_result("Stage 3: Concurrent PDF Download", False, f"Error: {e}")
        traceback.print_exc()

    # ==================================================================
    # SUMMARY & EVIDENCE REPORT
    # ==================================================================
    print("\n" + "=" * 70)
    print("  WEEK 19 DAY 5 TEST SUMMARY")
    print("=" * 70)
    print(f"  Total Tests: {PASS_COUNT + FAIL_COUNT}")
    print(f"  ✅ Passed:   {PASS_COUNT}")
    print(f"  ❌ Failed:   {FAIL_COUNT}")
    print(f"  Completed:  {datetime.now().isoformat()}")
    print("=" * 70)

    report_path = os.path.join(EXPORT_DIR, "week19_day5_evidence_report.json")
    report = {
        "test_name": "PhantomNet Week 19 Day 5 E2E Test",
        "timestamp": datetime.now().isoformat(),
        "summary": {"total": PASS_COUNT + FAIL_COUNT, "passed": PASS_COUNT, "failed": FAIL_COUNT},
        "evidence": EVIDENCE,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"\n📄 Evidence report: {report_path}")

    db.close()
    return FAIL_COUNT == 0

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
