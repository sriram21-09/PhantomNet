"""
tests/test_stix_bundle_compliance.py
-------------------------------------
STIX 2.1 Bundle Compliance Verification for PhantomNet v3.0.0 Security Sign-Off.

This script programmatically validates that the TAXII /objects/ endpoint
produces well-formed STIX 2.1 bundles per the OASIS specification.

Run:
    python tests/test_stix_bundle_compliance.py
"""

import os
import sys
import json
import re
from datetime import datetime

# Force test environment
os.environ["DATABASE_URL"] = "sqlite:///./test_stix_compliance.db"
os.environ["TESTING"] = "1"
os.environ["ENVIRONMENT"] = "test"

# Add backend to path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, backend_path)

# pyrefly: ignore [missing-import]
from sqlalchemy import create_engine
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import sessionmaker
# pyrefly: ignore [missing-import]
from fastapi import FastAPI
# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient

from database.models import Base  # pyrefly: ignore [missing-import]
from sentinel.models import SentinelPlaybook  # pyrefly: ignore [missing-import]
from api.taxii import router as taxii_router, TaxiiContentNegotiationMiddleware  # pyrefly: ignore [missing-import]
from database.database import get_db  # pyrefly: ignore [missing-import]

# ---------- Setup ----------
engine = create_engine(os.environ["DATABASE_URL"], connect_args={"check_same_thread": False})
Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

app = FastAPI(title="STIX Compliance Test")
app.add_middleware(TaxiiContentNegotiationMiddleware)
app.include_router(taxii_router)


def override_get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


from api.taxii import get_taxii_user  # pyrefly: ignore [missing-import]


def override_get_taxii_user():
    return type("User", (), {"username": "test", "status": "active"})()


app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_taxii_user] = override_get_taxii_user
client = TestClient(app)

# UUID v4/v5 regex pattern
UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)

VALID_STIX_TYPES = {
    "attack-pattern", "campaign", "course-of-action", "grouping", "identity",
    "indicator", "infrastructure", "intrusion-set", "location", "malware",
    "malware-analysis", "note", "observed-data", "opinion", "relationship",
    "report", "sighting", "threat-actor", "tool", "vulnerability", "bundle",
}

ISO8601_Z_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
)

results = []
pass_count = 0
fail_count = 0


def check(name, condition, detail=""):
    global pass_count, fail_count
    status = "✅ PASS" if condition else "❌ FAIL"
    if condition:
        pass_count += 1
    else:
        fail_count += 1
    results.append({"name": name, "status": status, "detail": detail})
    print(f"  {status} — {name}" + (f" ({detail})" if detail and not condition else ""))


def seed_test_data():
    db = SessionLocal()
    from datetime import timedelta
    base_time = datetime(2026, 9, 1, 0, 0, 0)
    for i in range(5):
        pb = SentinelPlaybook(
            playbook_id=f"PB-STIX-{i:04d}",
            created_at=base_time + timedelta(hours=i),
            updated_at=base_time + timedelta(hours=i),
            src_ip=f"192.168.1.{i + 10}",
            dst_port=22,
            protocol="TCP",
            attack_type="SSH_AUTH_FAILURE",
            tactic="Credential Access",
            technique_id="T1110",
            status="approved",
        )
        db.add(pb)
    db.commit()
    db.close()
    print("  Seeded 5 test playbooks.\n")


def run_compliance_checks():
    global pass_count, fail_count

    print("=" * 70)
    print("  STIX 2.1 Bundle Compliance Verification — PhantomNet v3.0.0")
    print("=" * 70)
    print()

    seed_test_data()

    headers = {"Accept": "application/stix+json;version=2.1"}

    # ---------- 1. Fetch STIX bundle ----------
    print("[1/8] Fetching STIX bundle from TAXII objects endpoint...")
    resp = client.get(
        "/taxii2/phantomnet/collections/honeypot-cowrie-ssh/objects/?limit=100",
        headers=headers,
    )
    check("HTTP 200 response", resp.status_code == 200, f"got {resp.status_code}")
    data = resp.json()

    # ---------- 2. Bundle structure ----------
    print("\n[2/8] Validating STIX bundle envelope structure...")
    check("Bundle has 'type' field", "type" in data)
    check("Bundle type is 'bundle'", data.get("type") == "bundle")
    check("Bundle has 'id' field", "id" in data)
    bundle_id = data.get("id", "")
    check("Bundle id starts with 'bundle--'", bundle_id.startswith("bundle--"))
    uuid_part = bundle_id.replace("bundle--", "")
    check("Bundle id contains valid UUID", bool(UUID_PATTERN.match(uuid_part)), uuid_part)
    check("Bundle has 'objects' array", isinstance(data.get("objects"), list))
    objects = data.get("objects", [])
    check("Bundle contains objects", len(objects) > 0, f"count={len(objects)}")

    # ---------- 3. Validate each STIX object ----------
    print(f"\n[3/8] Validating {len(objects)} individual STIX objects...")
    type_counts = {}
    for i, obj in enumerate(objects):
        obj_type = obj.get("type", "MISSING")
        type_counts[obj_type] = type_counts.get(obj_type, 0) + 1

        check(
            f"Object[{i}] has valid 'type'",
            obj_type in VALID_STIX_TYPES,
            f"type={obj_type}",
        )
        check(
            f"Object[{i}] has 'id' field",
            "id" in obj,
        )
        if "id" in obj:
            check(
                f"Object[{i}] id format '{obj_type}--<uuid>'",
                obj["id"].startswith(f"{obj_type}--"),
                obj["id"][:40],
            )
        if obj_type != "bundle":
            check(
                f"Object[{i}] has spec_version '2.1'",
                obj.get("spec_version") == "2.1",
                f"got '{obj.get('spec_version')}'",
            )
        if "created" in obj:
            check(
                f"Object[{i}] 'created' is ISO 8601 UTC",
                bool(ISO8601_Z_PATTERN.match(obj["created"])),
                obj["created"],
            )
        if "modified" in obj:
            check(
                f"Object[{i}] 'modified' is ISO 8601 UTC",
                bool(ISO8601_Z_PATTERN.match(obj["modified"])),
                obj["modified"],
            )

    print(f"\n  Object type distribution: {json.dumps(type_counts, indent=2)}")

    # ---------- 4. Identity object ----------
    print("\n[4/8] Validating Identity anchor object...")
    identities = [o for o in objects if o.get("type") == "identity"]
    check("At least one identity object exists", len(identities) >= 1)
    if identities:
        ident = identities[0]
        check("Identity has 'name'", "name" in ident)
        check("Identity has 'identity_class'", "identity_class" in ident)

    # ---------- 5. Attack-pattern objects ----------
    print("\n[5/8] Validating Attack-Pattern objects...")
    aps = [o for o in objects if o.get("type") == "attack-pattern"]
    check("Attack-pattern objects present", len(aps) > 0, f"count={len(aps)}")
    if aps:
        ap = aps[0]
        check("Attack-pattern has 'name'", "name" in ap)
        check("Attack-pattern has 'external_references'", "external_references" in ap)
        if "external_references" in ap:
            refs = ap["external_references"]
            check("External ref has 'source_name'", "source_name" in refs[0])
            check(
                "External ref source is 'mitre-attack'",
                refs[0].get("source_name") == "mitre-attack",
            )
            check("External ref has 'external_id'", "external_id" in refs[0])
            check("External ref has 'url'", "url" in refs[0])

    # ---------- 6. Indicator objects ----------
    print("\n[6/8] Validating Indicator objects...")
    inds = [o for o in objects if o.get("type") == "indicator"]
    check("Indicator objects present", len(inds) > 0, f"count={len(inds)}")
    if inds:
        ind = inds[0]
        check("Indicator has 'pattern'", "pattern" in ind)
        check("Indicator has 'pattern_type'", "pattern_type" in ind)
        check(
            "Indicator pattern_type is 'stix'",
            ind.get("pattern_type") == "stix",
        )
        check("Indicator has 'valid_from'", "valid_from" in ind)
        pattern = ind.get("pattern", "")
        check(
            "Indicator pattern is valid STIX pattern",
            pattern.startswith("[") and "ipv4-addr:value" in pattern,
            pattern[:60],
        )

    # ---------- 7. Report objects ----------
    print("\n[7/8] Validating Report objects...")
    reports = [o for o in objects if o.get("type") == "report"]
    check("Report objects present", len(reports) > 0, f"count={len(reports)}")
    if reports:
        rep = reports[0]
        check("Report has 'name'", "name" in rep)
        check("Report has 'published'", "published" in rep)
        check("Report has 'object_refs'", "object_refs" in rep)
        check(
            "Report object_refs is non-empty list",
            isinstance(rep.get("object_refs"), list) and len(rep.get("object_refs", [])) > 0,
        )

    # ---------- 8. Content-Type header ----------
    print("\n[8/8] Validating TAXII 2.1 response headers...")
    ct = resp.headers.get("content-type", "")
    check(
        "Response Content-Type is STIX 2.1 media type",
        "application/stix+json" in ct,
        ct,
    )

    # ---------- Summary ----------
    print("\n" + "=" * 70)
    print(f"  RESULTS: {pass_count} passed, {fail_count} failed, {pass_count + fail_count} total")
    print("=" * 70)

    if fail_count == 0:
        print("\n  🎉 ALL STIX 2.1 COMPLIANCE CHECKS PASSED — BUNDLE IS SPEC-COMPLIANT\n")
    else:
        print(f"\n  ⚠️  {fail_count} COMPLIANCE CHECK(S) FAILED — REVIEW REQUIRED\n")

    # Write results to JSON
    report_path = os.path.join(os.path.dirname(__file__), "..", "security", "stix_compliance_results.json")
    report = {
        "test": "STIX 2.1 Bundle Compliance Verification",
        "version": "v3.0.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "summary": {
            "total_checks": pass_count + fail_count,
            "passed": pass_count,
            "failed": fail_count,
            "status": "COMPLIANT" if fail_count == 0 else "NON-COMPLIANT",
        },
        "object_type_counts": type_counts,
        "checks": results,
    }
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"  Report saved to: security/stix_compliance_results.json\n")

    return fail_count == 0


if __name__ == "__main__":
    success = run_compliance_checks()
    sys.exit(0 if success else 1)
