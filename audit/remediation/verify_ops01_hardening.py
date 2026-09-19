import subprocess
import json
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent.parent

def verify_ops01():
    print("=" * 60)
    print("PHANTOMNET V3 — OPS-01 CONTAINER HARDENING VERIFICATION")
    print("=" * 60)

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "dimension": "OPS-01",
        "description": "Container runtime security posture (non-root UID, dropped capabilities, no-new-privileges, read-only rootfs with tmpfs mounts)",
        "inspected_container": "phantomnet_api",
        "container_config": {},
        "filesystem_write_tests": {},
        "properties_verified": {}
    }

    # 1. Inspect Docker Container Configuration
    inspect_raw = subprocess.check_output(["docker", "inspect", "phantomnet_api"])
    data = json.loads(inspect_raw)[0]

    cfg = data["Config"]
    host_cfg = data["HostConfig"]

    user = cfg.get("User", "")
    cap_drop = host_cfg.get("CapDrop", [])
    security_opt = host_cfg.get("SecurityOpt", [])
    readonly_rootfs = host_cfg.get("ReadonlyRootfs", False)
    tmpfs_mounts = host_cfg.get("Tmpfs", {})

    results["container_config"] = {
        "user": user,
        "cap_drop": cap_drop,
        "security_opt": security_opt,
        "readonly_rootfs": readonly_rootfs,
        "tmpfs_mounts": tmpfs_mounts
    }

    print(f"Container: phantomnet_api")
    print(f"  User: {user}")
    print(f"  CapDrop: {cap_drop}")
    print(f"  SecurityOpt: {security_opt}")
    print(f"  ReadonlyRootfs: {readonly_rootfs}")
    print(f"  Tmpfs Mounts: {tmpfs_mounts}")

    # 2. Test Filesystem Write Permissions inside container
    test_script = """
import os, json

res = {}
# Test authorized write to tmpfs /app/backend/logs
try:
    path = "/app/backend/logs/audit_hardening_test.log"
    with open(path, "w") as f:
        f.write("test log entry")
    res["authorized_tmpfs_write"] = {"path": path, "status": "SUCCESS"}
    os.remove(path)
except Exception as e:
    res["authorized_tmpfs_write"] = {"path": path, "status": "FAILED", "error": str(e)}

# Test unauthorized write to root filesystem /unauthorized.txt
try:
    with open("/unauthorized.txt", "w") as f:
        f.write("unauthorized")
    res["unauthorized_root_write"] = {"path": "/unauthorized.txt", "status": "FAILED_ALLOWED"}
except OSError as e:
    res["unauthorized_root_write"] = {"path": "/unauthorized.txt", "status": "BLOCKED", "error": str(e)}
except Exception as e:
    res["unauthorized_root_write"] = {"path": "/unauthorized.txt", "status": "BLOCKED", "error": str(e)}

# Test unauthorized write to /app/unauthorized.py
try:
    with open("/app/unauthorized.py", "w") as f:
        f.write("malicious = True")
    res["unauthorized_app_write"] = {"path": "/app/unauthorized.py", "status": "FAILED_ALLOWED"}
except OSError as e:
    res["unauthorized_app_write"] = {"path": "/app/unauthorized.py", "status": "BLOCKED", "error": str(e)}
except Exception as e:
    res["unauthorized_app_write"] = {"path": "/app/unauthorized.py", "status": "BLOCKED", "error": str(e)}

print(json.dumps(res))
"""

    exec_cmd = ["docker", "exec", "phantomnet_api", "python", "-c", test_script]
    exec_proc = subprocess.run(exec_cmd, capture_output=True, text=True, check=True)
    fs_results = json.loads(exec_proc.stdout.strip())
    results["filesystem_write_tests"] = fs_results

    print("\nFilesystem Write Tests:")
    for k, v in fs_results.items():
        print(f"  {k}: {v['status']} ({v.get('error', 'None')})")

    # 3. Evaluate Properties
    p_user = (user == "10001:10001" or user == "10001")
    p_cap = ("ALL" in cap_drop)
    p_sec = any("no-new-privileges:true" in opt for opt in security_opt)
    p_ro = (readonly_rootfs is True)
    p_auth_write = (fs_results["authorized_tmpfs_write"]["status"] == "SUCCESS")
    p_unauth_write = (fs_results["unauthorized_root_write"]["status"] == "BLOCKED" and fs_results["unauthorized_app_write"]["status"] == "BLOCKED")

    results["properties_verified"] = {
        "non_root_uid_10001": p_user,
        "cap_drop_all": p_cap,
        "no_new_privileges_enforced": p_sec,
        "readonly_rootfs_enforced": p_ro,
        "authorized_tmpfs_write_permitted": p_auth_write,
        "unauthorized_rootfs_write_blocked": p_unauth_write
    }

    all_passed = all(results["properties_verified"].values())
    results["overall_verdict"] = "VERIFIED" if all_passed else "NOT VERIFIED"

    out_file = ROOT / "audit" / "remediation" / "ops01_container_hardening_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nFinal Verdict for OPS-01: {results['overall_verdict']}")
    print(f"Saved evidence to {out_file}")

if __name__ == "__main__":
    verify_ops01()
