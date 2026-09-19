import os
import re
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

def test_rt02_reconnect():
    evidence = {
        "dimension": "RT-02",
        "name": "WebSocket Reconnection with Full Jitter",
        "original_claim": "Client reconnection implements exponential backoff with full jitter (1s base, 30s cap) to prevent thundering herd during server restarts.",
        "findings": []
    }

    # 1. Inspect frontend RealTimeContext.jsx
    frontend_file = ROOT / "frontend-dev" / "phantomnet-dashboard" / "src" / "context" / "RealTimeContext.jsx"
    if not frontend_file.exists():
        evidence["findings"].append({"error": "RealTimeContext.jsx not found"})
        return evidence

    with open(frontend_file, "r", encoding="utf-8") as f:
        content = f.read()

    # Check for hardcoded 3000ms delay
    has_fixed_3000 = "setTimeout(connect, 3000)" in content or "setTimeout(connect,3000)" in content
    has_jitter = "Math.random()" in content and "Math.pow" in content

    evidence["code_inspection"] = {
        "has_fixed_3000ms_retry": has_fixed_3000,
        "has_exponential_jitter": has_jitter,
        "file_path": str(frontend_file)
    }

    if has_fixed_3000 and not has_jitter:
        evidence["status"] = "REPRODUCED_FAIL"
        evidence["details"] = "RealTimeContext.jsx implements a fixed 3000ms delay (setTimeout(connect, 3000)) on socket close. Zero exponential backoff, zero jitter."
    else:
        evidence["status"] = "PASS_REMEDIATED"

    with open(ROOT / "audit" / "revalidation" / "rt02_reconnect_reproduce.json", "w", encoding="utf-8") as f:
        json.dump(evidence, f, indent=2)

    print(f"[+] RT-02 Inspection Complete: Fixed 3000ms={has_fixed_3000}, Has Jitter={has_jitter}")

if __name__ == "__main__":
    test_rt02_reconnect()
