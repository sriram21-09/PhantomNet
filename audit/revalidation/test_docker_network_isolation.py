import subprocess
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

def run_probe(container, host, port):
    # Run a python one-liner inside the container to test TCP socket connectivity
    cmd = [
        "docker", "exec", container,
        "python", "-c",
        f"import socket; s = socket.socket(); s.settimeout(2); res = s.connect_ex(('{host}', {port})); s.close(); print(res)"
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = proc.stdout.strip()
        # connect_ex returns 0 on success, or errno on failure
        return {"exit_code": proc.returncode, "socket_result": out, "connected": out == "0"}
    except Exception as e:
        return {"error": str(e), "connected": False}

def test_isolation():
    probes = [
        {"src": "phantomnet_api", "dst": "postgres", "port": 5432, "expected": True},
        {"src": "phantomnet_api", "dst": "redis", "port": 6379, "expected": True},
        {"src": "phantomnet_api", "dst": "ollama", "port": 11434, "expected": True},
    ]

    results = []
    for p in probes:
        res = run_probe(p["src"], p["dst"], p["port"])
        results.append({
            "source": p["src"],
            "destination": p["dst"],
            "port": p["port"],
            "expected_connectivity": p["expected"],
            "actual_connected": res.get("connected", False),
            "raw_output": res,
            "status": "PASS" if res.get("connected") == p["expected"] else "FAIL"
        })

    with open(ROOT / "audit" / "revalidation" / "network_isolation_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Network Isolation Probes Complete: {len(results)} probes executed.")

if __name__ == "__main__":
    test_isolation()
