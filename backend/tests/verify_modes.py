import requests
import json

BASE_URL = "http://localhost:8000"

def test():
    # Login with environment secret
    res = requests.post(f"{BASE_URL}/api/v1/admin/login", json={"username": "admin", "password": "PhantomNet_SecAdmin_2026!"})
    print("Login status:", res.status_code)
    if res.status_code != 200:
        print("Login failed:", res.text)
        return

    token = res.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    for mode in ["all", "live", "test"]:
        s = requests.get(f"{BASE_URL}/api/stats?mode={mode}", headers=headers).json()
        print(f"\n================ MODE: {mode.upper()} ================")
        print(f"Total Events: {s.get('totalEvents')}")
        print(f"Unique IPs: {s.get('uniqueIPs')}")
        print(f"Active Nodes: {s.get('activeHoneypots')} / {s.get('totalConfiguredNodes')}")
        print(f"Avg Threat Score: {s.get('avgThreatScore')}%")
        print(f"Avg Anomaly Score: {s.get('avgAnomalyScore')}%")
        print("Protocol Distribution:")
        for p in s.get("protocolDistribution", []):
            print(f"  - {p['name']}: {p['value']} packets ({p['percentage']}%)")
        print(f"Composition: {json.dumps(s.get('dataComposition'))}")

    print("\n================ TOP VECTORS: LIVE ================")
    v_live = requests.get(f"{BASE_URL}/api/threats/top-vectors?limit=5&mode=live", headers=headers).json()
    for v in v_live:
        print(f"  IP: {v['ip']:<15} | Count: {v['count']:>3} ({v.get('percentage'):>4}%) | Type: {v.get('source_type'):<32} | Origin: {v.get('country')}")

    print("\n================ TOP VECTORS: ALL ================")
    v_all = requests.get(f"{BASE_URL}/api/threats/top-vectors?limit=5&mode=all", headers=headers).json()
    for v in v_all:
        print(f"  IP: {v['ip']:<15} | Count: {v['count']:>3} ({v.get('percentage'):>4}%) | Type: {v.get('source_type'):<32} | Origin: {v.get('country')}")

    print("\n================ TIMELINE: LIVE ================")
    tl_live = requests.get(f"{BASE_URL}/api/stats/timeline?mode=live", headers=headers).json()
    print(f"Live 24h Total: {tl_live.get('total24h')}, Trend: {tl_live.get('trend')}")

if __name__ == "__main__":
    test()
