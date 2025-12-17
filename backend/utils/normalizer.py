import json
from datetime import datetime

def normalize_log(payload: dict):
    """
    Takes raw JSON from various honeypots (Cowrie, Dionaea)
    and standardizes it into our Database format.
    """
    normalized = {
        "source_ip": "0.0.0.0",
        "src_port": 0,
        "protocol": "unknown",
        "details": "",
        "timestamp": datetime.utcnow()
    }

    # 1. Handle Cowrie (SSH Honeypot) format
    if "cowrie" in payload.get("eventid", ""):
        normalized["source_ip"] = payload.get("src_ip", "0.0.0.0")
        normalized["src_port"] = payload.get("src_port", 22)
        normalized["protocol"] = "ssh"
        normalized["details"] = payload.get("message", "SSH Event")
    
    # 2. Handle Dionaea (Malware/SMB) format
    elif payload.get("connection", {}).get("type") == "accept":
        normalized["source_ip"] = payload.get("connection", {}).get("remote_host", "0.0.0.0")
        normalized["src_port"] = payload.get("connection", {}).get("remote_port", 0)
        normalized["protocol"] = payload.get("connection", {}).get("protocol", "smb")
        normalized["details"] = "Dionaea Connection Accepted"

    # 3. Fallback / Generic JSON
    else:
        normalized["source_ip"] = payload.get("source_ip", payload.get("ip", "0.0.0.0"))
        normalized["src_port"] = payload.get("src_port", payload.get("port", 0))
        normalized["protocol"] = payload.get("protocol", "unknown")
        normalized["details"] = json.dumps(payload)

    return normalized