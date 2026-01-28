import json
import hashlib
import ipaddress
from datetime import datetime
from typing import Optional


REQUIRED_FIELDS = [
    "honeypot_type",
    "src_ip",
    "port",
    "created_at",
    "raw_data"
]


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except Exception:
        return False


def parse_timestamp(ts) -> Optional[str]:
    """
    Normalize timestamp to ISO 8601 UTC
    """
    try:
        if isinstance(ts, datetime):
            return ts.isoformat()
        return datetime.fromisoformat(str(ts)).isoformat()
    except Exception:
        return None


def safe_json_load(value) -> dict:
    """
    Load JSON safely, fallback to empty dict
    """
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except Exception:
        return {}


def generate_event_id(normalized_event: dict) -> str:
    """
    Deterministic hash for ML / deduplication
    """
    h = hashlib.sha256()
    h.update(json.dumps(normalized_event, sort_keys=True).encode())
    return h.hexdigest()


def normalize_event(row: dict) -> Optional[dict]:
    """
    Normalize a single DB row into ML-ready format
    """

    honeypot_type = row.get("honeypot_type")

    # ---------------------------
    # SOURCE IP
    # ---------------------------
    src_ip = row.get("source_ip") or row.get("src_ip")
    if not src_ip or not is_valid_ip(src_ip):
        return None

    # ---------------------------
    # PORT
    # ---------------------------
    port = row.get("port")
    if port is None:
        return None

    # ---------------------------
    # TIMESTAMP
    # ---------------------------
    created_at = parse_timestamp(row.get("timestamp"))
    if not created_at:
        return None

    # ---------------------------
    # RAW DATA (protocol-specific)
    # ---------------------------
    if honeypot_type == "ssh":
        # SSH is STRUCTURED → rebuild raw_data
        raw_data = {
            "username": row.get("username"),
            "password": row.get("password"),
            "status": row.get("status")
        }

    else:
        # HTTP / FTP / SMTP already store raw JSON
        raw_data = safe_json_load(row.get("raw_data"))

    # ---------------------------
    # FINAL NORMALIZED EVENT
    # ---------------------------
    normalized = {
        "honeypot_type": honeypot_type,
        "src_ip": src_ip,
        "port": int(port),
        "created_at": created_at,
        "raw_data": raw_data
    }

    # ---------------------------
    # VALIDATION
    # ---------------------------
    for field in REQUIRED_FIELDS:
        if normalized.get(field) is None:
            return None

    normalized["event_id"] = generate_event_id(normalized)

    return normalized


# ---------------------------
# LOCAL TEST
# ---------------------------
if __name__ == "__main__":
    sample_ssh = {
        "timestamp": "2026-01-26T09:49:24.442910+00:00",
        "source_ip": "172.18.0.1",
        "honeypot_type": "ssh",
        "port": 2222,
        "username": "PhantomNet",
        "password": "1234",
        "status": "login_attempt"
    }

    normalized = normalize_event(sample_ssh)
    print(json.dumps(normalized, indent=2))
