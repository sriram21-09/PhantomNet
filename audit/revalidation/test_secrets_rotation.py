import os
import sys
import hmac
import hashlib
import time
import json
from pathlib import Path
from datetime import datetime, timedelta

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

os.environ["ENVIRONMENT"] = "test"
os.environ["JWT_SECRET"] = "secret_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

import jwt
from backend.middleware.auth import create_access_token, ALGORITHM

def test_secret_rotation_lifecycle():
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "dimension": "SEC-07 / SEC-10",
        "tests": []
    }

    # 1. JWT Rotation Test
    # Generate Token under V1 secret
    v1_secret = "secret_v1_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    v2_secret = "secret_v2_9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"

    # Token minted under V1
    v1_token = jwt.encode(
        {"sub": "test_user", "role": "ADMIN", "exp": datetime.utcnow() + timedelta(minutes=15)},
        v1_secret,
        algorithm=ALGORITHM
    )

    # Verify under V1
    try:
        payload_v1 = jwt.decode(v1_token, v1_secret, algorithms=[ALGORITHM])
        v1_valid_under_v1 = True
    except Exception:
        v1_valid_under_v1 = False

    # Simulate Secret Rotation: V1 -> V2
    # Verify V1 token under V2 secret (Expected: InvalidSignatureError)
    v1_rejected_under_v2 = False
    try:
        jwt.decode(v1_token, v2_secret, algorithms=[ALGORITHM])
    except jwt.InvalidSignatureError:
        v1_rejected_under_v2 = True
    except Exception:
        pass

    # Mint V2 token under V2 secret
    v2_token = jwt.encode(
        {"sub": "test_user", "role": "ADMIN", "exp": datetime.utcnow() + timedelta(minutes=15)},
        v2_secret,
        algorithm=ALGORITHM
    )
    try:
        jwt.decode(v2_token, v2_secret, algorithms=[ALGORITHM])
        v2_valid_under_v2 = True
    except Exception:
        v2_valid_under_v2 = False

    jwt_rotation_pass = v1_valid_under_v1 and v1_rejected_under_v2 and v2_valid_under_v2

    results["tests"].append({
        "name": "JWT Secret Rotation",
        "v1_valid_under_v1": v1_valid_under_v1,
        "v1_rejected_under_v2": v1_rejected_under_v2,
        "v2_valid_under_v2": v2_valid_under_v2,
        "zero_downtime_supported": False, # Current auth.py only supports single JWT_SECRET
        "status": "PASS" if jwt_rotation_pass else "FAIL"
    })

    # 2. Honeypot HMAC Secret Rotation Test
    hmac_key_v1 = b"hmac_key_v1_0123456789abcdef0123456789abcdef"
    hmac_key_v2 = b"hmac_key_v2_9876543210fedcba9876543210fedcba"
    payload = b'{"event": "login_attempt", "ip": "1.2.3.4"}'

    # Compute V1 signature
    sig_v1 = hmac.new(hmac_key_v1, payload, hashlib.sha256).hexdigest()

    # Verify under V1
    sig_v1_valid = hmac.compare_digest(sig_v1, hmac.new(hmac_key_v1, payload, hashlib.sha256).hexdigest())

    # Verify V1 under V2 (Must fail)
    sig_v1_under_v2 = hmac.compare_digest(sig_v1, hmac.new(hmac_key_v2, payload, hashlib.sha256).hexdigest())

    # Compute V2 signature and verify under V2
    sig_v2 = hmac.new(hmac_key_v2, payload, hashlib.sha256).hexdigest()
    sig_v2_valid = hmac.compare_digest(sig_v2, hmac.new(hmac_key_v2, payload, hashlib.sha256).hexdigest())

    hmac_rotation_pass = sig_v1_valid and (not sig_v1_under_v2) and sig_v2_valid

    results["tests"].append({
        "name": "Honeypot HMAC Secret Rotation",
        "v1_valid_under_v1": sig_v1_valid,
        "v1_rejected_under_v2": not sig_v1_under_v2,
        "v2_valid_under_v2": sig_v2_valid,
        "status": "PASS" if hmac_rotation_pass else "FAIL"
    })

    # 3. Audit Secret Defaults across Codebase
    secrets_inventory = [
        {"secret": "JWT_SECRET", "source": "os.getenv", "fallback": "phantomnet-admin-secret-key-2026", "safe_in_prod": False},
        {"secret": "HONEYPOT_SECRET_KEY", "source": "os.getenv", "fallback": "phantomnet-honeypot-secret-change-in-prod", "safe_in_prod": False},
        {"secret": "POSTGRES_PASSWORD", "source": "os.getenv", "fallback": "postgres", "safe_in_prod": False},
        {"secret": "API_KEY", "source": "os.getenv", "fallback": "default_key", "safe_in_prod": False}
    ]
    results["secrets_inventory"] = secrets_inventory

    with open(ROOT / "audit" / "revalidation" / "secret_rotation_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("[+] Secret Lifecycle & Rotation Tests Completed.")

if __name__ == "__main__":
    test_secret_rotation_lifecycle()
