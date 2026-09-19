import os
import sys
import json
from pathlib import Path
from datetime import datetime

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from backend.middleware.auth import (
    create_access_token,
    decode_token,
    get_jwt_secret,
    get_previous_jwt_secret,
)

def test_sec10_jwt_rotation():
    print("=" * 60)
    print("PHANTOMNET V3 — SEC-10 DUAL-KEY JWT ROTATION VERIFICATION")
    print("=" * 60)

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "dimension": "SEC-10",
        "description": "Dual-key JWT verification during zero-downtime rotation",
        "steps": {},
        "properties_verified": {}
    }

    SECRET_A = "rotation-secret-key-phase-alpha-2026-secure-32b"
    SECRET_B = "rotation-secret-key-phase-beta-2026-secure-32b"
    SECRET_C = "rotation-secret-key-phase-gamma-2026-secure-32b"

    # Step 1: Baseline under Secret A
    print("\n--- Step 1: Baseline Under Secret A ---")
    os.environ["JWT_SECRET"] = SECRET_A
    os.environ.pop("JWT_SECRET_PREVIOUS", None)
    os.environ.pop("PREVIOUS_SECRET", None)

    token_a = create_access_token({"sub": "analyst1", "role": "Analyst"})
    decoded_a_baseline = decode_token(token_a)
    print(f"Token A created. Decoded under Secret A: {decoded_a_baseline is not None}")

    results["steps"]["step1_baseline"] = {
        "token_created": token_a[:25] + "...",
        "decoded_successfully": decoded_a_baseline is not None,
        "sub": decoded_a_baseline.get("sub") if decoded_a_baseline else None
    }

    # Step 2: Rotate to Secret B with Secret A as Previous (Dual-Key Active)
    print("\n--- Step 2: Rotate to Secret B with Secret A as Fallback ---")
    os.environ["JWT_SECRET"] = SECRET_B
    os.environ["JWT_SECRET_PREVIOUS"] = SECRET_A

    # Verify existing session token_a still decodes successfully via previous secret
    decoded_a_during_rotation = decode_token(token_a)
    print(f"Existing Token A verified under new active key (via fallback): {decoded_a_during_rotation is not None}")

    # Issue new token under Secret B
    token_b = create_access_token({"sub": "admin_user", "role": "Admin"})
    decoded_b = decode_token(token_b)
    print(f"New Token B created. Decoded under Secret B: {decoded_b is not None}")

    results["steps"]["step2_rotation_window"] = {
        "active_secret": "Secret B",
        "previous_secret": "Secret A",
        "existing_token_a_valid": decoded_a_during_rotation is not None,
        "new_token_b_valid": decoded_b is not None
    }

    # Step 3: Rotate to Secret C with Secret B as Previous (Secret A now retired)
    print("\n--- Step 3: Rotate to Secret C (Secret A Retired) ---")
    os.environ["JWT_SECRET"] = SECRET_C
    os.environ["JWT_SECRET_PREVIOUS"] = SECRET_B

    # Token B should still be valid (fallback to B)
    decoded_b_step3 = decode_token(token_b)
    # Token A should now be REJECTED (A is no longer in active or previous)
    decoded_a_step3 = decode_token(token_a)
    print(f"Token B verified under Secret C (via fallback to B): {decoded_b_step3 is not None}")
    print(f"Token A rejected after retirement: {decoded_a_step3 is None}")

    results["steps"]["step3_retired_secret"] = {
        "active_secret": "Secret C",
        "previous_secret": "Secret B",
        "token_b_still_valid": decoded_b_step3 is not None,
        "retired_token_a_rejected": decoded_a_step3 is None
    }

    # Step 4: Verify Properties
    p1 = results["steps"]["step1_baseline"]["decoded_successfully"]
    p2 = results["steps"]["step2_rotation_window"]["existing_token_a_valid"]
    p3 = results["steps"]["step2_rotation_window"]["new_token_b_valid"]
    p4 = results["steps"]["step3_retired_secret"]["retired_token_a_rejected"]
    p5 = results["steps"]["step3_retired_secret"]["token_b_still_valid"]

    results["properties_verified"] = {
        "existing_sessions_valid_during_rotation": p2,
        "new_tokens_use_active_secret": p3,
        "previous_tokens_temporarily_verifiable": p2,
        "old_secret_eventually_invalid": p4,
        "zero_downtime_rotation_supported": (p1 and p2 and p3 and p4 and p5)
    }

    all_passed = all(results["properties_verified"].values())
    results["overall_verdict"] = "VERIFIED" if all_passed else "NOT VERIFIED"

    out_file = ROOT / "audit" / "remediation" / "sec10_jwt_rotation_results.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"\nProperties Verified:")
    for prop, val in results["properties_verified"].items():
        print(f"  {prop}: {val}")
    print(f"\nFinal Verdict for SEC-10: {results['overall_verdict']}")
    print(f"Saved evidence to {out_file}")

if __name__ == "__main__":
    test_sec10_jwt_rotation()
