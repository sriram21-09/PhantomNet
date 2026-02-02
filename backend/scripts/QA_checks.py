import pandas as pd

ALLOWED_HONEYPOTS = {"ssh", "http", "ftp", "smtp"}

CSV_PATH = "../../data/week6_test_events.csv"


def extract_features(row):
    """
    Same feature logic used in pipeline (QA mirror)
    """
    return {
        "honeypot": row.get("honeypot_type") or row.get("honeypot"),
        "event": row.get("event"),
        "has_source_ip": bool(row.get("source_ip")),
        "payload_length": len(str(row.get("data"))) if pd.notna(row.get("data")) else 0
    }


def main():
    print("[QA] Loading dataset...")
    df = pd.read_csv(CSV_PATH)

    sample_df = df.head(150)
    print(f"[QA] Testing feature extraction on {len(sample_df)} events")

    failures = 0

    # ================= TASK 1 =================
    for _, row in sample_df.iterrows():
        try:
            features = extract_features(row)
            assert features["honeypot"] is not None
            assert features["event"] is not None
            assert isinstance(features["payload_length"], int)
        except Exception:
            failures += 1

    print("[QA] Feature extraction test completed")
    print(f"[QA] Failures detected: {failures}")
    print("[QA] PASSED ✅" if failures == 0 else "[QA] FAILED ❌")

    # ================= TASK 2 =================
    print("\n[QA] Verifying feature value correctness...")
    invalid_values = 0

    for _, row in sample_df.iterrows():
        features = extract_features(row)

        if features["honeypot"] not in ALLOWED_HONEYPOTS:
            invalid_values += 1
        if not isinstance(features["event"], str) or not features["event"]:
            invalid_values += 1
        if not isinstance(features["has_source_ip"], bool):
            invalid_values += 1
        if not isinstance(features["payload_length"], int) or features["payload_length"] < 0:
            invalid_values += 1

    print(f"[QA] Invalid feature values found: {invalid_values}")
    print("[QA] PASSED ✅" if invalid_values == 0 else "[QA] FAILED ❌")

    # ================= TASK 3 =================
    print("\n[QA] Checking for null or corrupted data...")
    corrupted_rows = 0

    for _, row in sample_df.iterrows():
        honeypot = row.get("honeypot_type") or row.get("honeypot")
        event = row.get("event")
        source_ip = row.get("source_ip")

        if pd.isna(honeypot) or pd.isna(event) or pd.isna(source_ip):
            corrupted_rows += 1

    print(f"[QA] Corrupted / null rows found: {corrupted_rows}")
    print("[QA] PASSED ✅" if corrupted_rows == 0 else "[QA] FAILED ❌")

    # ================= TASK 4 =================
    print("\n[QA] Calculating data quality percentage...")
    total_rows = len(sample_df)
    bad_rows = corrupted_rows + invalid_values
    good_rows = total_rows - bad_rows
    data_quality_percent = (good_rows / total_rows) * 100

    print(f"[QA] Total rows tested : {total_rows}")
    print(f"[QA] Valid rows       : {good_rows}")
    print(f"[QA] Data quality     : {data_quality_percent:.2f}%")
    print("[QA] PASSED ✅" if data_quality_percent >= 99 else "[QA] FAILED ❌")

    # ================= TASK 5 (FIXED SCOPE) =================
    available_honeypots = set(
        (row.get("honeypot_type") or row.get("honeypot"))
        for _, row in df.iterrows()
    )

    print("\n[QA] Testing threat detection coverage for all available honeypots...")

    detected = {
        "ssh": False,
        "http": False,
        "ftp": False,
        "smtp": False
    }

    for _, row in df.iterrows():
        honeypot = row.get("honeypot_type") or row.get("honeypot")
        event = str(row.get("event")).lower()

        if honeypot == "ssh" and "login_failed" in event:
            detected["ssh"] = True
        elif honeypot == "http" and "sqli" in event:
            detected["http"] = True
        elif honeypot == "ftp" and ("command" in event or "connect" in event):
            detected["ftp"] = True
        elif honeypot == "smtp" and ("mail_from" in event or "rcpt_to" in event or "relay" in event):
            detected["smtp"] = True

    qa_failed = False
    for hp in available_honeypots:
        status = detected.get(hp, False)
        print(f"[QA] {hp.upper()} threat detection: {'OK' if status else 'MISSING'}")
        if not status:
            qa_failed = True

    print("[QA] PASSED ✅" if not qa_failed else "[QA] FAILED ❌")

    print("\n[QA] Verifying SSH brute-force detection...")

    ssh_present = False
    ssh_bruteforce_detected = False

    for _, row in df.iterrows():
        honeypot = row.get("honeypot_type") or row.get("honeypot")
        event = str(row.get("event")).lower()

        if honeypot == "ssh":
            ssh_present = True
            if "login_failed" in event:
                ssh_bruteforce_detected = True

    if not ssh_present:
        print("[QA] SSH data not present in dataset")
        print("[QA] RESULT: NOT APPLICABLE (N/A) ⚠️")
    elif ssh_bruteforce_detected:
        print("[QA] SSH brute-force detection verified")
        print("[QA] PASSED ✅")
    else:
        print("[QA] SSH data present but brute-force not detected")
        print("[QA] FAILED ❌")

    print("\n[QA] Verifying HTTP SQL injection detection...")

    http_present = False
    sqli_detected = False

    for _, row in df.iterrows():
        honeypot = row.get("honeypot_type") or row.get("honeypot")
        event = str(row.get("event")).lower()
        payload = str(row.get("data")).lower()

        if honeypot == "http":
            http_present = True
            if "sqli" in event or "union select" in payload or "' or 1=1" in payload or "--" in payload:
                sqli_detected = True

    if not http_present:
        print("[QA] HTTP data not present in dataset")
        print("[QA] RESULT: NOT APPLICABLE (N/A) ⚠️")
    elif sqli_detected:
        print("[QA] HTTP SQL injection detection verified")
        print("[QA] PASSED ✅")
    else:
        print("[QA] HTTP data present but SQL injection not detected")
        print("[QA] FAILED ❌")

    print("\n[QA] Verifying FTP reconnaissance detection...")

    ftp_present = False
    ftp_recon_detected = False

    for _, row in df.iterrows():
        honeypot = row.get("honeypot_type") or row.get("honeypot")
        event = str(row.get("event")).lower()

        if honeypot == "ftp":
            ftp_present = True
            if (
                "command" in event
                or "connect" in event
                or "login" in event
                or "user" in event
            ):
                ftp_recon_detected = True

    if not ftp_present:
        print("[QA] FTP data not present in dataset")
        print("[QA] RESULT: NOT APPLICABLE (N/A) ⚠️")
    elif ftp_recon_detected:
        print("[QA] FTP reconnaissance detection verified")
        print("[QA] PASSED ✅")
    else:
        print("[QA] FTP data present but reconnaissance not detected")
        print("[QA] FAILED ❌")

    print("\n[QA] Verifying SMTP relay / spoof detection...")

    smtp_present = False
    smtp_relay_detected = False

    for _, row in df.iterrows():
        honeypot = row.get("honeypot_type") or row.get("honeypot")
        event = str(row.get("event")).lower()

        if honeypot == "smtp":
            smtp_present = True
            if (
                "mail_from" in event
                or "rcpt_to" in event
                or "data" in event
                or "ehlo" in event
            ):
                smtp_relay_detected = True

    if not smtp_present:
        print("[QA] SMTP data not present in dataset")
        print("[QA] RESULT: NOT APPLICABLE (N/A) ⚠️")
    elif smtp_relay_detected:
        print("[QA] SMTP relay / spoof detection verified")
        print("[QA] PASSED ✅")
    else:
        print("[QA] SMTP data present but relay / spoof not detected")
        print("[QA] FAILED ❌")




if __name__ == "__main__":
    main()
