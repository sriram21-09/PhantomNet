"""
PhantomNet Phase ML-8: External Benchmark Acquisition Script
===========================================================
Downloads and persists representative, balanced samples of three prominent
public network intrusion benchmarks from verified research mirrors:
1. NF-ToN-IoT-v2 (IoT NetFlow benchmark from UNSW Canberra Cyber)
2. CIC-IDS2017 (Friday DDoS/PortScan benchmark from UNB/CIC)
3. UNSW-NB15 (Flow benchmark from ACCS)

Saves raw samples to data/external_benchmarks/ with SHA-256 verification.
"""

import os
import io
import hashlib
import urllib.request
import pandas as pd

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "external_benchmarks"))
os.makedirs(DATA_DIR, exist_ok=True)

def sha256_file(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def acquire_nf_ton_iot_v2(target_rows: int = 5000) -> str:
    dest_path = os.path.join(DATA_DIR, "nf_ton_iot_v2_sample.csv")
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 10000:
        print(f"[CACHE] NF-ToN-IoT-v2 already exists at {dest_path}")
        return dest_path

    print("[DOWNLOAD] Streaming NF-ToN-IoT-v2 sample from HuggingFace...")
    url = "https://huggingface.co/datasets/Nora9029/NF-ToN-IoT-v2/resolve/main/NF-ToN-IoT-v2-test.csv"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (PhantomNet ML-8 Auditor)"})

    lines = []
    with urllib.request.urlopen(req, timeout=45) as resp:
        header = resp.readline().decode("utf-8", errors="ignore").strip()
        lines.append(header)
        b_count, a_count = 0, 0
        b_target = int(target_rows * 0.70)
        a_target = target_rows - b_target
        
        for raw_line in resp:
            l = raw_line.decode("utf-8", errors="ignore").strip()
            if not l:
                continue
            parts = l.split(",")
            # Label is column index 43, Attack is column index 44
            if len(parts) >= 45:
                lbl = parts[43].strip()
                if lbl == "0" and b_count < b_target:
                    lines.append(l)
                    b_count += 1
                elif lbl == "1" and a_count < a_target:
                    lines.append(l)
                    a_count += 1
            if b_count >= b_target and a_count >= a_target:
                break

    with open(dest_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[SUCCESS] Saved {len(lines)-1} rows to {dest_path} (SHA-256: {sha256_file(dest_path)})")
    return dest_path


def acquire_cicids2017(target_rows: int = 5000) -> str:
    dest_path = os.path.join(DATA_DIR, "cicids2017_sample.csv")
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 10000:
        print(f"[CACHE] CIC-IDS2017 already exists at {dest_path}")
        return dest_path

    print("[DOWNLOAD] Streaming CIC-IDS2017 DDoS/PortScan sample from HuggingFace...")
    url = "https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (PhantomNet ML-8 Auditor)"})

    lines = []
    with urllib.request.urlopen(req, timeout=45) as resp:
        header = resp.readline().decode("utf-8", errors="ignore").strip()
        lines.append(header)
        b_count, a_count = 0, 0
        b_target = int(target_rows * 0.70)
        a_target = target_rows - b_target

        for raw_line in resp:
            l = raw_line.decode("utf-8", errors="ignore").strip()
            if not l:
                continue
            if l.endswith("BENIGN") and b_count < b_target:
                lines.append(l)
                b_count += 1
            elif l.endswith("DDoS") and a_count < a_target:
                lines.append(l)
                a_count += 1
            if b_count >= b_target and a_count >= a_target:
                break

    with open(dest_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[SUCCESS] Saved {len(lines)-1} rows to {dest_path} (SHA-256: {sha256_file(dest_path)})")
    return dest_path


def acquire_unsw_nb15(target_rows: int = 5000) -> str:
    dest_path = os.path.join(DATA_DIR, "unsw_nb15_sample.csv")
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 10000:
        print(f"[CACHE] UNSW-NB15 already exists at {dest_path}")
        return dest_path

    print("[DOWNLOAD] Streaming UNSW-NB15 sample from HuggingFace...")
    url = "https://huggingface.co/datasets/Mireu-Lab/UNSW-NB15/resolve/main/test.csv"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (PhantomNet ML-8 Auditor)"})

    lines = []
    with urllib.request.urlopen(req, timeout=45) as resp:
        header = resp.readline().decode("utf-8-sig", errors="ignore").strip()
        lines.append(header)
        b_count, a_count = 0, 0
        b_target = int(target_rows * 0.70)
        a_target = target_rows - b_target

        for raw_line in resp:
            l = raw_line.decode("utf-8", errors="ignore").strip()
            if not l:
                continue
            parts = l.split(",")
            if len(parts) >= 45:
                lbl = parts[-1].strip()
                if lbl == "0" and b_count < b_target:
                    lines.append(l)
                    b_count += 1
                elif lbl == "1" and a_count < a_target:
                    lines.append(l)
                    a_count += 1
            if b_count >= b_target and a_count >= a_target:
                break

    with open(dest_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"[SUCCESS] Saved {len(lines)-1} rows to {dest_path} (SHA-256: {sha256_file(dest_path)})")
    return dest_path


if __name__ == "__main__":
    print("=== Starting Phase ML-8 External Dataset Acquisition ===")
    p1 = acquire_nf_ton_iot_v2(5000)
    p2 = acquire_cicids2017(5000)
    p3 = acquire_unsw_nb15(5000)
    print("=== External Dataset Acquisition Complete ===")
