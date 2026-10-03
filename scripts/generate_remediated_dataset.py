"""
PhantomNet Remediated Dataset Generator (v3.0)
==============================================
Generates a scientifically rigorous, zero-leakage honeypot benchmark dataset:
- Exactly 12 clean network flow observables (no threat_score, no label feedback).
- Realistic overlapping statistical distributions between benign and malicious traffic.
- Verified absence of trivial separability (no single feature > 85% accuracy).
- 5,000 total samples with 70:30 class balance (3,500 benign, 1,500 malicious).
"""

import os
import sys
import math
import random
import hashlib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DATA_PATH = os.path.join(PROJECT_ROOT, "data", "remediated_dataset_v3.csv")
BACKEND_DATA_PATH = os.path.join(PROJECT_ROOT, "backend", "ml", "datasets", "labeled_events_remediated.csv")

os.makedirs(os.path.dirname(OUTPUT_DATA_PATH), exist_ok=True)
os.makedirs(os.path.dirname(BACKEND_DATA_PATH), exist_ok=True)

FEATURE_COLUMNS = [
    "packet_length",
    "protocol_encoding",
    "dst_port_class",
    "src_port_ephemeral",
    "event_rate_1m",
    "burst_rate_10s",
    "inter_arrival_mean",
    "inter_arrival_std",
    "packet_size_variance",
    "payload_entropy",
    "unique_dst_ips",
    "unique_dst_ports",
]

def generate_benign_samples(n=3500):
    samples = []
    for _ in range(n):
        # Benign traffic profiles:
        # 1. Web browsing (HTTP/HTTPS) - 55%
        # 2. DNS/NTP/Monitoring - 25%
        # 3. Normal SSH / Admin / File sync - 20%
        p_type = random.choices(["web", "network_svc", "admin_sync"], weights=[0.55, 0.25, 0.20])[0]

        if p_type == "web":
            # Packet length: mix of small ACKs (40-100), GET requests (150-500), and responses (800-1500)
            pkt_len = int(random.choice([
                random.randint(40, 120),
                random.randint(150, 600),
                random.randint(700, 1460)
            ]))
            proto = 1  # TCP
            dst_port_cls = random.choices([1, 2], weights=[0.85, 0.15])[0]  # 80, 443, 8080
            src_eph = 1 if random.random() < 0.98 else 0
            rate_1m = float(np.random.gamma(shape=2.5, scale=2.0)) + 1.0  # ~3 to 12 pkts/min
            burst_10s = int(min(rate_1m, max(1, np.random.poisson(lam=2.0))))
            arr_mean = float(np.random.exponential(scale=6.0)) + 0.1
            arr_std = float(arr_mean * np.random.uniform(0.6, 1.8))  # High natural variance
            size_var = float(np.random.gamma(shape=3.0, scale=8000.0))
            # Entropy of natural HTML/JSON/headers ranges from 2.8 to 4.9
            entropy = float(np.clip(np.random.normal(loc=3.85, scale=0.45), 2.2, 5.0))
            u_ips = 1 if random.random() < 0.92 else 2
            u_ports = 1 if random.random() < 0.88 else random.randint(2, 3)

        elif p_type == "network_svc":
            pkt_len = int(random.choice([
                random.randint(48, 128),   # DNS query
                random.randint(128, 512),  # NTP / SNMP
            ]))
            proto = random.choices([1, 2], weights=[0.3, 0.7])[0]  # TCP or UDP
            dst_port_cls = 1  # 53, 123, 161
            src_eph = 1 if random.random() < 0.90 else 0
            # Some monitoring services poll frequently (10-30 pkts/min)
            is_fast_monitor = random.random() < 0.25
            if is_fast_monitor:
                rate_1m = float(np.random.gamma(shape=6.0, scale=3.0)) + 8.0
                burst_10s = int(max(2, np.random.poisson(lam=4.0)))
            else:
                rate_1m = float(np.random.gamma(shape=1.5, scale=1.5)) + 1.0
                burst_10s = int(max(1, np.random.poisson(lam=1.2)))
            arr_mean = float(np.random.exponential(scale=6.0)) + 0.2
            arr_std = float(arr_mean * np.random.uniform(0.5, 1.5))
            size_var = float(np.random.gamma(shape=1.5, scale=2000.0))
            entropy = float(np.clip(np.random.normal(loc=3.40, scale=0.55), 2.0, 4.8))
            u_ips = 1
            u_ports = 1

        else:  # admin_sync
            pkt_len = int(random.randint(64, 1400))
            proto = 1  # TCP
            dst_port_cls = random.choices([1, 2], weights=[0.7, 0.3])[0]
            src_eph = 1
            # Admin file syncs and CI/CD pipelines generate higher rates (12-35 pkts/min)
            rate_1m = float(np.random.gamma(shape=5.0, scale=3.0)) + 6.0
            burst_10s = int(max(1, np.random.poisson(lam=4.0)))
            arr_mean = float(np.random.exponential(scale=3.0)) + 0.05
            arr_std = float(arr_mean * np.random.uniform(0.4, 1.4))
            size_var = float(np.random.gamma(shape=4.0, scale=12000.0))
            entropy = float(np.clip(np.random.normal(loc=4.10, scale=0.40), 2.5, 5.2))
            u_ips = 1 if random.random() < 0.85 else 2
            u_ports = 1 if random.random() < 0.90 else 2

        samples.append({
            "packet_length": pkt_len,
            "protocol_encoding": proto,
            "dst_port_class": dst_port_cls,
            "src_port_ephemeral": src_eph,
            "event_rate_1m": round(rate_1m, 2),
            "burst_rate_10s": int(burst_10s),
            "inter_arrival_mean": round(arr_mean, 4),
            "inter_arrival_std": round(arr_std, 4),
            "packet_size_variance": round(size_var, 2),
            "payload_entropy": round(entropy, 4),
            "unique_dst_ips": int(u_ips),
            "unique_dst_ports": int(u_ports),
            "label": 0
        })
    return samples

def generate_malicious_samples(n=1500):
    samples = []
    # Attack vectors:
    # 1. SSH Brute Force (rapid small/medium frames, very low timing variance) - 35%
    # 2. Web Application Exploits (SQLi, LFI, RCE - medium/large payloads, higher entropy) - 30%
    # 3. Port Reconnaissance / Scans (rapid probe of multiple ports/IPs) - 20%
    # 4. Data Exfiltration / C2 Tunneling (sustained large packets) - 15%
    attack_counts = {
        "ssh_brute": int(n * 0.35),
        "web_exploit": int(n * 0.30),
        "recon_scan": int(n * 0.20),
        "c2_exfil": n - int(n * 0.35) - int(n * 0.30) - int(n * 0.20)
    }

    for att, count in attack_counts.items():
        for _ in range(count):
            if att == "ssh_brute":
                # SSH brute force: mix of rapid bursts (65%) and stealthy low-and-slow (35%)
                is_stealthy = random.random() < 0.35
                pkt_len = int(random.randint(64, 380))  # SSH protocol frames
                proto = 1  # TCP
                dst_port_cls = random.choices([1, 2], weights=[0.6, 0.4])[0]  # port 22 or 2222
                src_eph = 1
                if is_stealthy:
                    rate_1m = float(np.random.gamma(shape=2.0, scale=2.0)) + 2.0  # 3-8 pkts/min
                    burst_10s = int(max(1, np.random.poisson(lam=1.5)))
                    arr_mean = float(np.random.uniform(5.0, 18.0))
                else:
                    rate_1m = float(np.random.gamma(shape=6.0, scale=3.0)) + 10.0  # 15-35 pkts/min
                    burst_10s = int(max(3, np.random.poisson(lam=5.5)))
                    arr_mean = float(np.random.uniform(0.1, 1.2))
                # Mechanized timing: low relative variance compared to humans
                arr_std = float(arr_mean * np.random.uniform(0.04, 0.30))
                size_var = float(np.random.gamma(shape=1.5, scale=400.0))
                entropy = float(np.clip(np.random.normal(loc=3.25, scale=0.40), 2.1, 4.6))
                u_ips = 1
                u_ports = 1

            elif att == "web_exploit":
                # SQLi / LFI / RCE payloads: larger payloads, special characters
                pkt_len = int(random.randint(250, 1500))
                proto = 1  # TCP
                dst_port_cls = random.choices([1, 2], weights=[0.75, 0.25])[0]
                src_eph = 1
                rate_1m = float(np.random.gamma(shape=3.0, scale=2.5)) + 2.0  # moderate rate
                burst_10s = int(max(1, np.random.poisson(lam=2.5)))
                arr_mean = float(np.random.exponential(scale=4.5)) + 0.2
                arr_std = float(arr_mean * np.random.uniform(0.3, 1.2))
                size_var = float(np.random.gamma(shape=3.5, scale=14000.0))
                # High entropy due to encoding (%20, hex, base64, special syntax)
                entropy = float(np.clip(np.random.normal(loc=4.35, scale=0.45), 3.0, 5.4))
                u_ips = 1 if random.random() < 0.85 else 2
                u_ports = 1 if random.random() < 0.75 else 2

            elif att == "recon_scan":
                # Port scan: mix of fast SYN sweep (60%) and slow stealthy scan (40%)
                is_slow_scan = random.random() < 0.40
                pkt_len = int(random.choice([40, 44, 52, 60, 64]))  # SYN packets
                proto = random.choices([1, 2, 3], weights=[0.8, 0.15, 0.05])[0]
                dst_port_cls = random.choice([1, 2, 3])  # sweeps all port classes
                src_eph = 1 if random.random() < 0.95 else 0
                if is_slow_scan:
                    rate_1m = float(np.random.gamma(shape=2.5, scale=2.0)) + 3.0  # 4-10 pkts/min
                    burst_10s = int(max(1, np.random.poisson(lam=2.0)))
                    arr_mean = float(np.random.uniform(4.0, 15.0))
                else:
                    rate_1m = float(np.random.gamma(shape=8.0, scale=3.0)) + 15.0  # 20-45 pkts/min
                    burst_10s = int(max(5, np.random.poisson(lam=8.0)))
                    arr_mean = float(np.random.uniform(0.05, 0.5))
                arr_std = float(arr_mean * np.random.uniform(0.02, 0.25))  # ultra-tight timing
                size_var = float(random.choice([0.0, 4.0, 16.0]))  # identical syn sizes
                entropy = float(np.clip(np.random.normal(loc=2.40, scale=0.40), 1.5, 3.8))
                u_ips = random.randint(2, 6)
                u_ports = random.randint(4, 25)

            else:  # c2_exfil
                # Large payloads, sustained transfer
                pkt_len = int(random.randint(1000, 1500))
                proto = 1  # TCP
                dst_port_cls = random.choices([1, 2, 3], weights=[0.5, 0.3, 0.2])[0]
                src_eph = 1
                rate_1m = float(np.random.gamma(shape=6.0, scale=3.0)) + 10.0
                burst_10s = int(max(2, np.random.poisson(lam=5.0)))
                arr_mean = float(np.random.uniform(0.2, 1.8))
                arr_std = float(arr_mean * np.random.uniform(0.1, 0.6))
                size_var = float(np.random.gamma(shape=2.0, scale=3000.0))
                # Encrypted / compressed exfil data has high entropy
                entropy = float(np.clip(np.random.normal(loc=4.75, scale=0.30), 3.8, 5.6))
                u_ips = 1
                u_ports = 1

            samples.append({
                "packet_length": pkt_len,
                "protocol_encoding": proto,
                "dst_port_class": dst_port_cls,
                "src_port_ephemeral": src_eph,
                "event_rate_1m": round(rate_1m, 2),
                "burst_rate_10s": int(burst_10s),
                "inter_arrival_mean": round(arr_mean, 4),
                "inter_arrival_std": round(arr_std, 4),
                "packet_size_variance": round(size_var, 2),
                "payload_entropy": round(entropy, 4),
                "unique_dst_ips": int(u_ips),
                "unique_dst_ports": int(u_ports),
                "label": 1
            })

    return samples

def audit_generated_dataset(df):
    print("\n--- AUDITING GENERATED BENCHMARK DATASET ---")
    y = df["label"]
    n_total = len(df)
    n_benign = sum(y == 0)
    n_malicious = sum(y == 1)
    print(f"Total samples: {n_total}")
    print(f"Benign: {n_benign} ({n_benign/n_total*100:.1f}%), Malicious: {n_malicious} ({n_malicious/n_total*100:.1f}%)")

    # Check NaNs / Infs
    assert df.isna().sum().sum() == 0, "Error: NaN values found!"
    assert np.isinf(df.select_dtypes(include=np.number)).sum().sum() == 0, "Error: Inf values found!"

    # Single-feature accuracy test (must be < 85%)
    flagged = []
    print("\nSingle-Feature Threshold Accuracy Test:")
    for col in FEATURE_COLUMNS:
        col_data = df[col]
        b_mean = col_data[y == 0].mean()
        m_mean = col_data[y == 1].mean()
        thresh = (b_mean + m_mean) / 2.0
        
        preds = (col_data > thresh).astype(int) if m_mean > b_mean else (col_data < thresh).astype(int)
        acc = accuracy_score(y, preds)
        
        b_range = [round(col_data[y == 0].min(), 2), round(col_data[y == 0].max(), 2)]
        m_range = [round(col_data[y == 1].min(), 2), round(col_data[y == 1].max(), 2)]
        overlap = not (b_range[1] < m_range[0] or m_range[1] < b_range[0])
        
        print(f"  {col:<24}: Acc={acc*100:5.2f}% | Overlap={overlap} | B_Range={b_range} | M_Range={m_range}")
        
        if acc >= 0.85 or not overlap:
            flagged.append((col, acc, overlap))

    if flagged:
        print(f"\n[FAILURE] Features exceeding 85% accuracy or lacking overlap: {flagged}")
        return False
    else:
        print("\n[SUCCESS] All features have overlapping distributions and accuracy < 85%. No trivial separability!")
        return True

def main():
    print("Generating Remediated Dataset v3.0...")
    benign = generate_benign_samples(3500)
    malicious = generate_malicious_samples(1500)
    
    all_samples = benign + malicious
    random.shuffle(all_samples)
    
    df = pd.DataFrame(all_samples)
    
    # Audit
    valid = audit_generated_dataset(df)
    if not valid:
        sys.exit(1)
        
    df.to_csv(OUTPUT_DATA_PATH, index=False)
    df.to_csv(BACKEND_DATA_PATH, index=False)
    
    sha256_hash = hashlib.sha256(open(OUTPUT_DATA_PATH, "rb").read()).hexdigest()
    print(f"\nSaved dataset to: {OUTPUT_DATA_PATH}")
    print(f"Saved replica to: {BACKEND_DATA_PATH}")
    print(f"Dataset SHA-256: {sha256_hash}")

if __name__ == "__main__":
    main()
