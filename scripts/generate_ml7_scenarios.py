#!/usr/bin/env python3
"""
PhantomNet Phase ML-7: Independent Synthetic Robustness Scenario Generator
==========================================================================
Generates 12 distinct, scientifically defensible synthetic distribution-shift
scenarios under independent parameterizations and alternative distribution
families (Pareto, Log-normal, Weibull, Gaussian mixtures, feature dropouts).

Does NOT alter labels arbitrarily.
All scenarios strictly adhere to the CANONICAL_FEATURE_NAMES (12D-v1) contract.
Outputs saved to: data/robustness_scenarios/
Metadata manifest: experiments/results/ml7_scenario_manifest.json
"""

import os
import sys
import json
import hashlib
import numpy as np
import pandas as pd
from typing import Dict, Any, List

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)

from backend.ml.config.feature_schema import CANONICAL_FEATURE_NAMES, SCHEMA_VERSION

SCENARIOS_DIR = os.path.join(PROJECT_ROOT, "data", "robustness_scenarios")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "experiments", "results")
os.makedirs(SCENARIOS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

SCENARIO_SEED = 777
np.random.seed(SCENARIO_SEED)

def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def generate_base_flow(n: int, p_malicious: float = 0.30, rng: np.random.Generator = None) -> pd.DataFrame:
    """Generates standard baseline synthetic flow for transformation."""
    if rng is None:
        rng = np.random.default_rng(SCENARIO_SEED)
        
    n_mal = int(n * p_malicious)
    n_ben = n - n_mal
    
    # Benign base
    b_pkt_len = rng.choice([64, 128, 512, 1420], size=n_ben, p=[0.3, 0.3, 0.2, 0.2]) + rng.normal(0, 10, size=n_ben)
    b_proto = rng.choice([1, 2], size=n_ben, p=[0.85, 0.15])
    b_dst_cls = rng.choice([1, 2, 3], size=n_ben, p=[0.7, 0.2, 0.1])
    b_src_eph = rng.choice([0, 1], size=n_ben, p=[0.05, 0.95])
    b_rate_1m = rng.gamma(shape=2.5, scale=2.0, size=n_ben) + 1.0
    b_burst_10s = np.clip(rng.poisson(lam=2.0, size=n_ben), 1, 10)
    b_arr_mean = rng.exponential(scale=5.0, size=n_ben) + 0.1
    b_arr_std = b_arr_mean * rng.uniform(0.6, 1.5, size=n_ben)
    b_size_var = rng.gamma(shape=3.0, scale=6000.0, size=n_ben)
    b_entropy = np.clip(rng.normal(loc=3.8, scale=0.4, size=n_ben), 2.0, 5.0)
    b_u_ips = np.ones(n_ben)
    b_u_ports = rng.choice([1, 2], size=n_ben, p=[0.9, 0.1])
    b_labels = np.zeros(n_ben, dtype=int)
    
    # Malicious base
    m_pkt_len = rng.choice([48, 80, 750, 1460], size=n_mal, p=[0.4, 0.3, 0.15, 0.15]) + rng.normal(0, 15, size=n_mal)
    m_proto = rng.choice([1, 2, 3], size=n_mal, p=[0.75, 0.20, 0.05])
    m_dst_cls = rng.choice([1, 2, 3], size=n_mal, p=[0.4, 0.4, 0.2])
    m_src_eph = rng.choice([0, 1], size=n_mal, p=[0.1, 0.9])
    m_rate_1m = rng.gamma(shape=5.0, scale=4.0, size=n_mal) + 5.0
    m_burst_10s = np.clip(rng.poisson(lam=5.0, size=n_mal), 1, 25)
    m_arr_mean = rng.exponential(scale=1.5, size=n_mal) + 0.01
    m_arr_std = m_arr_mean * rng.uniform(0.1, 0.8, size=n_mal)
    m_size_var = rng.gamma(shape=2.0, scale=4000.0, size=n_mal)
    m_entropy = np.clip(rng.normal(loc=5.5, scale=0.8, size=n_mal), 3.0, 7.5)
    m_u_ips = rng.choice([1, 2, 3, 5], size=n_mal, p=[0.5, 0.25, 0.15, 0.10])
    m_u_ports = rng.choice([1, 2, 4, 8], size=n_mal, p=[0.4, 0.3, 0.2, 0.1])
    m_labels = np.ones(n_mal, dtype=int)
    
    cols = {
        "packet_length": np.concatenate([b_pkt_len, m_pkt_len]),
        "protocol_encoding": np.concatenate([b_proto, m_proto]),
        "dst_port_class": np.concatenate([b_dst_cls, m_dst_cls]),
        "src_port_ephemeral": np.concatenate([b_src_eph, m_src_eph]),
        "event_rate_1m": np.concatenate([b_rate_1m, m_rate_1m]),
        "burst_rate_10s": np.concatenate([b_burst_10s, m_burst_10s]),
        "inter_arrival_mean": np.concatenate([b_arr_mean, m_arr_mean]),
        "inter_arrival_std": np.concatenate([b_arr_std, m_arr_std]),
        "packet_size_variance": np.concatenate([b_size_var, m_size_var]),
        "payload_entropy": np.concatenate([b_entropy, m_entropy]),
        "unique_dst_ips": np.concatenate([b_u_ips, m_u_ips]),
        "unique_dst_ports": np.concatenate([b_u_ports, m_u_ports]),
        "label": np.concatenate([b_labels, m_labels])
    }
    
    df = pd.DataFrame(cols)
    # Shuffle rows deterministically
    df = df.sample(frac=1.0, random_state=rng.integers(1, 10000)).reset_index(drop=True)
    return df

def generate_all_scenarios() -> List[Dict[str, Any]]:
    print("Generating 12 Independent Synthetic Robustness Scenarios...")
    manifest = []
    
    scenarios_def = [
        {
            "id": "SCEN-01",
            "name": "high_event_rate_flooding",
            "description": "High-throughput volumetric condition; event rate amplified 3.5x, burst rates elevated, inter-arrivals compressed.",
            "shift_family": "Covariate Shift (Traffic Volume)",
            "generator": lambda rng: shift_high_rate(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-02",
            "name": "low_and_slow_stealth",
            "description": "Low-and-slow stealth campaign; event rates reduced by 60%, inter-arrival means stretched 3x, zero bursts.",
            "shift_family": "Covariate Shift (Evasion Timing)",
            "generator": lambda rng: shift_low_slow(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-03",
            "name": "heavy_tailed_packet_sizes",
            "description": "Heavy-tailed payload size distribution sampled from Pareto distribution (alpha=1.8), simulating bulk data exfiltration.",
            "shift_family": "Distribution Family Shift (Packet Size Pareto)",
            "generator": lambda rng: shift_heavy_tail(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-04",
            "name": "bimodal_jitter_timing",
            "description": "Bimodal inter-arrival timing distribution with high timing jitter, simulating multi-hop proxy delays.",
            "shift_family": "Distribution Family Shift (Bimodal Timing)",
            "generator": lambda rng: shift_bimodal_jitter(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-05",
            "name": "protocol_mix_udp_dominance",
            "description": "Protocol drift towards UDP/DNS reflection dominance (protocol_encoding=2 dominant, dst_port_class=1).",
            "shift_family": "Covariate Shift (Protocol Mix)",
            "generator": lambda rng: shift_udp_dominance(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-06",
            "name": "wide_subnet_horizontal_scan",
            "description": "Horizontal network scan with elevated destination IP and port diversity (unique_dst_ips up to 15).",
            "shift_family": "Covariate Shift (Target Diversity)",
            "generator": lambda rng: shift_wide_scan(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-07",
            "name": "high_entropy_c2_tunneling",
            "description": "Encrypted C2 / TLS / DNS tunneling payload simulation with payload_entropy elevated to 7.0 - 7.9.",
            "shift_family": "Distribution Shift (Payload Encryption)",
            "generator": lambda rng: shift_high_entropy(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-08",
            "name": "sensor_noise_quantization",
            "description": "Bounded telemetry measurement noise (+-15% Gaussian jitter) and coarse rounding/quantization.",
            "shift_family": "Measurement Noise / Telemetry Distortion",
            "generator": lambda rng: shift_sensor_noise(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-09",
            "name": "feature_missingness_dropout",
            "description": "Lossy tap simulation: 10% random feature missingness imputed to 0.0.",
            "shift_family": "Missing Data (Lossy Telemetry)",
            "generator": lambda rng: shift_feature_dropout(generate_base_flow(1000, rng=rng), rng)
        },
        {
            "id": "SCEN-10",
            "name": "class_prior_extreme_rare_attack",
            "description": "Severe operational class imbalance: 95% benign (950) vs 5% malicious (50).",
            "shift_family": "Prior Probability Shift (Rare Attack)",
            "generator": lambda rng: generate_base_flow(1000, p_malicious=0.05, rng=rng)
        },
        {
            "id": "SCEN-11",
            "name": "class_prior_attack_storm",
            "description": "Severe attack saturation: 50% benign (500) vs 50% malicious (500).",
            "shift_family": "Prior Probability Shift (Attack Storm)",
            "generator": lambda rng: generate_base_flow(1000, p_malicious=0.50, rng=rng)
        },
        {
            "id": "SCEN-12",
            "name": "composite_multivariate_stress",
            "description": "Multi-dimensional compound stress condition: heavy-tailed sizes, timing jitter, elevated entropy, and sensor noise.",
            "shift_family": "Compound Multivariate Covariate Shift",
            "generator": lambda rng: shift_composite_stress(generate_base_flow(1000, rng=rng), rng)
        }
    ]

    for idx, sc in enumerate(scenarios_def):
        rng = np.random.default_rng(SCENARIO_SEED + idx * 17)
        df_sc = sc["generator"](rng)
        
        # Verify 12D schema and non-nulls
        assert tuple(df_sc.columns[:12]) == CANONICAL_FEATURE_NAMES
        assert df_sc.isna().sum().sum() == 0
        assert len(df_sc) == 1000
        
        filename = f"scenario_{sc['id'].lower().replace('-', '_')}_{sc['name']}.csv"
        filepath = os.path.join(SCENARIOS_DIR, filename)
        df_sc.to_csv(filepath, index=False)
        
        sha = compute_sha256(filepath)
        n_ben = int((df_sc["label"] == 0).sum())
        n_mal = int((df_sc["label"] == 1).sum())
        
        entry = {
            "scenario_id": sc["id"],
            "name": sc["name"],
            "description": sc["description"],
            "shift_family": sc["shift_family"],
            "filename": filename,
            "relative_path": f"data/robustness_scenarios/{filename}",
            "sha256": sha,
            "row_count": len(df_sc),
            "class_distribution": {"benign": n_ben, "malicious": n_mal, "malicious_ratio": float(n_mal / len(df_sc))},
            "feature_means": {col: float(df_sc[col].mean()) for col in CANONICAL_FEATURE_NAMES},
            "feature_stds": {col: float(df_sc[col].std()) for col in CANONICAL_FEATURE_NAMES}
        }
        manifest.append(entry)
        print(f"  [+] Created {sc['id']}: {sc['name']} ({len(df_sc)} rows, SHA: {sha[:12]})")

    out_manifest = os.path.join(RESULTS_DIR, "ml7_scenario_manifest.json")
    with open(out_manifest, "w", encoding="utf-8") as f:
        json.dump({"metadata": {"generator_version": "v1.0.0-independent", "seed": SCENARIO_SEED, "count": len(manifest)}, "scenarios": manifest}, f, indent=2)
    print(f"Saved scenario manifest: {out_manifest}")
    return manifest

# Transformation implementations
def shift_high_rate(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    d["event_rate_1m"] = d["event_rate_1m"] * rng.uniform(2.5, 4.5, size=len(d))
    d["burst_rate_10s"] = np.clip(d["burst_rate_10s"] * rng.uniform(1.8, 3.0, size=len(d)), 1, 50)
    d["inter_arrival_mean"] = np.clip(d["inter_arrival_mean"] / rng.uniform(2.0, 4.0, size=len(d)), 0.001, 10.0)
    d["inter_arrival_std"] = d["inter_arrival_mean"] * rng.uniform(0.2, 0.8, size=len(d))
    return d

def shift_low_slow(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    d["event_rate_1m"] = np.clip(d["event_rate_1m"] * 0.35, 0.1, 5.0)
    d["burst_rate_10s"] = 1
    d["inter_arrival_mean"] = d["inter_arrival_mean"] * rng.uniform(2.5, 5.0, size=len(d)) + 2.0
    d["inter_arrival_std"] = d["inter_arrival_mean"] * rng.uniform(0.8, 2.0, size=len(d))
    return d

def shift_heavy_tail(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    # Sample from Pareto (alpha=1.8, scale=120)
    pareto_sizes = (rng.pareto(a=1.8, size=len(d)) + 1.0) * 120.0
    d["packet_length"] = np.clip(pareto_sizes, 40.0, 9000.0)  # up to jumbo frames
    d["packet_size_variance"] = d["packet_size_variance"] * rng.uniform(2.0, 5.0, size=len(d))
    return d

def shift_bimodal_jitter(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    mode = rng.choice([1, 2], size=len(d), p=[0.6, 0.4])
    timing = np.where(mode == 1, rng.exponential(scale=0.5, size=len(d)), rng.normal(loc=8.0, scale=1.5, size=len(d)))
    d["inter_arrival_mean"] = np.clip(np.abs(timing), 0.01, 20.0)
    d["inter_arrival_std"] = d["inter_arrival_mean"] * rng.uniform(1.2, 2.5, size=len(d))
    return d

def shift_udp_dominance(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    d["protocol_encoding"] = rng.choice([2, 3], size=len(d), p=[0.85, 0.15])  # UDP / ICMP
    d["dst_port_class"] = rng.choice([1, 2], size=len(d), p=[0.80, 0.20])
    return d

def shift_wide_scan(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    d["unique_dst_ips"] = np.clip(d["unique_dst_ips"] * rng.choice([2, 4, 8, 15], size=len(d), p=[0.3, 0.4, 0.2, 0.1]), 1, 30)
    d["unique_dst_ports"] = np.clip(d["unique_dst_ports"] * rng.choice([2, 5, 10], size=len(d), p=[0.4, 0.4, 0.2]), 1, 20)
    return d

def shift_high_entropy(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    d["payload_entropy"] = np.clip(rng.normal(loc=7.4, scale=0.35, size=len(d)), 6.5, 7.99)
    return d

def shift_sensor_noise(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    for col in ["packet_length", "event_rate_1m", "inter_arrival_mean", "packet_size_variance"]:
        noise = rng.normal(loc=1.0, scale=0.15, size=len(d))
        d[col] = np.clip(d[col] * noise, 0.01, None)
    # Round to coarse units
    d["event_rate_1m"] = np.round(d["event_rate_1m"], 0)
    d["inter_arrival_mean"] = np.round(d["inter_arrival_mean"], 1)
    return d

def shift_feature_dropout(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = df.copy()
    numeric_cols = [c for c in CANONICAL_FEATURE_NAMES if c not in ["protocol_encoding", "dst_port_class"]]
    for col in numeric_cols:
        mask = rng.random(size=len(d)) < 0.10
        d.loc[mask, col] = 0.0
    return d

def shift_composite_stress(df: pd.DataFrame, rng: np.random.Generator) -> pd.DataFrame:
    d = shift_heavy_tail(df, rng)
    d = shift_bimodal_jitter(d, rng)
    d = shift_high_entropy(d, rng)
    d = shift_sensor_noise(d, rng)
    return d

if __name__ == "__main__":
    generate_all_scenarios()
