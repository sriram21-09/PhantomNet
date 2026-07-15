#!/usr/bin/env python3
"""
scripts/ollama_benchmark.py
----------------------------
PhantomNet — Ollama Inference Benchmark Script

Measures cold-start load time, prompt evaluation latency, and generation
throughput (tokens/sec) for all models available in the local Ollama daemon.

Usage:
    python scripts/ollama_benchmark.py                  # Default: localhost:11434
    python scripts/ollama_benchmark.py --host http://localhost:11434
    python scripts/ollama_benchmark.py --models mistral phi3:3.8b
    python scripts/ollama_benchmark.py --runs 5          # Average over 5 runs

Requirements:
    - Ollama container running (docker compose up -d ollama)
    - Target models pre-pulled (docker exec phantomnet_ollama ollama pull mistral)
    - Python 3.9+ with 'requests' installed (pip install requests)
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from typing import Any, Dict, List, Optional

import codecs
import io

try:
    import requests
except ImportError:
    print("ERROR: 'requests' package is required. Install with: pip install requests")
    sys.exit(1)

# Ensure UTF-8 output on Windows terminals to prevent charmap encoding errors with emojis
if hasattr(sys.stdout, "buffer"):
    sys.stdout = codecs.getwriter("utf-8")(sys.stdout.buffer, "replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = codecs.getwriter("utf-8")(sys.stderr.buffer, "replace")


# ---------------------------------------------------------------------------
# Benchmark prompts — representative of PhantomNet Sentinel workloads
# ---------------------------------------------------------------------------
BENCHMARK_PROMPTS = [
    {
        "name": "Short (Honeypot Definition)",
        "prompt": (
            "Explain what a honeypot healthcheck filter does in cybersecurity "
            "in exactly 2 sentences."
        ),
    },
    {
        "name": "Medium (Incident Summary)",
        "prompt": (
            "You are a cybersecurity analyst. Analyze the following: An SSH brute "
            "force attack from 192.168.1.100 targeting port 22 with 450 failed "
            "login attempts over 15 minutes. The attack used a dictionary of 120 "
            "unique usernames. Provide a 2-paragraph incident summary in Markdown."
        ),
    },
    {
        "name": "Long (Threat Report)",
        "prompt": (
            "You are a senior incident response analyst. Write a detailed threat "
            "analysis report for the following campaign:\n"
            "- Attack Type: SQL Injection\n"
            "- Source IPs: 10.0.0.5, 10.0.0.12, 10.0.0.33\n"
            "- Target: HTTP honeypot on port 8080\n"
            "- Payloads detected: UNION SELECT, OR 1=1, DROP TABLE\n"
            "- Event count: 1,250 over 3 hours\n"
            "- MITRE ATT&CK: T1190 (Exploit Public-Facing Application)\n\n"
            "Include: Executive Summary, Technical Analysis, IOC Table, "
            "Containment Steps, and Recommendations. Format in Markdown."
        ),
    },
]


def check_ollama_health(base_url: str) -> bool:
    """Verify the Ollama daemon is reachable."""
    try:
        resp = requests.get(base_url, timeout=5)
        return resp.status_code == 200
    except requests.ConnectionError:
        return False


def list_models(base_url: str) -> List[str]:
    """List all models available in the Ollama instance."""
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        pass
    return []


def run_inference(
    base_url: str, model: str, prompt: str
) -> Optional[Dict[str, Any]]:
    """Send a non-streaming inference request and return timing metrics."""
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.15,
            "top_p": 0.9,
            "num_predict": 512,
        },
    }

    wall_start = time.perf_counter()
    try:
        resp = requests.post(
            f"{base_url}/api/generate",
            json=payload,
            timeout=120,
        )
        wall_end = time.perf_counter()

        if resp.status_code != 200:
            print(f"  ⚠ HTTP {resp.status_code}: {resp.text[:200]}")
            return None

        data = resp.json()

        # Extract Ollama timing metrics (nanoseconds → human-readable)
        eval_count = data.get("eval_count", 0)
        eval_duration_ns = data.get("eval_duration", 0)
        prompt_eval_duration_ns = data.get("prompt_eval_duration", 0)
        load_duration_ns = data.get("load_duration", 0)
        total_duration_ns = data.get("total_duration", 0)

        # Calculate derived metrics
        eval_duration_s = eval_duration_ns / 1e9 if eval_duration_ns else 0
        tokens_per_sec = (
            eval_count / eval_duration_s if eval_duration_s > 0 else 0
        )
        latency_per_token_ms = (
            (eval_duration_ns / eval_count) / 1e6 if eval_count > 0 else 0
        )

        return {
            "model": model,
            "eval_count": eval_count,
            "eval_duration_ms": eval_duration_ns / 1e6,
            "prompt_eval_duration_ms": prompt_eval_duration_ns / 1e6,
            "load_duration_ms": load_duration_ns / 1e6,
            "total_duration_ms": total_duration_ns / 1e6,
            "wall_time_s": wall_end - wall_start,
            "tokens_per_sec": round(tokens_per_sec, 2),
            "latency_per_token_ms": round(latency_per_token_ms, 2),
            "response_length": len(data.get("response", "")),
        }

    except requests.Timeout:
        print("  ⚠ Request timed out (120s limit)")
        return None
    except requests.ConnectionError:
        print("  ⚠ Connection refused — is Ollama running?")
        return None
    except Exception as exc:
        print(f"  ⚠ Unexpected error: {exc}")
        return None


def print_separator(char: str = "─", width: int = 80) -> None:
    """Print a horizontal separator."""
    print(char * width)


def run_benchmark(
    base_url: str,
    models: List[str],
    num_runs: int = 3,
) -> Dict[str, List[Dict[str, Any]]]:
    """Execute the full benchmark suite."""

    print()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║         PhantomNet — Ollama Inference Benchmark Suite           ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()
    print(f"  Target:    {base_url}")
    print(f"  Models:    {', '.join(models)}")
    print(f"  Runs:      {num_runs} per prompt")
    print(f"  Prompts:   {len(BENCHMARK_PROMPTS)}")
    print()
    print_separator("═")

    all_results: Dict[str, List[Dict[str, Any]]] = {}

    for model in models:
        print(f"\n🔄 Benchmarking model: {model}")
        print_separator()

        model_results: List[Dict[str, Any]] = []

        for prompt_info in BENCHMARK_PROMPTS:
            prompt_name = prompt_info["name"]
            prompt_text = prompt_info["prompt"]

            print(f"\n  📝 Prompt: {prompt_name}")
            run_metrics: List[Dict[str, Any]] = []

            for run_idx in range(num_runs):
                print(f"    Run {run_idx + 1}/{num_runs}...", end=" ", flush=True)
                result = run_inference(base_url, model, prompt_text)

                if result:
                    run_metrics.append(result)
                    print(
                        f"✓ {result['tokens_per_sec']} tok/s | "
                        f"{result['eval_count']} tokens | "
                        f"{result['latency_per_token_ms']} ms/tok | "
                        f"load={result['load_duration_ms']:.0f}ms"
                    )
                else:
                    print("✗ Failed")

            # Aggregate results for this prompt
            if run_metrics:
                avg_result = {
                    "model": model,
                    "prompt_name": prompt_name,
                    "runs": len(run_metrics),
                    "avg_tokens_per_sec": round(
                        statistics.mean(r["tokens_per_sec"] for r in run_metrics), 2
                    ),
                    "avg_latency_per_token_ms": round(
                        statistics.mean(
                            r["latency_per_token_ms"] for r in run_metrics
                        ),
                        2,
                    ),
                    "avg_eval_count": round(
                        statistics.mean(r["eval_count"] for r in run_metrics), 1
                    ),
                    "avg_prompt_eval_ms": round(
                        statistics.mean(
                            r["prompt_eval_duration_ms"] for r in run_metrics
                        ),
                        1,
                    ),
                    "avg_load_ms": round(
                        statistics.mean(r["load_duration_ms"] for r in run_metrics),
                        1,
                    ),
                    "avg_wall_time_s": round(
                        statistics.mean(r["wall_time_s"] for r in run_metrics), 2
                    ),
                }

                if len(run_metrics) > 1:
                    avg_result["stddev_tokens_per_sec"] = round(
                        statistics.stdev(
                            r["tokens_per_sec"] for r in run_metrics
                        ),
                        2,
                    )

                model_results.append(avg_result)

        all_results[model] = model_results

    # Print summary table
    print("\n")
    print_separator("═")
    print("\n📊 BENCHMARK SUMMARY")
    print_separator()

    header = (
        f"{'Model':<18} {'Prompt':<28} {'Tok/s':>8} {'ms/tok':>8} "
        f"{'Tokens':>8} {'Prompt':>10} {'Load':>10} {'Wall':>8}"
    )
    print(header)
    print_separator("─")

    for model, results in all_results.items():
        for r in results:
            row = (
                f"{r['model']:<18} {r['prompt_name']:<28} "
                f"{r['avg_tokens_per_sec']:>8.1f} "
                f"{r['avg_latency_per_token_ms']:>8.1f} "
                f"{r['avg_eval_count']:>8.0f} "
                f"{r['avg_prompt_eval_ms']:>9.0f}ms "
                f"{r['avg_load_ms']:>9.0f}ms "
                f"{r['avg_wall_time_s']:>7.1f}s"
            )
            print(row)
        print_separator("·")

    print()
    return all_results


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="PhantomNet Ollama Inference Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default="http://localhost:11434",
        help="Ollama base URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=None,
        help="Models to benchmark (default: all pulled models)",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        help="Number of runs per prompt (default: 3)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Save results to JSON file",
    )
    args = parser.parse_args()

    # Health check
    print(f"🔍 Checking Ollama at {args.host}...")
    if not check_ollama_health(args.host):
        print(f"❌ Cannot reach Ollama at {args.host}")
        print("   Ensure the container is running: docker compose up -d ollama")
        sys.exit(1)
    print("✅ Ollama is responsive")

    # Resolve models
    if args.models:
        models = args.models
    else:
        models = list_models(args.host)
        if not models:
            print("❌ No models found. Pull a model first:")
            print("   docker exec -it phantomnet_ollama ollama pull mistral")
            sys.exit(1)
        print(f"📦 Detected models: {', '.join(models)}")

    # Run benchmarks
    results = run_benchmark(args.host, models, num_runs=args.runs)

    # Save results if requested
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"💾 Results saved to {args.output}")


if __name__ == "__main__":
    main()
