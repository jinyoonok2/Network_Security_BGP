"""
Research 11.1: Partial Deployment Curve

Models incremental ASPA adoption by subsampling the CAIDA AS-relationship
dataset at 10%, 20%, ..., 100% and measuring the leak detection rate at
each level.

Produces:
  - output/partial_deployment_stats.json
  - output/charts/partial_deployment_curve.png
"""

import csv
import json
import os
import random
import sys
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aspa_cache import ASPACache
from aspa_verifier import verify_as_path, ASPAResult
from config import BASE_DIR, DATA_DIR, OUTPUT_DIR, CHARTS_DIR, load_ingested_routes


def build_subsampled_cache(full_cache, fraction, seed=42):
    """
    Create a new ASPACache containing only `fraction` of the full cache's
    customer ASNs (selected randomly).
    """
    rng = random.Random(seed)
    all_customers = list(full_cache.records.keys())
    k = max(1, int(len(all_customers) * fraction))
    selected = set(rng.sample(all_customers, k))

    sub = ASPACache()
    sub.source = f"caida-{int(fraction*100)}pct"
    for cust in selected:
        sub.records[cust] = full_cache.records[cust]
    # Keep all peer relationships (peers don't "deploy" ASPA the same way)
    sub.peers = full_cache.peers
    return sub


def sweep(input_csv, full_cache, steps=None):
    """
    Run ASPA verification at each deployment level and return results.
    """
    if steps is None:
        steps = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]

    # Pre-load all routes into memory (avoid re-reading CSV 10 times)
    print("  Loading routes into memory …")
    routes = list(load_ingested_routes(input_csv))
    print(f"  {len(routes):,} routes loaded\n")

    results = []
    for frac in steps:
        pct = int(frac * 100)
        cache = build_subsampled_cache(full_cache, frac)
        n_records = len(cache.records)

        counts = {"valid": 0, "invalid": 0, "unknown": 0}
        t0 = time.time()
        for route in routes:
            result, _ = verify_as_path(route["as_path"], cache)
            counts[result.value] += 1
        elapsed = time.time() - t0

        total = sum(counts.values())
        detection_rate = 100 * counts["invalid"] / total if total else 0
        coverage = 100 * (counts["valid"] + counts["invalid"]) / total if total else 0

        row = {
            "deployment_pct": pct,
            "aspa_records": n_records,
            "total": total,
            "valid": counts["valid"],
            "invalid": counts["invalid"],
            "unknown": counts["unknown"],
            "detection_rate_pct": round(detection_rate, 2),
            "coverage_pct": round(coverage, 2),
            "elapsed_s": round(elapsed, 1),
        }
        results.append(row)
        print(f"  {pct:>3d}% deployment  │  {n_records:>6,} records  │  "
              f"leaks {detection_rate:5.1f}%  │  coverage {coverage:5.1f}%  │  {elapsed:.1f}s")

    return results


def plot_curve(results):
    """Generate the partial deployment curve chart."""
    os.makedirs(CHARTS_DIR, exist_ok=True)

    pcts = [r["deployment_pct"] for r in results]
    detection = [r["detection_rate_pct"] for r in results]
    coverage = [r["coverage_pct"] for r in results]

    fig, ax1 = plt.subplots(figsize=(10, 6))

    color1 = "#e74c3c"
    color2 = "#3498db"

    ax1.plot(pcts, detection, "o-", color=color1, linewidth=2.5, markersize=8,
             label="Leak Detection Rate")
    ax1.set_xlabel("ASPA Deployment (%)", fontsize=13)
    ax1.set_ylabel("Leak Detection Rate (%)", fontsize=13, color=color1)
    ax1.tick_params(axis="y", labelcolor=color1)
    ax1.set_xlim(5, 105)
    ax1.set_xticks(pcts)

    ax2 = ax1.twinx()
    ax2.plot(pcts, coverage, "s--", color=color2, linewidth=2, markersize=7,
             label="ASPA Coverage")
    ax2.set_ylabel("Coverage Rate (%)", fontsize=13, color=color2)
    ax2.tick_params(axis="y", labelcolor=color2)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="center right", fontsize=11)

    ax1.set_title("ASPA Partial Deployment: Leak Detection vs. Adoption Level",
                  fontsize=14, fontweight="bold")
    ax1.grid(True, alpha=0.3)

    fig.tight_layout()
    out_path = os.path.join(CHARTS_DIR, "partial_deployment_curve.png")
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"\n  Chart saved: {out_path}")
    return out_path


def main():
    input_csv = os.path.join(OUTPUT_DIR, "ingested_updates.csv")
    if not os.path.exists(input_csv):
        print("ERROR: Run Phase 2 (ingest.py) first.")
        sys.exit(1)

    print("=" * 65)
    print("RESEARCH 11.1: Partial Deployment Curve")
    print("=" * 65)

    # Build full CAIDA cache
    print("\nLoading full CAIDA ASPA cache …")
    full_cache = ASPACache()
    caida_path = os.path.join(DATA_DIR, "20240101.as-rel2.txt.bz2")
    n = full_cache.load_from_caida_relationships(caida_path)
    print(f"  {n:,} customer ASNs in full cache\n")

    # Sweep
    print("Running deployment sweep:")
    print(f"  {'Deploy':>7s}  │  {'Records':>8s}  │  {'Leaks':>7s}  │  {'Coverage':>9s}  │  Time")
    print(f"  {'─'*7}──┼──{'─'*8}──┼──{'─'*7}──┼──{'─'*9}──┼──{'─'*5}")
    results = sweep(input_csv, full_cache)

    # Save JSON
    stats_path = os.path.join(OUTPUT_DIR, "partial_deployment_stats.json")
    with open(stats_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Stats saved: {stats_path}")

    # Plot
    plot_curve(results)

    print("\nResearch 11.1 COMPLETE ✓")


if __name__ == "__main__":
    main()
