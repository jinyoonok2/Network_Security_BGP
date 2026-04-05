"""
Phase 4: Analysis Pipeline — combines BGP ingestion data with ASPA verification.

Reads ingested BGP updates from CSV, runs each AS path through the ASPA
verifier, and produces:
  - output/flagged_routes.csv    (routes that failed ASPA validation)
  - output/all_results.csv       (every route with its ASPA verdict)
  - output/statistics.json       (aggregate counts and percentages)
  - Console summary
"""

import csv
import json
import os
import sys
import time

# Ensure src/ is on the path so imports work when running from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aspa_cache import ASPACache
from aspa_verifier import verify_as_path, ASPAResult


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")


def load_ingested_routes(csv_path):
    """
    Read BGP routes from the Phase-2 CSV.

    Yields dicts with keys: timestamp, prefix, as_path (list[int]), peer_asn.
    """
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            as_path = [int(x) for x in row["as_path"].split()]
            yield {
                "timestamp": row["timestamp"],
                "prefix": row["prefix"],
                "as_path": as_path,
                "peer_asn": int(row["peer_asn"]),
            }


def build_cache(source="caida"):
    """
    Build an ASPACache from the requested source.

    Args:
        source: "caida" for simulated ASPA from CAIDA AS-relationships,
                "routinator" for real RPKI ASPA records,
                "both" for real records augmented with CAIDA data.
    """
    cache = ASPACache()

    if source in ("routinator", "both"):
        rpath = os.path.join(DATA_DIR, "rpki_vrps_with_aspa.json")
        if os.path.exists(rpath):
            n = cache.load_from_routinator_json(rpath)
            print(f"  Loaded {n:,} real ASPA records from Routinator")
        else:
            print(f"  WARNING: Routinator file not found: {rpath}")

    if source in ("caida", "both"):
        cpath = os.path.join(DATA_DIR, "20240101.as-rel2.txt.bz2")
        if os.path.exists(cpath):
            n = cache.load_from_caida_relationships(cpath)
            print(f"  Loaded {n:,} ASPA records from CAIDA")
        else:
            print(f"  WARNING: CAIDA file not found: {cpath}")

    return cache


def run_analysis(cache, input_csv, tag="analysis"):
    """
    Run ASPA verification on every route in the input CSV.

    Args:
        cache: populated ASPACache
        input_csv: path to ingested_updates.csv
        tag: label used in output filenames (e.g., "caida", "routinator")

    Returns:
        dict with aggregate statistics
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_csv = os.path.join(OUTPUT_DIR, f"all_results_{tag}.csv")
    flagged_csv = os.path.join(OUTPUT_DIR, f"flagged_routes_{tag}.csv")

    stats = {
        "total": 0,
        "valid": 0,
        "invalid": 0,
        "unknown": 0,
        "path_lengths": [],
    }

    t0 = time.time()

    with (
        open(all_csv, "w", newline="") as f_all,
        open(flagged_csv, "w", newline="") as f_flag,
    ):
        all_writer = csv.writer(f_all)
        flag_writer = csv.writer(f_flag)

        header = [
            "timestamp", "prefix", "as_path", "result",
            "violation_count", "violations", "peer_asn",
        ]
        all_writer.writerow(header)
        flag_writer.writerow(header)

        for route in load_ingested_routes(input_csv):
            result, violations = verify_as_path(route["as_path"], cache)

            stats["total"] += 1
            stats[result.value] += 1
            stats["path_lengths"].append(len(route["as_path"]))

            row = [
                route["timestamp"],
                route["prefix"],
                " ".join(map(str, route["as_path"])),
                result.value,
                len(violations),
                "; ".join(v[1] for v in violations) if violations else "",
                route["peer_asn"],
            ]
            all_writer.writerow(row)

            if result == ASPAResult.INVALID:
                flag_writer.writerow(row)

            # Progress indicator
            if stats["total"] % 50000 == 0:
                print(f"    … {stats['total']:,} routes processed")

    elapsed = time.time() - t0

    # Compute summary statistics
    total = stats["total"]
    pl = stats["path_lengths"]
    summary = {
        "tag": tag,
        "total_routes": total,
        "valid": stats["valid"],
        "invalid": stats["invalid"],
        "unknown": stats["unknown"],
        "valid_pct": round(100 * stats["valid"] / total, 2) if total else 0,
        "invalid_pct": round(100 * stats["invalid"] / total, 2) if total else 0,
        "unknown_pct": round(100 * stats["unknown"] / total, 2) if total else 0,
        "avg_path_length": round(sum(pl) / len(pl), 2) if pl else 0,
        "max_path_length": max(pl) if pl else 0,
        "elapsed_seconds": round(elapsed, 1),
    }

    # Save statistics JSON
    stats_path = os.path.join(OUTPUT_DIR, f"statistics_{tag}.json")
    with open(stats_path, "w") as f:
        json.dump(summary, f, indent=2)

    return summary


def print_summary(summary):
    """Pretty-print analysis results."""
    print(f"\n{'=' * 60}")
    print(f"ANALYSIS RESULTS — {summary['tag'].upper()}")
    print(f"{'=' * 60}")
    print(f"  Total routes analyzed:   {summary['total_routes']:>10,}")
    print(f"  VALID   (no violations): {summary['valid']:>10,}  ({summary['valid_pct']:.1f}%)")
    print(f"  INVALID (route leaks):   {summary['invalid']:>10,}  ({summary['invalid_pct']:.1f}%)")
    print(f"  UNKNOWN (no ASPA data):  {summary['unknown']:>10,}  ({summary['unknown_pct']:.1f}%)")
    print(f"  Avg AS-path length:      {summary['avg_path_length']:>10.1f}")
    print(f"  Max AS-path length:      {summary['max_path_length']:>10}")
    print(f"  Processing time:         {summary['elapsed_seconds']:>10.1f}s")


def main():
    """
    Run analysis with both ASPA data sources for comparison.

    Usage:
        python analyze.py                # run both (default)
        python analyze.py caida          # CAIDA simulation only
        python analyze.py routinator     # real ASPA records only
    """
    input_csv = os.path.join(OUTPUT_DIR, "ingested_updates.csv")
    if not os.path.exists(input_csv):
        print(f"ERROR: Input CSV not found: {input_csv}")
        print("Run Phase 2 (ingest.py) first.")
        sys.exit(1)

    source = sys.argv[1] if len(sys.argv) > 1 else "both_separate"

    if source == "both_separate":
        # Run with CAIDA simulation
        print("\n[1/2] Loading CAIDA-simulated ASPA cache …")
        cache_caida = build_cache("caida")
        print(f"  Cache: {cache_caida.summary()['total_customer_asns']:,} customer ASNs")
        print("  Running ASPA verification …")
        s1 = run_analysis(cache_caida, input_csv, tag="caida")
        print_summary(s1)

        # Run with real Routinator ASPA
        print("\n[2/2] Loading real ASPA cache (Routinator) …")
        cache_real = build_cache("routinator")
        print(f"  Cache: {cache_real.summary()['total_customer_asns']:,} customer ASNs")
        print("  Running ASPA verification …")
        s2 = run_analysis(cache_real, input_csv, tag="routinator")
        print_summary(s2)

        # Comparison
        print(f"\n{'=' * 60}")
        print(f"COMPARISON: CAIDA simulation vs Real ASPA")
        print(f"{'=' * 60}")
        print(f"  {'Metric':<28s} {'CAIDA':>12s} {'Routinator':>12s}")
        print(f"  {'-'*52}")
        print(f"  {'ASPA records':<28s} {s1['total_routes']:>12,} {s2['total_routes']:>12,}")
        print(f"  {'Valid':<28s} {s1['valid']:>12,} {s2['valid']:>12,}")
        print(f"  {'Invalid (route leaks)':<28s} {s1['invalid']:>12,} {s2['invalid']:>12,}")
        print(f"  {'Unknown':<28s} {s1['unknown']:>12,} {s2['unknown']:>12,}")
        print(f"  {'Invalid %':<28s} {s1['invalid_pct']:>11.1f}% {s2['invalid_pct']:>11.1f}%")
        print(f"  {'Unknown %':<28s} {s1['unknown_pct']:>11.1f}% {s2['unknown_pct']:>11.1f}%")

    else:
        print(f"\nLoading ASPA cache ({source}) …")
        cache = build_cache(source)
        print(f"  Cache: {cache.summary()['total_customer_asns']:,} customer ASNs")
        print("  Running ASPA verification …")
        summary = run_analysis(cache, input_csv, tag=source)
        print_summary(summary)

    print(f"\nPhase 4 COMPLETE. Output files in: {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()
