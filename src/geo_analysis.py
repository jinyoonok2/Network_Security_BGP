"""
Research 11.3: Per-Country / Per-Region Geographic Analysis

Maps offending ASNs (those appearing in ASPA-invalid routes) to their
registered countries using RIR delegation files. Produces a bar chart
of the top leak-originating countries.

Produces:
  - output/geo_stats.json
  - output/charts/leaks_by_country.png
"""

import csv
import json
import os
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import BASE_DIR, DATA_DIR, OUTPUT_DIR, CHARTS_DIR

# RIR delegation files
RIR_FILES = [
    "delegated-arin.txt",
    "delegated-ripencc.txt",
    "delegated-apnic.txt",
    "delegated-lacnic.txt",
    "delegated-afrinic.txt",
]


def load_asn_to_country():
    """
    Build ASN → country code mapping from RIR delegation files.

    Delegation file format (pipe-delimited):
        rir|CC|asn|start|count|date|status[|hash]

    Some ASN blocks span multiple ASNs (count > 1), so we expand them.
    """
    asn_to_cc = {}
    for fname in RIR_FILES:
        fpath = os.path.join(DATA_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  WARNING: {fname} not found, skipping")
            continue

        with open(fpath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split("|")
                if len(parts) < 5:
                    continue

                # Skip summary/header lines
                if parts[2] != "asn":
                    continue
                if parts[1] == "*":
                    continue

                cc = parts[1]
                try:
                    start_asn = int(parts[3])
                    count = int(parts[4])
                except ValueError:
                    continue

                for asn in range(start_asn, start_asn + count):
                    asn_to_cc[asn] = cc

    return asn_to_cc


def extract_offending_asns(flagged_csv):
    """
    From the flagged routes CSV, extract the ASNs involved in violations.

    For each invalid route, the violation detail tells us which hop pair
    failed. We count each AS that appears in a violation as an offender.
    """
    asn_counter = Counter()  # how many leak routes this ASN appears in
    origin_counter = Counter()  # how many leak routes originate from this ASN

    with open(flagged_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            as_path_str = row.get("as_path", "")
            violations = row.get("violations", "")

            as_path = [int(x) for x in as_path_str.split() if x.isdigit()]

            # Count origin AS
            if as_path:
                origin_counter[as_path[0]] += 1

            # Count every AS in the path for general involvement
            for asn in set(as_path):
                asn_counter[asn] += 1

    return asn_counter, origin_counter


def run_geo_analysis(flagged_csv):
    """Run the geographic analysis and return stats."""
    print("  Loading ASN → country mapping from RIR files …")
    asn_to_cc = load_asn_to_country()
    print(f"  {len(asn_to_cc):,} ASNs mapped to countries")

    print("  Extracting offending ASNs from flagged routes …")
    asn_counts, origin_counts = extract_offending_asns(flagged_csv)
    print(f"  {len(asn_counts):,} unique ASNs appear in invalid paths")
    print(f"  {len(origin_counts):,} unique origin ASNs in invalid paths")

    # Map to countries
    country_leak_count = Counter()  # total route-leak involvement by country
    country_origin_count = Counter()  # routes originating from country's ASNs
    unmapped = 0

    for asn, count in origin_counts.items():
        cc = asn_to_cc.get(asn)
        if cc:
            country_origin_count[cc] += count
        else:
            unmapped += count

    for asn, count in asn_counts.items():
        cc = asn_to_cc.get(asn)
        if cc:
            country_leak_count[cc] += count

    # RIR-level aggregation
    cc_to_rir = {}
    for fname in RIR_FILES:
        rir = fname.replace("delegated-", "").replace(".txt", "").upper()
        fpath = os.path.join(DATA_DIR, fname)
        if not os.path.exists(fpath):
            continue
        with open(fpath) as f:
            for line in f:
                parts = line.strip().split("|")
                if len(parts) >= 5 and parts[2] == "asn" and parts[1] != "*":
                    cc_to_rir[parts[1]] = rir

    rir_counts = Counter()
    for cc, count in country_origin_count.items():
        rir = cc_to_rir.get(cc, "UNKNOWN")
        rir_counts[rir] += count

    stats = {
        "total_mapped_asns": len(asn_to_cc),
        "unique_offending_asns": len(asn_counts),
        "unique_origin_asns": len(origin_counts),
        "unmapped_origins": unmapped,
        "top_20_countries_by_origin": [
            {"country": cc, "leak_routes": count}
            for cc, count in country_origin_count.most_common(20)
        ],
        "top_20_countries_by_involvement": [
            {"country": cc, "involvement_count": count}
            for cc, count in country_leak_count.most_common(20)
        ],
        "by_rir": [
            {"rir": rir, "leak_routes": count}
            for rir, count in rir_counts.most_common()
        ],
    }

    return stats, country_origin_count, rir_counts


def plot_charts(stats, country_counts, rir_counts):
    """Generate geographic analysis charts."""
    os.makedirs(CHARTS_DIR, exist_ok=True)

    # --- Chart 1: Top 15 countries by leak origin ---
    top = stats["top_20_countries_by_origin"][:15]
    countries = [r["country"] for r in top]
    values = [r["leak_routes"] for r in top]

    fig, ax = plt.subplots(figsize=(12, 6))
    colors = plt.cm.Reds([(v / max(values)) * 0.7 + 0.3 for v in values])
    bars = ax.barh(countries[::-1], values[::-1], color=colors[::-1], edgecolor="white")
    ax.set_xlabel("Number of Route Leak Announcements", fontsize=12)
    ax.set_title("Top 15 Countries by BGP Route Leak Origin (ASPA Invalid)",
                 fontsize=13, fontweight="bold")
    ax.grid(axis="x", alpha=0.3)

    # Add value labels
    for bar, val in zip(bars, values[::-1]):
        ax.text(bar.get_width() + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:,}", va="center", fontsize=9)

    fig.tight_layout()
    path1 = os.path.join(CHARTS_DIR, "leaks_by_country.png")
    fig.savefig(path1, dpi=150)
    plt.close(fig)
    print(f"  Chart saved: {path1}")

    # --- Chart 2: By RIR ---
    rirs = [r["rir"] for r in stats["by_rir"]]
    rir_vals = [r["leak_routes"] for r in stats["by_rir"]]

    rir_colors = {
        "ARIN": "#2ecc71", "RIPENCC": "#3498db", "APNIC": "#e74c3c",
        "LACNIC": "#f39c12", "AFRINIC": "#9b59b6",
    }

    fig2, ax2 = plt.subplots(figsize=(8, 5))
    bar_colors = [rir_colors.get(r, "#95a5a6") for r in rirs]
    ax2.bar(rirs, rir_vals, color=bar_colors, edgecolor="white", linewidth=1.5)
    ax2.set_ylabel("Number of Route Leak Announcements", fontsize=12)
    ax2.set_title("Route Leak Origins by RIR Region", fontsize=13, fontweight="bold")
    ax2.grid(axis="y", alpha=0.3)

    for i, (r, v) in enumerate(zip(rirs, rir_vals)):
        ax2.text(i, v + max(rir_vals) * 0.02, f"{v:,}", ha="center", fontsize=10)

    fig2.tight_layout()
    path2 = os.path.join(CHARTS_DIR, "leaks_by_rir.png")
    fig2.savefig(path2, dpi=150)
    plt.close(fig2)
    print(f"  Chart saved: {path2}")

    return path1, path2


def main():
    flagged_csv = os.path.join(OUTPUT_DIR, "flagged_routes_caida.csv")
    if not os.path.exists(flagged_csv):
        print("ERROR: Run Phase 4 (analyze.py) first.")
        sys.exit(1)

    print("=" * 65)
    print("RESEARCH 11.3: Per-Country / Per-Region Analysis")
    print("=" * 65)
    print()

    stats, country_counts, rir_counts = run_geo_analysis(flagged_csv)

    # Print results
    print(f"\n{'=' * 65}")
    print(f"GEOGRAPHIC ANALYSIS RESULTS")
    print(f"{'=' * 65}")
    print(f"\n  Top 10 countries by route leak origin:")
    for entry in stats["top_20_countries_by_origin"][:10]:
        print(f"    {entry['country']:>4s}:  {entry['leak_routes']:>8,} leak announcements")

    print(f"\n  By RIR:")
    for entry in stats["by_rir"]:
        print(f"    {entry['rir']:>8s}:  {entry['leak_routes']:>8,} leak announcements")

    # Save
    stats_path = os.path.join(OUTPUT_DIR, "geo_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"\n  Stats saved: {stats_path}")

    # Plot
    plot_charts(stats, country_counts, rir_counts)

    print("\nResearch 11.3 COMPLETE ✓")


if __name__ == "__main__":
    main()
