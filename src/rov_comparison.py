"""
Research 11.2: ROA vs. ASPA Comparison

Runs Route Origin Validation (ROV) alongside ASPA verification on the same
dataset. Produces a 2×2 contingency table and Venn-style diagram showing
which routes are caught by ROV only, ASPA only, both, or neither.

ROV checks: "Is the origin AS authorized to announce this prefix?"
ASPA checks: "Is the entire AS path structurally valid?"

Produces:
  - output/rov_vs_aspa_stats.json
  - output/charts/roa_vs_aspa_venn.png
"""

import csv
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle
import matplotlib.patches as mpatches
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aspa_cache import ASPACache
from aspa_verifier import verify_as_path, ASPAResult
from analyze import load_ingested_routes

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
CHARTS_DIR = os.path.join(OUTPUT_DIR, "charts")


class ROACache:
    """
    In-memory cache of ROA (Route Origin Authorization) records.
    Maps (prefix, max_length) → set of authorized origin ASNs.
    """

    def __init__(self):
        # {prefix_str: [(asn, max_length), ...]}
        self.records = {}

    def load_from_routinator_json(self, filepath):
        """Load ROA records from Routinator's JSON export."""
        with open(filepath) as f:
            data = json.load(f)

        for roa in data.get("roas", []):
            asn = int(roa["asn"].replace("AS", ""))
            prefix = roa["prefix"]
            max_len = roa["maxLength"]

            if prefix not in self.records:
                self.records[prefix] = []
            self.records[prefix].append((asn, max_len))

        return len(self.records)

    def validate_origin(self, prefix, origin_asn):
        """
        Run ROV on a (prefix, origin) pair.

        Returns:
          "valid"    — a ROA exists and the origin ASN matches
          "invalid"  — a ROA exists for this prefix but with a different ASN
          "unknown"  — no ROA covers this prefix
        """
        import ipaddress

        try:
            announced = ipaddress.ip_network(prefix, strict=False)
        except ValueError:
            return "unknown"

        # Check exact prefix match first
        if prefix in self.records:
            for auth_asn, max_len in self.records[prefix]:
                if auth_asn == origin_asn and announced.prefixlen <= max_len:
                    return "valid"
            # ROA exists but origin doesn't match → invalid
            has_covering = True
        else:
            has_covering = False

        # Check covering prefixes (a ROA for 10.0.0.0/8 covers 10.1.0.0/24)
        for roa_prefix_str, entries in self.records.items():
            try:
                roa_net = ipaddress.ip_network(roa_prefix_str, strict=False)
            except ValueError:
                continue

            if (roa_net.version == announced.version
                    and announced.subnet_of(roa_net)):
                for auth_asn, max_len in entries:
                    if auth_asn == origin_asn and announced.prefixlen <= max_len:
                        return "valid"
                has_covering = True

        if has_covering:
            return "invalid"  # covered by ROA but origin not authorized
        return "unknown"


def build_roa_prefix_tree(roa_cache):
    """
    Build a hash-map lookup structure for fast ROV.

    For each announced prefix, we check all shorter covering prefixes
    by iterating from the announcement's prefix length down to /0.
    This is O(32) for IPv4 and O(128) for IPv6 per lookup — far faster
    than scanning all 800K ROA entries.
    """
    import ipaddress
    # Key: (network_address_int, prefix_len) → list of (asn, max_length)
    tree = {}
    for prefix_str, entries in roa_cache.records.items():
        try:
            net = ipaddress.ip_network(prefix_str, strict=False)
        except ValueError:
            continue
        key = (int(net.network_address), net.prefixlen, net.version)
        tree[key] = entries
    return tree


def fast_rov(prefix_str, origin_asn, tree):
    """
    Fast ROV using hash lookup with covering prefix walk.
    For a given prefix, walk from its prefix length down to /0,
    checking each potential covering prefix.

    Returns "valid", "invalid", or "unknown".
    """
    import ipaddress
    try:
        announced = ipaddress.ip_network(prefix_str, strict=False)
    except ValueError:
        return "unknown"

    addr_int = int(announced.network_address)
    ann_len = announced.prefixlen
    version = announced.version
    max_bits = 32 if version == 4 else 128
    has_covering = False

    # Walk from the announced prefix length down to /0
    for plen in range(ann_len, -1, -1):
        # Compute the network address at this prefix length
        mask = ((1 << max_bits) - 1) ^ ((1 << (max_bits - plen)) - 1) if plen > 0 else 0
        net_addr = addr_int & mask
        key = (net_addr, plen, version)
        entries = tree.get(key)
        if entries:
            for auth_asn, max_len in entries:
                if auth_asn == origin_asn and ann_len <= max_len:
                    return "valid"
            has_covering = True

    return "invalid" if has_covering else "unknown"


def run_comparison(input_csv, aspa_cache, roa_tree):
    """
    Run both ROV and ASPA on every route and classify into 4 quadrants.
    """
    # Quadrants
    both_flag = 0      # ROV invalid AND ASPA invalid
    rov_only = 0       # ROV invalid, ASPA valid/unknown
    aspa_only = 0      # ROV valid/unknown, ASPA invalid
    neither = 0        # neither flagged
    total = 0

    rov_counts = {"valid": 0, "invalid": 0, "unknown": 0}
    aspa_counts = {"valid": 0, "invalid": 0, "unknown": 0}

    for route in load_ingested_routes(input_csv):
        total += 1
        origin = route["as_path"][-1] if route["as_path"] else None

        # ROV check
        if origin is not None:
            rov_result = fast_rov(route["prefix"], origin, roa_tree)
        else:
            rov_result = "unknown"

        # ASPA check
        aspa_result, _ = verify_as_path(route["as_path"], aspa_cache)
        aspa_val = aspa_result.value

        rov_counts[rov_result] += 1
        aspa_counts[aspa_val] += 1

        rov_bad = (rov_result == "invalid")
        aspa_bad = (aspa_val == "invalid")

        if rov_bad and aspa_bad:
            both_flag += 1
        elif rov_bad:
            rov_only += 1
        elif aspa_bad:
            aspa_only += 1
        else:
            neither += 1

        if total % 50000 == 0:
            print(f"    … {total:,} routes processed")

    return {
        "total": total,
        "both_flagged": both_flag,
        "rov_only": rov_only,
        "aspa_only": aspa_only,
        "neither_flagged": neither,
        "rov_counts": rov_counts,
        "aspa_counts": aspa_counts,
    }


def plot_venn(stats):
    """Generate a Venn-style diagram of ROV vs. ASPA detection."""
    os.makedirs(CHARTS_DIR, exist_ok=True)

    fig, (ax_venn, ax_table) = plt.subplots(1, 2, figsize=(14, 6),
                                             gridspec_kw={"width_ratios": [1.2, 1]})

    # --- Venn diagram ---
    c_rov = Circle((0.35, 0.5), 0.3, alpha=0.3, color="#e74c3c", label="ROV Invalid")
    c_aspa = Circle((0.65, 0.5), 0.3, alpha=0.3, color="#3498db", label="ASPA Invalid")
    ax_venn.add_patch(c_rov)
    ax_venn.add_patch(c_aspa)

    # Labels
    total = stats["total"]
    ax_venn.text(0.22, 0.5, f"ROV only\n{stats['rov_only']:,}\n({100*stats['rov_only']/total:.1f}%)",
                 ha="center", va="center", fontsize=11, fontweight="bold")
    ax_venn.text(0.50, 0.5, f"Both\n{stats['both_flagged']:,}\n({100*stats['both_flagged']/total:.1f}%)",
                 ha="center", va="center", fontsize=11, fontweight="bold")
    ax_venn.text(0.78, 0.5, f"ASPA only\n{stats['aspa_only']:,}\n({100*stats['aspa_only']/total:.1f}%)",
                 ha="center", va="center", fontsize=11, fontweight="bold")
    ax_venn.text(0.50, 0.05, f"Neither: {stats['neither_flagged']:,} ({100*stats['neither_flagged']/total:.1f}%)",
                 ha="center", va="center", fontsize=10, style="italic", color="#555")

    ax_venn.set_xlim(0, 1)
    ax_venn.set_ylim(0, 1)
    ax_venn.set_aspect("equal")
    ax_venn.set_title("ROV vs. ASPA: Route Invalidation Overlap", fontsize=13, fontweight="bold")

    rov_patch = mpatches.Patch(color="#e74c3c", alpha=0.3, label="ROV Invalid")
    aspa_patch = mpatches.Patch(color="#3498db", alpha=0.3, label="ASPA Invalid")
    ax_venn.legend(handles=[rov_patch, aspa_patch], loc="upper left", fontsize=10)
    ax_venn.axis("off")

    # --- Table ---
    row_labels = ["ROV Valid/Unknown", "ROV Invalid", "Total"]
    col_labels = ["ASPA Valid/Unknown", "ASPA Invalid", "Total"]

    aspa_ok = stats["neither_flagged"] + stats["rov_only"]
    rov_ok_aspa_bad = stats["aspa_only"]
    rov_bad_aspa_ok = stats["rov_only"]
    cell_values = [
        [f"{stats['neither_flagged']:,}", f"{stats['aspa_only']:,}",
         f"{stats['neither_flagged']+stats['aspa_only']:,}"],
        [f"{stats['rov_only']:,}", f"{stats['both_flagged']:,}",
         f"{stats['rov_only']+stats['both_flagged']:,}"],
        [f"{stats['neither_flagged']+stats['rov_only']:,}",
         f"{stats['aspa_only']+stats['both_flagged']:,}",
         f"{total:,}"],
    ]

    ax_table.axis("off")
    table = ax_table.table(cellText=cell_values, rowLabels=row_labels,
                            colLabels=col_labels, loc="center", cellLoc="center")
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1.2, 1.8)
    ax_table.set_title("2×2 Contingency Table", fontsize=13, fontweight="bold", pad=20)

    fig.tight_layout()
    out_path = os.path.join(CHARTS_DIR, "roa_vs_aspa_venn.png")
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
    print("RESEARCH 11.2: ROA vs. ASPA Comparison")
    print("=" * 65)

    # Load ROA cache
    print("\nLoading ROA records from Routinator …")
    roa_cache = ROACache()
    roa_path = os.path.join(DATA_DIR, "rpki_vrps_with_aspa.json")
    n = roa_cache.load_from_routinator_json(roa_path)
    print(f"  {n:,} unique prefixes with ROA records")

    # Build prefix tree for fast lookup
    print("  Building prefix lookup table …")
    roa_tree = build_roa_prefix_tree(roa_cache)
    print(f"  {len(roa_tree):,} prefix entries indexed")

    # Load ASPA cache (CAIDA for best coverage)
    print("\nLoading ASPA cache (CAIDA) …")
    aspa_cache = ASPACache()
    caida_path = os.path.join(DATA_DIR, "20240101.as-rel2.txt.bz2")
    m = aspa_cache.load_from_caida_relationships(caida_path)
    print(f"  {m:,} ASPA records")

    # Run comparison
    print("\nRunning ROV + ASPA on all routes …")
    stats = run_comparison(input_csv, aspa_cache, roa_tree)

    # Print results
    total = stats["total"]
    print(f"\n{'=' * 65}")
    print(f"ROA vs. ASPA COMPARISON RESULTS")
    print(f"{'=' * 65}")
    print(f"  Total routes:              {total:>10,}")
    print(f"  Flagged by BOTH:           {stats['both_flagged']:>10,}  ({100*stats['both_flagged']/total:.1f}%)")
    print(f"  ROV only (origin invalid): {stats['rov_only']:>10,}  ({100*stats['rov_only']/total:.1f}%)")
    print(f"  ASPA only (path invalid):  {stats['aspa_only']:>10,}  ({100*stats['aspa_only']/total:.1f}%)")
    print(f"  Neither flagged:           {stats['neither_flagged']:>10,}  ({100*stats['neither_flagged']/total:.1f}%)")

    print(f"\n  ROV breakdown:  valid={stats['rov_counts']['valid']:,}  "
          f"invalid={stats['rov_counts']['invalid']:,}  "
          f"unknown={stats['rov_counts']['unknown']:,}")
    print(f"  ASPA breakdown: valid={stats['aspa_counts']['valid']:,}  "
          f"invalid={stats['aspa_counts']['invalid']:,}  "
          f"unknown={stats['aspa_counts']['unknown']:,}")

    # Save stats
    stats_path = os.path.join(OUTPUT_DIR, "rov_vs_aspa_stats.json")
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"\n  Stats saved: {stats_path}")

    # Plot
    plot_venn(stats)

    print("\nResearch 11.2 COMPLETE ✓")


if __name__ == "__main__":
    main()
