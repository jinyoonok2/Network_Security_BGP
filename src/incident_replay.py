"""
Research 11.5: Real-World Incident Case Study — Rostelecom Leak (April 2020)

Replays the Rostelecom route leak incident (April 1, 2020) through
our ASPA verification engine to demonstrate that the tool detects
the leaked paths.

Background:
  On April 1, 2020, AS12389 (Rostelecom, Russia's national telecom)
  leaked prefixes belonging to Cloudflare (AS13335), Akamai (AS20940),
  Amazon/AWS (AS16509), and other major CDN/cloud providers. This caused
  traffic destined for these services to be routed through Russia.

  The leak occurred because AS12389 announced routes with itself as a
  transit provider for networks it had no business transiting. Under ASPA,
  these routes would have been flagged as INVALID because AS12389 is NOT
  an authorized provider for these networks.

Produces:
  - output/incident_case_study.json
  - Console narrative showing ASPA detection of the leaked paths
"""

import ipaddress
import json
import os
import sys
import time

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aspa_cache import ASPACache
from aspa_verifier import verify_as_path, ASPAResult, remove_prepends
from config import BASE_DIR, DATA_DIR, OUTPUT_DIR, CHARTS_DIR


# --- Known leaker and target ASNs for this incident ---
LEAKER_ASN = 12389  # Rostelecom

TARGET_ASNS = {
    13335: "Cloudflare",
    20940: "Akamai",
    16509: "Amazon (AWS)",
    32934: "Facebook (Meta)",
    8075:  "Microsoft",
    8068:  "Microsoft (MSIT)",
}

# --- Known victim prefix ranges (documented in the incident) ---
# Sources: Cloudflare blog, BGPStream reports, MANRS post-incident analysis
VICTIM_PREFIXES = [
    # Cloudflare
    "1.1.1.0/24", "1.0.0.0/24", "104.16.0.0/12", "172.64.0.0/13",
    "141.101.64.0/18", "173.245.48.0/20", "190.93.240.0/20",
    "197.234.240.0/22", "198.41.128.0/17",
    # Akamai
    "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "104.64.0.0/10",
    # Amazon AWS
    "13.32.0.0/15", "13.224.0.0/14", "52.0.0.0/11", "54.192.0.0/12",
    "99.84.0.0/16", "143.204.0.0/16", "205.251.192.0/19",
    # Facebook / Meta
    "31.13.24.0/21", "31.13.64.0/18", "157.240.0.0/16", "179.60.192.0/22",
    "185.60.216.0/22",
    # Microsoft
    "13.64.0.0/11", "20.33.0.0/16", "40.74.0.0/15", "52.96.0.0/12",
    "104.208.0.0/13", "131.253.0.0/16", "204.79.197.0/24",
]

# Pre-compile into ip_network objects for fast matching
_VICTIM_NETS = [ipaddress.ip_network(p, strict=False) for p in VICTIM_PREFIXES]


def prefix_matches_victim(prefix_str):
    """Check if an announced prefix falls within any known victim range."""
    try:
        announced = ipaddress.ip_network(prefix_str, strict=False)
    except ValueError:
        return False
    for victim_net in _VICTIM_NETS:
        if (announced.version == victim_net.version
                and announced.subnet_of(victim_net)):
            return True
    return False


def ingest_incident_data():
    """
    Stream BGP UPDATE data from the Rostelecom incident window.
    Returns lists of routes in several categories:
      - all_routes: every announcement in the hour
      - rostelecom_routes: routes where AS12389 appears in the path
      - rostelecom_target_routes: routes where AS12389 + a victim ASN are in the path
      - rostelecom_prefix_routes: routes where AS12389 is in the path AND the
        prefix belongs to a known victim (prefix-filtered — most precise)
    """
    import pybgpstream

    print("  Streaming BGP data from RouteViews (2020-04-01 19:00–20:00 UTC) …")

    stream = pybgpstream.BGPStream(
        from_time="2020-04-01 19:00:00",
        until_time="2020-04-01 20:00:00",
        collectors=["route-views2"],
        record_type="updates",
    )

    all_routes = []
    rostelecom_routes = []
    rostelecom_target_routes = []
    rostelecom_prefix_routes = []
    count = 0

    for elem in stream:
        count += 1
        if elem.type != "A":
            continue

        as_path_str = elem.fields.get("as-path", "")
        prefix = elem.fields.get("prefix", "")
        tokens = as_path_str.split()

        # Parse AS path
        as_path = []
        for tok in tokens:
            if tok.startswith("{"):
                continue
            try:
                as_path.append(int(tok))
            except ValueError:
                continue

        if not as_path:
            continue

        route = {
            "prefix": prefix,
            "as_path": as_path,
            "as_path_str": as_path_str,
            "peer_asn": elem.peer_asn,
            "timestamp": elem.time,
        }
        all_routes.append(route)

        # Track Rostelecom routes
        if LEAKER_ASN in as_path:
            rostelecom_routes.append(route)

            # Check if route involves a target CDN/cloud (ASN-based)
            target_hits = set(as_path) & set(TARGET_ASNS.keys())
            if target_hits:
                rostelecom_target_routes.append((route, target_hits))

            # Check if the prefix belongs to a known victim (prefix-based)
            if prefix_matches_victim(prefix):
                rostelecom_prefix_routes.append(route)

        if count % 100000 == 0:
            print(f"    … {count:,} BGP elements processed "
                  f"({len(rostelecom_target_routes)} suspicious routes)")

    print(f"  Done: {count:,} elements → {len(all_routes):,} announcements")
    print(f"    Routes involving AS12389: {len(rostelecom_routes):,}")
    print(f"    Routes with AS12389 + target CDN: {len(rostelecom_target_routes):,}")
    print(f"    Routes with AS12389 + victim prefix: {len(rostelecom_prefix_routes):,}")

    return all_routes, rostelecom_routes, rostelecom_target_routes, rostelecom_prefix_routes


def analyze_incident(all_routes, rostelecom_routes, target_routes,
                     prefix_routes, aspa_cache):
    """
    Run ASPA verification on all routes from the incident window
    and highlight the leaked paths.
    """
    # 1. Verify ALL routes
    print("\n  Running ASPA verification on all routes …")
    total_invalid = 0
    total_valid = 0
    total_unknown = 0

    for route in all_routes:
        result, _ = verify_as_path(route["as_path"], aspa_cache)
        if result == ASPAResult.INVALID:
            total_invalid += 1
        elif result == ASPAResult.VALID:
            total_valid += 1
        else:
            total_unknown += 1

    # 2. Verify Rostelecom routes specifically
    rt_invalid = 0
    rt_valid = 0
    rt_unknown = 0
    for route in rostelecom_routes:
        result, _ = verify_as_path(route["as_path"], aspa_cache)
        if result == ASPAResult.INVALID:
            rt_invalid += 1
        elif result == ASPAResult.VALID:
            rt_valid += 1
        else:
            rt_unknown += 1

    # 2b. Verify prefix-filtered routes (Rostelecom + victim prefix)
    pf_invalid = 0
    pf_valid = 0
    pf_unknown = 0
    for route in prefix_routes:
        result, _ = verify_as_path(route["as_path"], aspa_cache)
        if result == ASPAResult.INVALID:
            pf_invalid += 1
        elif result == ASPAResult.VALID:
            pf_valid += 1
        else:
            pf_unknown += 1

    # 3. Analyze specific target leaks
    leak_details = []
    for route, target_hits in target_routes:
        result, violations = verify_as_path(route["as_path"], aspa_cache)
        clean = remove_prepends(route["as_path"])
        targets = [TARGET_ASNS[a] for a in target_hits if a in TARGET_ASNS]

        leak_details.append({
            "prefix": route["prefix"],
            "as_path": route["as_path"],
            "as_path_clean": clean,
            "targets": targets,
            "aspa_result": result.value,
            "violations": [(v[0], v[1]) for v in violations],
            "path_display": " → ".join(
                f"**AS{a}**" if a == LEAKER_ASN else f"AS{a}"
                for a in clean
            ),
        })

    return {
        "all_routes": {
            "total": len(all_routes),
            "valid": total_valid,
            "invalid": total_invalid,
            "unknown": total_unknown,
        },
        "rostelecom_routes": {
            "total": len(rostelecom_routes),
            "valid": rt_valid,
            "invalid": rt_invalid,
            "unknown": rt_unknown,
        },
        "prefix_filtered": {
            "total": len(prefix_routes),
            "valid": pf_valid,
            "invalid": pf_invalid,
            "unknown": pf_unknown,
        },
        "target_leaks": leak_details,
    }


def main():
    print("=" * 65)
    print("RESEARCH 11.5: Incident Case Study — Rostelecom Leak (Apr 2020)")
    print("=" * 65)

    # Load ASPA cache (CAIDA April 2020 — matching the incident date)
    print("\nLoading CAIDA ASPA cache (April 2020) …")
    cache = ASPACache()
    caida_path = os.path.join(DATA_DIR, "20200401.as-rel2.txt.bz2")
    n = cache.load_from_caida_relationships(caida_path)
    print(f"  {n:,} ASPA records loaded")

    # Ingest incident data
    print("\nIngesting incident data …")
    all_routes, rt_routes, target_routes, prefix_routes = ingest_incident_data()

    if not all_routes:
        print("ERROR: No BGP data retrieved. Network or archive issue.")
        sys.exit(1)

    # Analyze
    print("\nAnalyzing incident …")
    results = analyze_incident(all_routes, rt_routes, target_routes,
                               prefix_routes, cache)

    # Print narrative
    total = results["all_routes"]
    rt = results["rostelecom_routes"]

    print(f"\n{'=' * 65}")
    print(f"INCIDENT CASE STUDY: Rostelecom Route Leak (April 1, 2020)")
    print(f"{'=' * 65}")

    print(f"\n  BACKGROUND:")
    print(f"    On April 1, 2020, AS12389 (Rostelecom) leaked routes for major")
    print(f"    CDN/cloud providers, causing traffic to be rerouted through Russia.")

    print(f"\n  DATA WINDOW: 2020-04-01 19:00–20:00 UTC (RouteViews route-views2)")

    print(f"\n  OVERALL RESULTS (all routes in window):")
    print(f"    Total announcements:  {total['total']:>8,}")
    print(f"    ASPA Valid:           {total['valid']:>8,}")
    print(f"    ASPA Invalid:        {total['invalid']:>8,}")
    print(f"    ASPA Unknown:        {total['unknown']:>8,}")

    print(f"\n  ROSTELECOM-SPECIFIC RESULTS (routes involving AS12389):")
    print(f"    Total routes:         {rt['total']:>8,}")
    print(f"    ASPA Valid:           {rt['valid']:>8,}")
    print(f"    ASPA Invalid:        {rt['invalid']:>8,}")
    print(f"    ASPA Unknown:        {rt['unknown']:>8,}")
    if rt["total"] > 0:
        pct = 100 * rt["invalid"] / rt["total"]
        print(f"    Detection rate:      {pct:>8.1f}%")

    pf = results["prefix_filtered"]
    print(f"\n  PREFIX-FILTERED RESULTS (AS12389 + victim address ranges):")
    print(f"    Total routes:         {pf['total']:>8,}")
    print(f"    ASPA Valid:           {pf['valid']:>8,}")
    print(f"    ASPA Invalid:        {pf['invalid']:>8,}")
    print(f"    ASPA Unknown:        {pf['unknown']:>8,}")
    if pf["total"] > 0:
        pf_pct = 100 * pf["invalid"] / pf["total"]
        print(f"    Detection rate:      {pf_pct:>8.1f}%")

    # Show specific leaked paths
    if results["target_leaks"]:
        print(f"\n  FLAGGED LEAK PATHS (AS12389 + CDN targets):")
        shown = set()
        for detail in results["target_leaks"]:
            # Deduplicate by cleaned path
            key = tuple(detail["as_path_clean"])
            if key in shown:
                continue
            shown.add(key)
            if len(shown) > 15:
                break

            path_str = " → ".join(
                f"[AS{a} Rostelecom]" if a == LEAKER_ASN else f"AS{a}"
                for a in detail["as_path_clean"]
            )
            targets = ", ".join(detail["targets"])
            result = detail["aspa_result"].upper()
            print(f"\n    Path: {path_str}")
            print(f"    Prefix: {detail['prefix']}")
            print(f"    Targets: {targets}")
            print(f"    ASPA Result: {result}")
            if detail["violations"]:
                for v_idx, v_reason in detail["violations"]:
                    print(f"      ⚠ hop {v_idx}: {v_reason}")

    # Key finding
    if pf["total"] > 0:
        pf_pct = 100 * pf["invalid"] / pf["total"]
        print(f"\n  {'=' * 61}")
        print(f"  KEY FINDING: With prefix filtering, ASPA flagged {pf['invalid']:,}")
        print(f"  of {pf['total']:,} ({pf_pct:.1f}%) routes where Rostelecom was")
        print(f"  carrying victim traffic (Cloudflare, Amazon, Akamai, etc.).")
        print(f"  These routes would have been REJECTED, preventing the leak.")
        print(f"  {'=' * 61}")

    # Visualize
    plot_incident_chart(results)

    # Save
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    save_data = {
        "incident": "Rostelecom Route Leak",
        "date": "2020-04-01",
        "leaker_asn": LEAKER_ASN,
        "data_window": "2020-04-01 19:00-20:00 UTC",
        "collector": "route-views2",
        "caida_file": "20200401.as-rel2.txt.bz2",
        "all_routes": results["all_routes"],
        "rostelecom_routes": results["rostelecom_routes"],
        "prefix_filtered": results["prefix_filtered"],
        "sample_leak_paths": [
            {
                "prefix": d["prefix"],
                "as_path": d["as_path_clean"],
                "targets": d["targets"],
                "aspa_result": d["aspa_result"],
                "violations": d["violations"],
            }
            for d in results["target_leaks"][:20]
        ],
    }
    stats_path = os.path.join(OUTPUT_DIR, "incident_case_study.json")
    with open(stats_path, "w") as f:
        json.dump(save_data, f, indent=2)
    print(f"\n  Stats saved: {stats_path}")

    print("\nResearch 11.5 COMPLETE ✓")


def plot_incident_chart(results):
    """
    Stacked percentage bar chart comparing ASPA verdict breakdown across
    four groups: normal baseline, all routes during incident, Rostelecom only,
    and prefix-filtered (victim traffic only).
    """
    # --- Data ---
    # Normal day baseline (from CAIDA analysis, Jan 2024)
    baseline = {"valid": 86.5, "invalid": 13.2, "unknown": 0.3}

    def to_pct(d):
        t = d["total"]
        return {
            "valid":   100 * d["valid"]   / t,
            "invalid": 100 * d["invalid"] / t,
            "unknown": 100 * d["unknown"] / t,
        }

    incident_all = to_pct(results["all_routes"])
    incident_rt  = to_pct(results["rostelecom_routes"])
    incident_pf  = to_pct(results["prefix_filtered"])

    groups = ["Normal Day\n(Jan 2024 baseline)",
              "During Incident\n(all routes, Apr 2020)",
              "Rostelecom Routes\n(AS12389, all traffic)",
              "Prefix-Filtered\n(AS12389 + victim prefixes)"]
    valids   = [baseline["valid"],   incident_all["valid"],   incident_rt["valid"],   incident_pf["valid"]]
    invalids = [baseline["invalid"], incident_all["invalid"], incident_rt["invalid"], incident_pf["invalid"]]
    unknowns = [baseline["unknown"], incident_all["unknown"], incident_rt["unknown"], incident_pf["unknown"]]

    x = np.arange(len(groups))
    colors = {"valid": "#2ecc71", "invalid": "#e74c3c", "unknown": "#95a5a6"}

    fig, ax = plt.subplots(figsize=(11, 6))

    bars_v = ax.bar(x, valids,   color=colors["valid"],   label="Valid",   zorder=3)
    bars_i = ax.bar(x, invalids, color=colors["invalid"],  label="Invalid",
                    bottom=valids, zorder=3)
    bars_u = ax.bar(x, unknowns, color=colors["unknown"],  label="Unknown",
                    bottom=[v + i for v, i in zip(valids, invalids)], zorder=3)

    # Annotate each segment with its percentage
    for bar, val in zip(bars_v, valids):
        if val > 2:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() / 2,
                    f"{val:.1f}%", ha="center", va="center",
                    fontsize=11, fontweight="bold", color="white")

    for bar, base, val in zip(bars_i, valids, invalids):
        if val > 2:
            ax.text(bar.get_x() + bar.get_width() / 2,
                    base + val / 2,
                    f"{val:.1f}%", ha="center", va="center",
                    fontsize=11, fontweight="bold", color="white")

    ax.set_xticks(x)
    ax.set_xticklabels(groups, fontsize=11)
    ax.set_ylabel("Percentage of Routes (%)", fontsize=12)
    ax.set_ylim(0, 110)
    ax.set_title("ASPA Verdict Breakdown: Normal Day vs. Rostelecom Leak (Apr 2020)",
                 fontsize=13, fontweight="bold", pad=14)
    ax.legend(loc="upper right", fontsize=11)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)

    # Highlight the prefix-filtered bar
    pf_x = x[3]
    pf_invalid_pct = incident_pf["invalid"]
    ax.annotate(
        f"{pf_invalid_pct:.1f}% detected\nas INVALID\n(victim traffic only)",
        xy=(pf_x, valids[3] + invalids[3] / 2),
        xytext=(pf_x - 0.15, 70),
        fontsize=10, color="#c0392b", fontweight="bold",
        arrowprops=dict(arrowstyle="->", color="#c0392b", lw=1.5),
    )

    plt.tight_layout()
    os.makedirs(CHARTS_DIR, exist_ok=True)
    out_path = os.path.join(CHARTS_DIR, "incident_aspa_verdicts.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Chart saved: {out_path}")


if __name__ == "__main__":
    main()
