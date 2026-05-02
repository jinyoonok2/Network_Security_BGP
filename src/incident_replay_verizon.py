"""
Research: Real-World Incident Case Study — Verizon/DQE Route Leak (June 2019)

Replays the Verizon/DQE route leak incident (June 24, 2019) through
our ASPA verification engine to demonstrate detection of a small-ISP-caused leak.

Background:
  On June 24, 2019, AS33154 (DQE Communications, a small Pennsylvania ISP)
  accidentally leaked ~70,000 routes to AS701 (Verizon), which accepted them
  and propagated them to the global internet. This caused traffic destined for
  Cloudflare, Google, and thousands of other destinations to be rerouted
  through a tiny ISP with insufficient capacity, causing widespread slowdowns
  and outages for roughly two hours.

  The leak occurred because DQE re-announced routes it had learned from its
  upstream providers back out to Verizon, violating the valley-free property.
  Under ASPA, these routes would be flagged as INVALID because DQE (AS33154)
  is not an authorized provider for the major networks whose traffic it was
  carrying.

  Key contrast with Rostelecom (2020):
    - Rostelecom is a large national carrier with many legitimate relationships.
    - DQE is a tiny ISP with no legitimate reason to appear in global paths.
    - Verizon's acceptance of DQE's leaked routes is itself a policy failure.

Requires:
  - data/20190601.as-rel2.txt.bz2  (CAIDA AS-relationships, June 2019)
    Download from: https://www.caida.org/catalog/datasets/as-relationships/

Produces:
  - output/incident_verizon.json
  - output/charts/incident_verizon_verdicts.png
"""

import ipaddress
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aspa_cache import ASPACache
from aspa_verifier import verify_as_path, ASPAResult, remove_prepends
from config import BASE_DIR, DATA_DIR, OUTPUT_DIR, CHARTS_DIR


# ---------------------------------------------------------------------------
# Incident parameters
# ---------------------------------------------------------------------------

LEAKER_ASN    = 33154   # DQE Communications (originated the leak)
PROPAGATOR_ASN = 701    # Verizon (accepted and propagated to global internet)

TARGET_ASNS = {
    13335: "Cloudflare",
    15169: "Google",
    16509: "Amazon (AWS)",
    20940: "Akamai",
    32934: "Facebook (Meta)",
    8075:  "Microsoft",
}

# Known victim prefix ranges affected in this incident.
# Sources: Cloudflare blog post (2019-06-24), MANRS incident report,
#          BGPStream analysis of the event.
VICTIM_PREFIXES = [
    # Cloudflare
    "1.1.1.0/24", "1.0.0.0/24", "104.16.0.0/12", "172.64.0.0/13",
    "141.101.64.0/18", "173.245.48.0/20", "190.93.240.0/20",
    "197.234.240.0/22", "198.41.128.0/17",
    # Google
    "8.8.8.0/24", "8.8.4.0/24", "172.217.0.0/16", "74.125.0.0/16",
    "64.233.160.0/19", "66.249.64.0/19", "209.85.128.0/17",
    # Amazon AWS
    "13.32.0.0/15", "13.224.0.0/14", "52.0.0.0/11", "54.192.0.0/12",
    "99.84.0.0/16", "143.204.0.0/16", "205.251.192.0/19",
    # Akamai
    "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "104.64.0.0/10",
    # Facebook / Meta
    "31.13.24.0/21", "31.13.64.0/18", "157.240.0.0/16", "179.60.192.0/22",
    "185.60.216.0/22",
    # Microsoft
    "13.64.0.0/11", "20.33.0.0/16", "40.74.0.0/15", "52.96.0.0/12",
    "104.208.0.0/13", "131.253.0.0/16",
]

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


# ---------------------------------------------------------------------------
# Data ingestion
# ---------------------------------------------------------------------------

def ingest_incident_data():
    """
    Stream BGP UPDATE data from the Verizon/DQE incident window.

    Returns four route lists:
      all_routes          — every announcement in the window
      dqe_routes          — routes where AS33154 (DQE) appears in the path
      dqe_target_routes   — DQE routes that also include a known victim ASN
      dqe_prefix_routes   — DQE routes whose prefix matches a known victim range
                            (prefix-filtered — most precise isolation of leak traffic)
    """
    import pybgpstream

    start = "2019-06-24 10:30:00"
    end   = "2019-06-24 12:30:00"   # 2-hour window covering the full leak duration

    print(f"  Streaming BGP data from RouteViews ({start} – {end} UTC) …")

    stream = pybgpstream.BGPStream(
        from_time=start,
        until_time=end,
        collectors=["route-views2"],
        record_type="updates",
    )

    all_routes        = []
    dqe_routes        = []
    dqe_target_routes = []
    dqe_prefix_routes = []
    count = 0

    for elem in stream:
        count += 1
        if elem.type != "A":
            continue

        as_path_str = elem.fields.get("as-path", "")
        prefix      = elem.fields.get("prefix", "")

        as_path = []
        for tok in as_path_str.split():
            if tok.startswith("{"):
                continue
            try:
                as_path.append(int(tok))
            except ValueError:
                continue

        if not as_path:
            continue

        route = {
            "prefix":     prefix,
            "as_path":    as_path,
            "as_path_str": as_path_str,
            "peer_asn":   elem.peer_asn,
            "timestamp":  elem.time,
        }
        all_routes.append(route)

        if LEAKER_ASN in as_path:
            dqe_routes.append(route)

            target_hits = set(as_path) & set(TARGET_ASNS.keys())
            if target_hits:
                dqe_target_routes.append((route, target_hits))

            if prefix_matches_victim(prefix):
                dqe_prefix_routes.append(route)

        if count % 200000 == 0:
            print(f"    … {count:,} BGP elements processed "
                  f"({len(dqe_routes):,} DQE routes seen)")

    print(f"  Done: {count:,} elements → {len(all_routes):,} announcements")
    print(f"    Routes involving AS33154 (DQE):            {len(dqe_routes):,}")
    print(f"    Routes with DQE + target CDN/cloud (ASN):  {len(dqe_target_routes):,}")
    print(f"    Routes with DQE + victim prefix:           {len(dqe_prefix_routes):,}")

    return all_routes, dqe_routes, dqe_target_routes, dqe_prefix_routes


# ---------------------------------------------------------------------------
# ASPA verification
# ---------------------------------------------------------------------------

def _verdict_counts(routes, aspa_cache):
    """Run ASPA on a list of routes and return (valid, invalid, unknown) counts."""
    valid = invalid = unknown = 0
    for route in routes:
        result, _ = verify_as_path(route["as_path"], aspa_cache)
        if result == ASPAResult.VALID:
            valid += 1
        elif result == ASPAResult.INVALID:
            invalid += 1
        else:
            unknown += 1
    return valid, invalid, unknown


def analyze_incident(all_routes, dqe_routes, target_routes,
                     prefix_routes, aspa_cache):
    """Run ASPA verification across all four route groups."""

    print("\n  Verifying all routes …")
    av, ai, au = _verdict_counts(all_routes, aspa_cache)

    print("  Verifying DQE-specific routes …")
    dv, di, du = _verdict_counts(dqe_routes, aspa_cache)

    print("  Verifying prefix-filtered routes …")
    pv, pi, pu = _verdict_counts(prefix_routes, aspa_cache)

    # Detailed analysis for target-matched routes
    leak_details = []
    for route, target_hits in target_routes:
        result, violations = verify_as_path(route["as_path"], aspa_cache)
        clean   = remove_prepends(route["as_path"])
        targets = [TARGET_ASNS[a] for a in target_hits if a in TARGET_ASNS]
        leak_details.append({
            "prefix":        route["prefix"],
            "as_path":       route["as_path"],
            "as_path_clean": clean,
            "targets":       targets,
            "aspa_result":   result.value,
            "violations":    [(v[0], v[1]) for v in violations],
        })

    return {
        "all_routes":      {"total": len(all_routes),   "valid": av, "invalid": ai, "unknown": au},
        "dqe_routes":      {"total": len(dqe_routes),   "valid": dv, "invalid": di, "unknown": du},
        "prefix_filtered": {"total": len(prefix_routes),"valid": pv, "invalid": pi, "unknown": pu},
        "target_leaks":    leak_details,
    }


# ---------------------------------------------------------------------------
# Chart
# ---------------------------------------------------------------------------

def plot_incident_chart(results):
    """
    Stacked percentage bar chart: normal baseline vs. Verizon/DQE incident.
    Four bars: baseline, all incident routes, DQE-only routes, prefix-filtered.
    """
    baseline = {"valid": 86.5, "invalid": 13.2, "unknown": 0.3}

    def to_pct(d):
        t = d["total"]
        if t == 0:
            return {"valid": 0, "invalid": 0, "unknown": 0}
        return {
            "valid":   100 * d["valid"]   / t,
            "invalid": 100 * d["invalid"] / t,
            "unknown": 100 * d["unknown"] / t,
        }

    incident_all = to_pct(results["all_routes"])
    incident_dqe = to_pct(results["dqe_routes"])
    incident_pf  = to_pct(results["prefix_filtered"])

    groups = [
        "Normal Day\n(Jan 2024 baseline)",
        "During Incident\n(all routes, Jun 2019)",
        "DQE Routes\n(AS33154, all traffic)",
        "Prefix-Filtered\n(AS33154 + victim prefixes)",
    ]
    valids   = [baseline["valid"],   incident_all["valid"],   incident_dqe["valid"],   incident_pf["valid"]]
    invalids = [baseline["invalid"], incident_all["invalid"], incident_dqe["invalid"], incident_pf["invalid"]]
    unknowns = [baseline["unknown"], incident_all["unknown"], incident_dqe["unknown"], incident_pf["unknown"]]

    x = np.arange(len(groups))
    colors = {"valid": "#2ecc71", "invalid": "#e74c3c", "unknown": "#95a5a6"}

    fig, ax = plt.subplots(figsize=(11, 6))

    bars_v = ax.bar(x, valids,   color=colors["valid"],   label="Valid",   zorder=3)
    bars_i = ax.bar(x, invalids, color=colors["invalid"], label="Invalid",
                    bottom=valids, zorder=3)
    bars_u = ax.bar(x, unknowns, color=colors["unknown"], label="Unknown",
                    bottom=[v + i for v, i in zip(valids, invalids)], zorder=3)

    for bar, val in zip(bars_v, valids):
        if val > 2:
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() / 2,
                    f"{val:.1f}%", ha="center", va="center",
                    fontsize=11, fontweight="bold", color="white")

    for bar, base, val in zip(bars_i, valids, invalids):
        if val > 2:
            ax.text(bar.get_x() + bar.get_width() / 2, base + val / 2,
                    f"{val:.1f}%", ha="center", va="center",
                    fontsize=11, fontweight="bold", color="white")

    # Annotate the prefix-filtered bar
    pf_x = x[3]
    pf_invalid_pct = incident_pf["invalid"]
    if pf_invalid_pct > 0:
        ax.annotate(
            f"{pf_invalid_pct:.1f}% detected\nas INVALID\n(victim traffic only)",
            xy=(pf_x, valids[3] + invalids[3] / 2),
            xytext=(pf_x - 0.15, 70),
            fontsize=10, color="#c0392b", fontweight="bold",
            arrowprops=dict(arrowstyle="->", color="#c0392b", lw=1.5),
        )

    ax.set_xticks(x)
    ax.set_xticklabels(groups, fontsize=11)
    ax.set_ylabel("Percentage of Routes (%)", fontsize=12)
    ax.set_ylim(0, 110)
    ax.set_title("ASPA Verdict Breakdown: Normal Day vs. Verizon/DQE Leak (Jun 2019)",
                 fontsize=13, fontweight="bold", pad=14)
    ax.legend(loc="upper right", fontsize=11)
    ax.yaxis.grid(True, linestyle="--", alpha=0.5, zorder=0)
    ax.set_axisbelow(True)

    plt.tight_layout()
    os.makedirs(CHARTS_DIR, exist_ok=True)
    out_path = os.path.join(CHARTS_DIR, "incident_verizon_verdicts.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  Chart saved: {out_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 65)
    print("INCIDENT CASE STUDY: Verizon/DQE Route Leak (June 24, 2019)")
    print("=" * 65)

    # Load CAIDA data temporally matched to the incident
    caida_path = os.path.join(DATA_DIR, "20190601.as-rel2.txt.bz2")
    if not os.path.exists(caida_path):
        print(f"\nERROR: CAIDA file not found: {caida_path}")
        print("Download 20190601.as-rel2.txt.bz2 from:")
        print("  https://www.caida.org/catalog/datasets/as-relationships/")
        print("and place it in the data/ folder.")
        sys.exit(1)

    print(f"\nLoading CAIDA ASPA cache (June 2019) …")
    cache = ASPACache()
    n = cache.load_from_caida_relationships(caida_path)
    print(f"  {n:,} ASPA records loaded")

    print("\nIngesting incident data …")
    all_routes, dqe_routes, target_routes, prefix_routes = ingest_incident_data()

    if not all_routes:
        print("ERROR: No BGP data retrieved. Check network connection.")
        sys.exit(1)

    print("\nAnalyzing incident …")
    results = analyze_incident(all_routes, dqe_routes, target_routes,
                               prefix_routes, cache)

    # --- Print results ---
    total = results["all_routes"]
    dqe   = results["dqe_routes"]
    pf    = results["prefix_filtered"]

    print(f"\n{'=' * 65}")
    print(f"RESULTS: Verizon/DQE Route Leak (June 24, 2019)")
    print(f"{'=' * 65}")

    print(f"\n  BACKGROUND:")
    print(f"    AS33154 (DQE Communications, small PA ISP) leaked ~70,000")
    print(f"    routes to AS701 (Verizon), which propagated them globally.")
    print(f"    Affected: Cloudflare, Google, Amazon, and thousands of others.")

    print(f"\n  DATA WINDOW: 2019-06-24 10:30–12:30 UTC (RouteViews route-views2)")

    print(f"\n  OVERALL RESULTS (all routes in window):")
    print(f"    Total announcements:  {total['total']:>8,}")
    print(f"    ASPA Valid:           {total['valid']:>8,}")
    print(f"    ASPA Invalid:         {total['invalid']:>8,}")
    print(f"    ASPA Unknown:         {total['unknown']:>8,}")

    print(f"\n  DQE-SPECIFIC RESULTS (routes involving AS33154):")
    print(f"    Total routes:         {dqe['total']:>8,}")
    print(f"    ASPA Valid:           {dqe['valid']:>8,}")
    print(f"    ASPA Invalid:         {dqe['invalid']:>8,}")
    print(f"    ASPA Unknown:         {dqe['unknown']:>8,}")
    if dqe["total"] > 0:
        print(f"    Detection rate:       {100 * dqe['invalid'] / dqe['total']:>7.1f}%")

    print(f"\n  PREFIX-FILTERED RESULTS (AS33154 + victim address ranges):")
    print(f"    Total routes:         {pf['total']:>8,}")
    print(f"    ASPA Valid:           {pf['valid']:>8,}")
    print(f"    ASPA Invalid:         {pf['invalid']:>8,}")
    print(f"    ASPA Unknown:         {pf['unknown']:>8,}")
    if pf["total"] > 0:
        pf_pct = 100 * pf["invalid"] / pf["total"]
        print(f"    Detection rate:       {pf_pct:>7.1f}%")

    # Show sample leaked paths
    if results["target_leaks"]:
        print(f"\n  SAMPLE FLAGGED PATHS (AS33154 + known CDN/cloud targets):")
        shown = set()
        for detail in results["target_leaks"]:
            key = tuple(detail["as_path_clean"])
            if key in shown:
                continue
            shown.add(key)
            if len(shown) > 10:
                break
            path_str = " → ".join(
                f"[AS{a} DQE]" if a == LEAKER_ASN
                else f"[AS{a} Verizon]" if a == PROPAGATOR_ASN
                else f"AS{a}"
                for a in detail["as_path_clean"]
            )
            print(f"\n    Path:        {path_str}")
            print(f"    Prefix:      {detail['prefix']}")
            print(f"    Targets:     {', '.join(detail['targets'])}")
            print(f"    ASPA Result: {detail['aspa_result'].upper()}")
            for v_idx, v_reason in detail["violations"]:
                print(f"      ⚠ hop {v_idx}: {v_reason}")

    if pf["total"] > 0:
        pf_pct = 100 * pf["invalid"] / pf["total"]
        print(f"\n  {'=' * 61}")
        print(f"  KEY FINDING: With prefix filtering, ASPA flagged {pf['invalid']:,}")
        print(f"  of {pf['total']:,} ({pf_pct:.1f}%) routes where DQE was carrying")
        print(f"  victim traffic (Cloudflare, Google, Amazon, etc.).")
        print(f"  {'=' * 61}")

    # Save chart
    plot_incident_chart(results)

    # Save JSON output
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    save_data = {
        "incident":    "Verizon/DQE Route Leak",
        "date":        "2019-06-24",
        "leaker_asn":  LEAKER_ASN,
        "propagator_asn": PROPAGATOR_ASN,
        "data_window": "2019-06-24 10:30-12:30 UTC",
        "collector":   "route-views2",
        "caida_file":  "20190601.as-rel2.txt.bz2",
        "all_routes":       results["all_routes"],
        "dqe_routes":       results["dqe_routes"],
        "prefix_filtered":  results["prefix_filtered"],
        "sample_leak_paths": [
            {
                "prefix":      d["prefix"],
                "as_path":     d["as_path_clean"],
                "targets":     d["targets"],
                "aspa_result": d["aspa_result"],
                "violations":  d["violations"],
            }
            for d in results["target_leaks"][:20]
        ],
    }
    stats_path = os.path.join(OUTPUT_DIR, "incident_verizon.json")
    with open(stats_path, "w") as f:
        json.dump(save_data, f, indent=2)
    print(f"\n  Stats saved: {stats_path}")

    print("\nVerizon/DQE Incident Analysis COMPLETE ✓")


if __name__ == "__main__":
    main()
