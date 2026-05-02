"""
Incident Comparison Chart — Rostelecom 2020 vs. Verizon/DQE 2019

Reads the two incident JSON output files and produces a side-by-side
comparison visualization with two panels:

  Panel 1 (left):  Stacked bar chart — ASPA verdict breakdown for each incident
                   across three filtering levels (all routes, leaker routes,
                   prefix-filtered victim traffic).

  Panel 2 (right): Detection rate bar chart comparing the two incidents at the
                   prefix-filtered level — the most precise measure of ASPA's
                   ability to catch actual leak traffic.

Requires:
  output/incident_case_study.json   (Rostelecom — produced by incident_replay.py)
  output/incident_verizon.json      (Verizon/DQE — produced by incident_replay_verizon.py)

Produces:
  output/charts/incident_comparison.png
"""

import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import OUTPUT_DIR, CHARTS_DIR


# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------

def load_json(path, label):
    if not os.path.exists(path):
        print(f"ERROR: {label} file not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def to_pct(d):
    t = d["total"]
    if t == 0:
        return {"valid": 0, "invalid": 0, "unknown": 0}
    return {
        "valid":   100 * d["valid"]   / t,
        "invalid": 100 * d["invalid"] / t,
        "unknown": 100 * d["unknown"] / t,
    }


# ---------------------------------------------------------------------------
# Chart
# ---------------------------------------------------------------------------

def plot_comparison(rt_data, vz_data):
    os.makedirs(CHARTS_DIR, exist_ok=True)

    fig, (ax_bars, ax_detect) = plt.subplots(
        1, 2, figsize=(16, 6),
        gridspec_kw={"width_ratios": [2.2, 1]}
    )

    colors = {
        "valid":   "#2ecc71",
        "invalid": "#e74c3c",
        "unknown": "#95a5a6",
    }

    # -----------------------------------------------------------------------
    # Panel 1 — Stacked bars: 3 levels × 2 incidents = 6 bars
    # -----------------------------------------------------------------------

    # Rostelecom levels
    rt_all    = to_pct(rt_data["all_routes"])
    rt_leaker = to_pct(rt_data["rostelecom_routes"])
    rt_pf     = to_pct(rt_data["prefix_filtered"])

    # Verizon/DQE levels
    vz_all    = to_pct(vz_data["all_routes"])
    vz_leaker = to_pct(vz_data["dqe_routes"])
    vz_pf     = to_pct(vz_data["prefix_filtered"])

    # Arrange: Rostelecom trio, gap, Verizon trio
    bar_data = [rt_all, rt_leaker, rt_pf, None, vz_all, vz_leaker, vz_pf]

    bar_labels = [
        "All Routes\n(Apr 2020)",
        "Rostelecom\nRoutes",
        "Prefix-\nFiltered",
        "",
        "All Routes\n(Jun 2019)",
        "DQE\nRoutes",
        "Prefix-\nFiltered",
    ]

    # Build x positions with a gap between the two groups
    positions = [0, 1, 2, 3, 4, 5, 6]
    bar_width = 0.75

    for pos, data, label in zip(positions, bar_data, bar_labels):
        if data is None:
            continue

        v = data["valid"]
        i = data["invalid"]
        u = data["unknown"]

        ax_bars.bar(pos, v, bar_width, color=colors["valid"],   zorder=3)
        ax_bars.bar(pos, i, bar_width, color=colors["invalid"], bottom=v, zorder=3)
        ax_bars.bar(pos, u, bar_width, color=colors["unknown"], bottom=v + i, zorder=3)

        if v > 3:
            ax_bars.text(pos, v / 2, f"{v:.1f}%",
                         ha="center", va="center", fontsize=9,
                         fontweight="bold", color="white")
        if i > 3:
            ax_bars.text(pos, v + i / 2, f"{i:.1f}%",
                         ha="center", va="center", fontsize=9,
                         fontweight="bold", color="white")

    ax_bars.set_xticks(positions)
    ax_bars.set_xticklabels(bar_labels, fontsize=9.5)
    ax_bars.set_ylabel("Percentage of Routes (%)", fontsize=11)
    ax_bars.set_ylim(0, 115)
    ax_bars.set_title(
        "ASPA Verdict Breakdown by Incident and Filtering Level",
        fontsize=12, fontweight="bold", pad=12
    )
    ax_bars.yaxis.grid(True, linestyle="--", alpha=0.4, zorder=0)
    ax_bars.set_axisbelow(True)

    # Incident group labels above the bars
    ax_bars.text(1, 108, "Rostelecom 2020", ha="center", fontsize=11,
                 fontweight="bold", color="#2c3e50",
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="#ecf0f1", edgecolor="#bdc3c7"))
    ax_bars.text(5, 108, "Verizon / DQE 2019", ha="center", fontsize=11,
                 fontweight="bold", color="#2c3e50",
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="#ecf0f1", edgecolor="#bdc3c7"))

    # Vertical divider between the two groups
    ax_bars.axvline(x=3, color="#bdc3c7", linestyle="--", linewidth=1.2, zorder=2)

    # Legend
    patches = [
        mpatches.Patch(color=colors["valid"],   label="Valid"),
        mpatches.Patch(color=colors["invalid"], label="Invalid"),
        mpatches.Patch(color=colors["unknown"], label="Unknown"),
    ]
    ax_bars.legend(handles=patches, loc="upper left", fontsize=10)

    # -----------------------------------------------------------------------
    # Panel 2 — Detection rate comparison at prefix-filtered level
    # -----------------------------------------------------------------------

    rt_pf_raw = rt_data["prefix_filtered"]
    vz_pf_raw = vz_data["prefix_filtered"]

    rt_det = 100 * rt_pf_raw["invalid"] / rt_pf_raw["total"] if rt_pf_raw["total"] else 0
    vz_det = 100 * vz_pf_raw["invalid"] / vz_pf_raw["total"] if vz_pf_raw["total"] else 0

    incident_labels = ["Rostelecom\n(Apr 2020)", "Verizon/DQE\n(Jun 2019)"]
    detection_rates = [rt_det, vz_det]
    bar_colors      = ["#e67e22", "#8e44ad"]

    bars = ax_detect.bar(incident_labels, detection_rates, color=bar_colors,
                         width=0.45, zorder=3)

    for bar, rate in zip(bars, detection_rates):
        ax_detect.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1.5,
            f"{rate:.1f}%",
            ha="center", va="bottom", fontsize=14, fontweight="bold",
        )

    # Route counts as small text just below each % label
    ax_detect.text(
        bars[0].get_x() + bars[0].get_width() / 2,
        bars[0].get_height() + 9,
        f"({rt_pf_raw['invalid']:,} / {rt_pf_raw['total']:,})",
        ha="center", va="bottom", fontsize=7.5, color="#777"
    )
    ax_detect.text(
        bars[1].get_x() + bars[1].get_width() / 2,
        bars[1].get_height() + 9,
        f"({vz_pf_raw['invalid']:,} / {vz_pf_raw['total']:,})",
        ha="center", va="bottom", fontsize=7.5, color="#777"
    )

    ax_detect.set_ylabel("Detection Rate — Prefix-Filtered (%)", fontsize=10.5)
    ax_detect.set_ylim(0, 130)
    ax_detect.set_title(
        "ASPA Detection Rate\n(Victim Traffic Only)",
        fontsize=12, fontweight="bold", pad=12
    )
    ax_detect.yaxis.grid(True, linestyle="--", alpha=0.4, zorder=0)
    ax_detect.set_axisbelow(True)

    # Rostelecom annotation — text right of bar, arrow pointing left to bar
    ax_detect.annotate(
        "Large carrier:\nmany legitimate\nrelationships\n→ low catch rate",
        xy=(bars[0].get_x() + bars[0].get_width(), rt_det),
        xytext=(0.55, 30),
        fontsize=8.5, color="#e67e22", ha="center",
        arrowprops=dict(arrowstyle="->", color="#e67e22", lw=1.2),
    )

    # Verizon annotation — text left of center, arrow pointing right to bar edge
    ax_detect.annotate(
        "Tiny ISP:\nno legitimate\nglobal paths\n→ 100% catch rate",
        xy=(bars[1].get_x(), 60),
        xytext=(0.2, 60),
        fontsize=8.5, color="#8e44ad", ha="center",
        arrowprops=dict(arrowstyle="->", color="#8e44ad", lw=1.2),
    )

    plt.tight_layout()
    out_path = os.path.join(CHARTS_DIR, "incident_comparison.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")

    plt.close()
    print(f"Chart saved: {out_path}")
    return out_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    rt_path = os.path.join(OUTPUT_DIR, "incident_case_study.json")
    vz_path = os.path.join(OUTPUT_DIR, "incident_verizon.json")

    print("Loading incident data …")
    rt_data = load_json(rt_path, "Rostelecom")
    vz_data = load_json(vz_path, "Verizon/DQE")

    print("Generating comparison chart …")
    out = plot_comparison(rt_data, vz_data)

    print("\nSummary:")
    rt_pf = rt_data["prefix_filtered"]
    vz_pf = vz_data["prefix_filtered"]
    print(f"  Rostelecom 2020 — prefix-filtered detection: "
          f"{100*rt_pf['invalid']/rt_pf['total']:.1f}%  "
          f"({rt_pf['invalid']:,} / {rt_pf['total']:,} routes)")
    print(f"  Verizon/DQE 2019 — prefix-filtered detection: "
          f"{100*vz_pf['invalid']/vz_pf['total']:.1f}%  "
          f"({vz_pf['invalid']:,} / {vz_pf['total']:,} routes)")
    print(f"\nComparison chart saved: {out}")


if __name__ == "__main__":
    main()
