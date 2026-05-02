"""
Research 11.4: Path Length as Leak Predictor

Compares AS-path length distributions of ASPA-valid vs. ASPA-invalid routes.
Route leaks tend to create longer paths because the leaked path traverses
extra (unauthorized) ASes.

Produces:
  - output/charts/path_length_cdf.png
  - Console output: mean, median, KS test result with p-value
"""

import csv
import os
import sys
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats as scistat

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import OUTPUT_DIR, CHARTS_DIR


def load_path_lengths(all_results_csv):
    """Load path lengths grouped by ASPA result from all_results CSV."""
    groups = {"valid": [], "invalid": [], "unknown": []}

    with open(all_results_csv, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            result = row["result"]
            path_len = len(row["as_path"].split())
            if result in groups:
                groups[result].append(path_len)

    return groups


def compute_statistics(groups):
    """Compute descriptive statistics and hypothesis test."""
    valid = np.array(groups["valid"])
    invalid = np.array(groups["invalid"])

    stats_dict = {}
    for label, arr in [("valid", valid), ("invalid", invalid), ("unknown", np.array(groups["unknown"]))]:
        if len(arr) == 0:
            continue
        stats_dict[label] = {
            "count": len(arr),
            "mean": round(float(np.mean(arr)), 2),
            "median": float(np.median(arr)),
            "std": round(float(np.std(arr)), 2),
            "min": int(np.min(arr)),
            "max": int(np.max(arr)),
            "q25": float(np.percentile(arr, 25)),
            "q75": float(np.percentile(arr, 75)),
        }

    # Mann-Whitney U test (non-parametric, doesn't assume normality)
    if len(valid) > 0 and len(invalid) > 0:
        u_stat, p_mw = scistat.mannwhitneyu(valid, invalid, alternative="two-sided")
        stats_dict["mann_whitney_u"] = {
            "U_statistic": float(u_stat),
            "p_value": float(p_mw),
            "significant_at_001": p_mw < 0.001,
        }

    # Kolmogorov-Smirnov test
    if len(valid) > 0 and len(invalid) > 0:
        ks_stat, p_ks = scistat.ks_2samp(valid, invalid)
        stats_dict["ks_test"] = {
            "KS_statistic": round(float(ks_stat), 4),
            "p_value": float(p_ks),
            "significant_at_001": p_ks < 0.001,
        }

    return stats_dict


def plot_cdf(groups):
    """Generate CDF comparison plot."""
    os.makedirs(CHARTS_DIR, exist_ok=True)

    fig, (ax_cdf, ax_hist) = plt.subplots(1, 2, figsize=(14, 5.5))

    colors = {"valid": "#2ecc71", "invalid": "#e74c3c", "unknown": "#95a5a6"}
    labels = {"valid": f"Valid (n={len(groups['valid']):,})",
              "invalid": f"Invalid (n={len(groups['invalid']):,})",
              "unknown": f"Unknown (n={len(groups['unknown']):,})"}

    # --- CDF ---
    for key in ["valid", "invalid"]:
        arr = sorted(groups[key])
        if not arr:
            continue
        cdf = np.arange(1, len(arr) + 1) / len(arr)
        ax_cdf.step(arr, cdf, linewidth=2, color=colors[key], label=labels[key])

    ax_cdf.set_xlabel("AS Path Length", fontsize=12)
    ax_cdf.set_ylabel("Cumulative Probability", fontsize=12)
    ax_cdf.set_title("CDF: Path Length — Valid vs. Invalid Routes", fontsize=13, fontweight="bold")
    ax_cdf.legend(fontsize=10)
    ax_cdf.grid(alpha=0.3)
    ax_cdf.set_xlim(0, 20)

    # --- Histogram ---
    max_len = min(20, max(max(groups["valid"], default=0), max(groups["invalid"], default=0)))
    bins = range(1, max_len + 2)

    for key in ["valid", "invalid"]:
        if groups[key]:
            ax_hist.hist(groups[key], bins=bins, alpha=0.5, color=colors[key],
                        label=labels[key], density=True, edgecolor="white")

    ax_hist.set_xlabel("AS Path Length", fontsize=12)
    ax_hist.set_ylabel("Density", fontsize=12)
    ax_hist.set_title("Distribution: Path Length — Valid vs. Invalid", fontsize=13, fontweight="bold")
    ax_hist.legend(fontsize=10)
    ax_hist.grid(axis="y", alpha=0.3)

    fig.tight_layout()
    out_path = os.path.join(CHARTS_DIR, "path_length_cdf.png")
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    print(f"  Chart saved: {out_path}")
    return out_path


def main():
    all_csv = os.path.join(OUTPUT_DIR, "all_results_caida.csv")
    if not os.path.exists(all_csv):
        print("ERROR: Run Phase 4 (analyze.py) first.")
        sys.exit(1)

    print("=" * 65)
    print("RESEARCH 11.4: Path Length as Leak Predictor")
    print("=" * 65)

    print("\n  Loading path lengths …")
    groups = load_path_lengths(all_csv)
    print(f"  Valid: {len(groups['valid']):,}  |  Invalid: {len(groups['invalid']):,}  |  Unknown: {len(groups['unknown']):,}")

    print("\n  Computing statistics …")
    stats = compute_statistics(groups)

    # Print results
    print(f"\n{'=' * 65}")
    print(f"PATH LENGTH STATISTICS")
    print(f"{'=' * 65}")

    for label in ["valid", "invalid"]:
        if label in stats:
            s = stats[label]
            print(f"\n  {label.upper()} routes (n={s['count']:,}):")
            print(f"    Mean:   {s['mean']:.2f}")
            print(f"    Median: {s['median']:.1f}")
            print(f"    Std:    {s['std']:.2f}")
            print(f"    Range:  [{s['min']}, {s['max']}]")
            print(f"    IQR:    [{s['q25']:.0f}, {s['q75']:.0f}]")

    if "mann_whitney_u" in stats:
        mw = stats["mann_whitney_u"]
        print(f"\n  Mann-Whitney U test:")
        print(f"    U statistic:  {mw['U_statistic']:,.0f}")
        print(f"    p-value:      {mw['p_value']:.2e}")
        print(f"    Significant at α=0.001: {'YES ✓' if mw['significant_at_001'] else 'NO'}")

    if "ks_test" in stats:
        ks = stats["ks_test"]
        print(f"\n  Kolmogorov-Smirnov test:")
        print(f"    KS statistic: {ks['KS_statistic']:.4f}")
        print(f"    p-value:      {ks['p_value']:.2e}")
        print(f"    Significant at α=0.001: {'YES ✓' if ks['significant_at_001'] else 'NO'}")

    # Interpretation
    if "valid" in stats and "invalid" in stats:
        diff = stats["invalid"]["mean"] - stats["valid"]["mean"]
        print(f"\n  → Invalid paths are {diff:+.2f} hops longer on average")

    # Plot
    plot_cdf(groups)

    print("\nResearch 11.4 COMPLETE ✓")


if __name__ == "__main__":
    main()
