"""
Shared project paths and utility functions used across all pipeline modules.
"""

import csv
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
CHARTS_DIR = os.path.join(BASE_DIR, "charts")


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
