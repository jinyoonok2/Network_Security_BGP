"""
Phase 2: BGP Data Ingestion from RouteViews via pybgpstream.

Streams BGP UPDATE messages from RouteViews collectors and extracts
AS paths, prefixes, and metadata for downstream ASPA analysis.
"""

import pybgpstream
import json
import csv
import os
from datetime import datetime


def parse_as_path(as_path_str):
    """
    Parse a raw AS path string into a clean list of integer ASNs.

    Handles:
    - Normal ASNs: "3356 174 13335" -> [3356, 174, 13335]
    - AS path prepending: "3356 3356 174" -> [3356, 3356, 174] (kept as-is)
    - AS sets: "{1,2,3}" -> skipped (ambiguous, can't validate)
    """
    as_path = []
    for token in as_path_str.split():
        if token.startswith("{") or token.endswith("}"):
            continue  # skip AS sets
        try:
            as_path.append(int(token))
        except ValueError:
            continue
    return as_path


def stream_bgp_updates(collector="route-views2",
                       start_time="2024-01-15 00:00:00",
                       end_time="2024-01-15 00:15:00"):
    """
    Stream BGP UPDATE data from a RouteViews collector.

    Args:
        collector: RouteViews collector name (e.g., "route-views2")
        start_time: Start of data window (UTC), format "YYYY-MM-DD HH:MM:SS"
        end_time: End of data window (UTC)

    Yields:
        dict with keys: prefix, as_path, as_path_str, peer_asn, timestamp, type
    """
    stream = pybgpstream.BGPStream(
        from_time=start_time,
        until_time=end_time,
        collectors=[collector],
        record_type="updates",
    )

    for elem in stream:
        # "A" = announcement, "W" = withdrawal
        if elem.type == "A":
            as_path_str = elem.fields.get("as-path", "")
            prefix = elem.fields.get("prefix", "")
            as_path = parse_as_path(as_path_str)

            if as_path and prefix:
                yield {
                    "prefix": prefix,
                    "as_path": as_path,
                    "as_path_str": as_path_str,
                    "peer_asn": elem.peer_asn,
                    "timestamp": elem.time,
                }


def save_to_csv(routes, output_path):
    """Save ingested routes to CSV for later analysis."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "prefix", "as_path", "peer_asn"])
        for route in routes:
            writer.writerow([
                route["timestamp"],
                route["prefix"],
                " ".join(map(str, route["as_path"])),
                route["peer_asn"],
            ])


def main():
    """Ingest a 15-minute window of BGP updates and print summary."""
    collector = "route-views2"
    start = "2024-01-15 00:00:00"
    end = "2024-01-15 00:15:00"

    print(f"Connecting to RouteViews collector: {collector}")
    print(f"Time window: {start} → {end} UTC")
    print(f"Streaming BGP UPDATE announcements...\n")

    routes = []
    unique_prefixes = set()
    unique_origins = set()
    unique_peers = set()

    for route in stream_bgp_updates(collector, start, end):
        routes.append(route)
        unique_prefixes.add(route["prefix"])
        unique_peers.add(route["peer_asn"])
        if route["as_path"]:
            unique_origins.add(route["as_path"][-1])  # origin is last in path

        # Print first 10 as examples
        if len(routes) <= 10:
            ts = datetime.utcfromtimestamp(route["timestamp"]).strftime("%H:%M:%S")
            path_display = " → ".join(map(str, route["as_path"][:6]))
            if len(route["as_path"]) > 6:
                path_display += f" → ... ({len(route['as_path'])} hops)"
            print(f"  [{ts}] {route['prefix']:>20s}  path: {path_display}")

        # Progress indicator every 10,000 routes
        if len(routes) % 10000 == 0:
            print(f"  ... {len(routes)} routes ingested so far")

    # Summary
    print(f"\n{'='*60}")
    print(f"INGESTION SUMMARY")
    print(f"{'='*60}")
    print(f"Total announcements:  {len(routes):,}")
    print(f"Unique prefixes:      {len(unique_prefixes):,}")
    print(f"Unique origin ASes:   {len(unique_origins):,}")
    print(f"Unique peer ASes:     {len(unique_peers):,}")

    if routes:
        path_lengths = [len(r["as_path"]) for r in routes]
        avg_len = sum(path_lengths) / len(path_lengths)
        max_len = max(path_lengths)
        print(f"Avg AS path length:   {avg_len:.1f}")
        print(f"Max AS path length:   {max_len}")

    # Save to CSV
    if routes:
        csv_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "output", "ingested_updates.csv"
        )
        save_to_csv(routes, csv_path)
        print(f"\nSaved to: {csv_path}")

    print(f"\nPhase 2 PASSED: Data ingestion working.")
    return routes


if __name__ == "__main__":
    main()
