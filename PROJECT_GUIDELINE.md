# BGP Route Leaks & ASPA Validation — Project Guideline

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture](#2-architecture)
3. [Phase 1: Environment Setup](#3-phase-1-environment-setup)
4. [Phase 2: Data Ingestion](#4-phase-2-data-ingestion)
5. [Phase 3: Cryptographic Cache Setup](#5-phase-3-cryptographic-cache-setup)
6. [Phase 4: The Analysis Engine](#6-phase-4-the-analysis-engine)
7. [Phase 5: Exploration & Write-up](#7-phase-5-exploration--write-up)
8. [Directory Structure](#8-directory-structure)
9. [Key Concepts Reference](#9-key-concepts-reference)
10. [Risk & Troubleshooting](#10-risk--troubleshooting)

---

## 1. Project Overview

### What We Are Building

An **automated BGP route-leak monitor** that:

1. Ingests real, historical BGP routing data (MRT dumps from RouteViews/RIPE RIS).
2. Loads cryptographically signed ASPA records from the global RPKI.
3. Runs every observed AS path through the ASPA validation algorithm (draft-ietf-sidrops-aspa-verification).
4. Flags invalid routes and produces quantitative statistics on how many leaks ASPA would have caught.

### Core Question We Answer

> "If every network on the internet enforced ASPA today, what percentage of historically observed BGP routes would have been blocked as illegitimate?"

### Key Terms

| Term | Definition |
|------|-----------|
| **BGP** | Border Gateway Protocol — the routing protocol that connects Autonomous Systems on the internet. |
| **AS (Autonomous System)** | A network or group of networks under a single administrative domain, identified by a unique AS Number (ASN). |
| **AS Path** | The ordered sequence of ASNs a BGP route announcement has traversed. |
| **Route Leak** | Propagation of a BGP announcement beyond its intended scope (e.g., a customer re-announcing a provider's route to another provider). |
| **RPKI** | Resource Public Key Infrastructure — a cryptographic framework that binds internet resources (IPs, ASNs) to public keys. |
| **ROA** | Route Origin Authorization — an RPKI object that authorizes an AS to originate a prefix. |
| **ASPA** | Autonomous System Provider Authorization — an RPKI object that lists the authorized upstream providers for a given customer AS. |
| **MRT** | Multi-threaded Routing Toolkit — the binary format used to store BGP routing table dumps. |
| **Routinator** | An open-source RPKI relying-party software that fetches, validates, and caches RPKI objects (ROAs and ASPAs). |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Data Sources                         │
│  ┌──────────────┐          ┌──────────────────────┐     │
│  │  RouteViews / │          │  RPKI Repositories   │     │
│  │  RIPE RIS     │          │  (via Routinator)    │     │
│  │  (MRT dumps)  │          │                      │     │
│  └──────┬───────┘          └──────────┬───────────┘     │
└─────────┼──────────────────────────────┼────────────────┘
          │                              │
          ▼                              ▼
┌──────────────────┐          ┌──────────────────────┐
│  pybgpstream      │          │  Routinator          │
│  (Python library)  │          │  (local RPKI cache)  │
│  Parses MRT →     │          │  Serves ASPA objects │
│  yields AS Paths  │          │  via RTR / JSON API  │
└────────┬─────────┘          └──────────┬───────────┘
         │                               │
         ▼                               ▼
┌────────────────────────────────────────────────────────┐
│              Analysis Engine (Python)                   │
│                                                        │
│  1. Read AS path from pybgpstream                      │
│  2. For each adjacent pair (AS_i, AS_i+1) in path:     │
│     → Query ASPA records: Is AS_i+1 an authorized      │
│       provider of AS_i?                                │
│  3. Apply ASPA verification algorithm:                 │
│     → Valid / Invalid / Unknown                        │
│  4. Log invalid routes to CSV                          │
└────────────────────┬───────────────────────────────────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────┐
│                   Output & Analysis                     │
│                                                        │
│  • flagged_routes.csv  — every invalid route + reason  │
│  • statistics.json     — summary metrics               │
│  • charts (matplotlib) — visual breakdown              │
│  • final report (PDF/MD)                               │
└────────────────────────────────────────────────────────┘
```

### Technology Stack

| Component | Tool | Why |
|-----------|------|-----|
| Language | Python 3.10+ | Best library ecosystem for BGP research |
| Environment | Miniconda | Isolated dependencies, reproducible builds |
| BGP data parsing | libbgpstream + pybgpstream | Industry-standard MRT parser, access to RouteViews & RIPE RIS |
| RPKI cache | Routinator 0.13+ | Most mature open-source RPKI relying party with ASPA support |
| Data analysis | pandas | Efficient tabular data operations |
| Visualization | matplotlib / seaborn | Publication-quality charts |
| Output | CSV + JSON | Machine-readable, easy to import into report |

---

## 3. Phase 1: Environment Setup

### Goal
A working Linux environment with all dependencies installed and verified.

### Steps

#### 1.1 Install Miniconda (if not already installed)

```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh
# Follow prompts, then restart terminal
```

#### 1.2 Create the project Conda environment

```bash
conda create -n bgp_aspa python=3.10 -y
conda activate bgp_aspa
```

#### 1.3 Install system-level dependencies (libbgpstream)

BGPStream is a C library; pybgpstream is its Python binding.

```bash
# Add CAIDA's BGPStream repo (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y build-essential curl libssl-dev zlib1g-dev

# Install libbgpstream from source or package
# Option A: From CAIDA apt repo (preferred)
curl -s https://pkg.caida.org/os/ubuntu/bootstrap.sh | sudo bash
sudo apt-get install -y bgpstream

# Option B: From source (fallback)
# git clone https://github.com/CAIDA/libbgpstream.git
# cd libbgpstream && mkdir build && cd build
# cmake .. && make && sudo make install && sudo ldconfig
```

#### 1.4 Install Python dependencies

```bash
conda activate bgp_aspa
pip install pybgpstream pandas matplotlib seaborn requests
```

#### 1.5 Verification checkpoint

```python
# test_setup.py — run this to verify everything works
import pybgpstream
print("pybgpstream version:", pybgpstream.__version__ if hasattr(pybgpstream, '__version__') else "OK (imported)")
print("Phase 1 PASSED: All dependencies installed.")
```

Expected output: No import errors.

### Deliverables
- [x] Miniconda environment `bgp_aspa` created
- [x] libbgpstream installed at system level
- [x] pybgpstream importable in Python
- [x] All Python packages installed

---

## 4. Phase 2: Data Ingestion

### Goal
Prove the pipeline can read real BGP routing data and extract AS paths.

### Steps

#### 2.1 Understand data sources

| Source | URL | What It Provides |
|--------|-----|-------------------|
| RouteViews | http://archive.routeviews.org | Historical MRT RIB dumps and BGP updates from multiple vantage points |
| RIPE RIS | https://data.ris.ripe.net | Same as above, European vantage points |

We will use **RouteViews** as the primary source. Each collector (e.g., `route-views2`) stores periodic RIB (Routing Information Base) snapshots and continuous UPDATE files in MRT format.

#### 2.2 Choose a data window

Pick a specific, narrow time window to start (e.g., a 15-minute update file or a single RIB snapshot). This keeps initial runs fast.

The format for pybgpstream:
- **RIB dump**: Full routing table snapshot. Large (~2 GB compressed). Use for baseline analysis.
- **Updates**: Incremental BGP announcements/withdrawals. Smaller. Use for live-event analysis.

**Recommendation**: Start with a **single 15-minute UPDATE file** from one collector for development, then scale to a full RIB dump for final analysis.

#### 2.3 Write the ingestion script

```python
# ingest.py — Phase 2 data ingestion script

import pybgpstream
from datetime import datetime

def stream_bgp_data(collector="route-views2",
                    record_type="updates",
                    start_time="2024-01-15 00:00:00",
                    end_time="2024-01-15 00:15:00"):
    """
    Stream BGP data from RouteViews using pybgpstream.

    Args:
        collector: RouteViews collector name
        record_type: "updates" or "ribs"
        start_time: Start of data window (UTC)
        end_time: End of data window (UTC)

    Yields:
        dict with keys: prefix, as_path, peer_asn, timestamp
    """
    stream = pybgpstream.BGPStream(
        from_time=start_time,
        until_time=end_time,
        collectors=[collector],
        record_type=record_type,
    )

    for elem in stream:
        if elem.type == "A":  # Announcement
            as_path_str = elem.fields.get("as-path", "")
            prefix = elem.fields.get("prefix", "")

            # Parse AS path into list of ASNs
            # Handle AS sets {1,2,3} by skipping them
            as_path = []
            for token in as_path_str.split():
                if token.startswith("{"):
                    continue  # skip AS sets
                try:
                    as_path.append(int(token))
                except ValueError:
                    continue

            if as_path:
                yield {
                    "prefix": prefix,
                    "as_path": as_path,
                    "peer_asn": elem.peer_asn,
                    "timestamp": elem.time,
                }


if __name__ == "__main__":
    count = 0
    for route in stream_bgp_data():
        print(f"Prefix: {route['prefix']}, AS Path: {route['as_path']}")
        count += 1
        if count >= 20:  # Print first 20 for verification
            break
    print(f"\nTotal routes read: {count}")
    print("Phase 2 PASSED: Data ingestion working.")
```

#### 2.4 Verification checkpoint

Run `python ingest.py` and confirm:
- The script connects to RouteViews without errors.
- At least one AS path is printed.
- The AS path is a clean list of integers (e.g., `[3356, 174, 13335]`).

#### 2.5 Optional: Download MRT file manually (offline mode)

```bash
# Download a single MRT update file for offline development
mkdir -p data/
wget -P data/ http://archive.routeviews.org/bgpdata/2024.01/UPDATES/updates.20240115.0000.bz2
```

pybgpstream can also read from local files:
```python
stream = pybgpstream.BGPStream(data_interface="singlefile")
stream.set_data_interface_option("singlefile", "upd-file", "data/updates.20240115.0000.bz2")
```

### Deliverables
- [x] `ingest.py` script that streams BGP data
- [x] Confirmed ability to parse AS paths from real MRT data
- [x] Understanding of RouteViews data structure

---

## 5. Phase 3: Cryptographic Cache Setup

### Goal
A running Routinator instance that serves RPKI data (including ASPA objects) from a local cache.

### Steps

#### 3.1 Install Routinator

```bash
# Install Rust toolchain (Routinator is written in Rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Routinator
cargo install routinator

# Verify
routinator --version
```

#### 3.2 Initialize the RPKI cache

```bash
# First-time setup: accept ARIN's Terms of Service and download trust anchors
routinator init --accept-arin-rpa
```

This downloads the five Regional Internet Registry (RIR) Trust Anchor Locators (TALs):
- AFRINIC, APNIC, ARIN, LACNIC, RIPE NCC

#### 3.3 Run Routinator and validate the cache

```bash
# Run a one-time validation (downloads all RPKI objects)
routinator vrps --output-format json > data/rpki_vrps.json

# Or run as a persistent server with HTTP API (recommended)
routinator server --http 127.0.0.1:8323 --rtr 127.0.0.1:3323
```

When running as a server, Routinator provides:
- **HTTP API** on port 8323 — queryable for VRPs (Validated ROA Payloads) and ASPA data
- **RTR protocol** on port 3323 — for router integration (not needed for us)

#### 3.4 Verify ASPA data availability

```bash
# Check if ASPA objects are being served
curl http://127.0.0.1:8323/api/v1/status
```

> **Important Note on ASPA Data Availability:**
> ASPA is a *new* standard (still in draft as of early 2025). The number of published ASPA objects in the global RPKI is still very small. This is expected and is itself a finding for the report.
>
> **Fallback Strategy:** If Routinator's ASPA data is too sparse for meaningful analysis, we will:
> 1. Use the available ASPA records as-is and report on the current deployment state.
> 2. Supplement with **simulated ASPA records** derived from CAIDA's AS-relationship dataset to model what "full ASPA deployment" would look like.
> 3. Clearly label simulated vs. real data in the report.

#### 3.5 CAIDA AS-Relationship Data (Supplemental)

CAIDA publishes inferred AS relationships (customer-provider, peer-peer):
```bash
# Download CAIDA AS-relationship dataset
# Available at: https://www.caida.org/catalog/datasets/as-relationships/
# File format: <provider-as>|<customer-as>|<relationship-type>
# relationship-type: -1 = provider-to-customer, 0 = peer-to-peer

mkdir -p data/
# Download requires CAIDA account — use the serial-2 dataset
wget -P data/ https://publicdata.caida.org/datasets/as-relationships/serial-2/20240101.as-rel2.txt.bz2
```

This dataset allows us to build a comprehensive provider-customer map to simulate full ASPA deployment.

#### 3.6 Build the ASPA lookup module

```python
# aspa_cache.py — loads ASPA data into memory for fast lookups

class ASPACache:
    """
    Stores ASPA records: for each customer ASN, a set of authorized provider ASNs.
    """

    def __init__(self):
        # {customer_asn: set(provider_asn_1, provider_asn_2, ...)}
        self.aspa_records = {}

    def load_from_routinator(self, api_url="http://127.0.0.1:8323"):
        """Load real ASPA records from Routinator's HTTP API."""
        # Implementation depends on Routinator's ASPA endpoint
        pass

    def load_from_caida_relationships(self, filepath):
        """
        Build simulated ASPA records from CAIDA AS-relationship data.
        For each customer AS, its authorized providers = all ASes marked
        as its providers in the CAIDA dataset.
        """
        pass

    def get_providers(self, customer_asn):
        """Return set of authorized provider ASNs for a customer, or None if no record."""
        return self.aspa_records.get(customer_asn)

    def has_record(self, customer_asn):
        """Check if an ASPA record exists for this customer ASN."""
        return customer_asn in self.aspa_records
```

### Deliverables
- [x] Routinator installed and initialized
- [x] RPKI cache populated with current data
- [x] ASPA data accessibility confirmed (real or simulated via CAIDA)
- [x] `aspa_cache.py` module with provider lookup interface

---

## 6. Phase 4: The Analysis Engine

### Goal
Combine BGP data (Phase 2) with ASPA records (Phase 3) to validate every observed AS path and flag leaks.

### Steps

#### 4.1 Understand the ASPA Verification Algorithm

The ASPA verification algorithm (RFC draft-ietf-sidrops-aspa-verification) checks the **upstream path** for unauthorized hops. The core logic:

**For an AS path `[AS_1, AS_2, ..., AS_n]` (where AS_1 is the origin):**

The algorithm walks the path and checks each hop direction:

```
Direction types between adjacent ASes:
  - Customer → Provider  (normal upstream, VALID)
  - Provider → Customer  (normal downstream, VALID)
  - Peer → Peer          (lateral, VALID at most once)
  - Customer → Provider → Customer  (valley — INVALID, this is a route leak)
```

**Simplified ASPA check for a pair (AS_i, AS_i+1):**

1. Look up the ASPA record for AS_i.
2. If AS_i has an ASPA record and AS_i+1 is **not** in the authorized provider set → the hop is **invalid** (unless AS_i+1 is a customer of AS_i, which we infer from the reverse ASPA record or CAIDA data).
3. If AS_i has no ASPA record → the hop is **unknown** (we cannot validate it).

**Full path validation states:**
- **Valid**: All hops are consistent with ASPA records.
- **Invalid**: At least one hop violates ASPA (a detected route leak).
- **Unknown**: Not enough ASPA records exist to make a determination.

#### 4.2 Implement the ASPA verifier

```python
# aspa_verifier.py — ASPA path validation engine

from enum import Enum

class ASPAResult(Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"

class HopRole(Enum):
    CUSTOMER = "customer"
    PROVIDER = "provider"
    PEER = "peer"
    UNKNOWN = "unknown"

def classify_hop(customer_asn, neighbor_asn, aspa_cache, relationship_map):
    """
    Determine the role of neighbor_asn relative to customer_asn.
    Returns HopRole.
    """
    pass

def verify_as_path(as_path, aspa_cache, relationship_map):
    """
    Run ASPA verification on a full AS path.

    Args:
        as_path: list of ASNs [origin, ..., last_hop]
        aspa_cache: ASPACache instance
        relationship_map: dict of AS relationships

    Returns:
        ASPAResult, list of (hop_index, reason) for any violations
    """
    pass
```

#### 4.3 Detailed verification logic (pseudocode)

```
function verify_as_path(path, aspa_cache):
    # Remove prepending (consecutive duplicate ASNs)
    clean_path = remove_prepends(path)

    if len(clean_path) <= 1:
        return VALID  # Single-AS path, nothing to check

    # Walk the path checking for "valley" violations
    # A valley = traffic goes UP (customer→provider), then DOWN (provider→customer),
    # then UP again (customer→provider). This is a route leak.

    # Step 1: Forward check (from origin toward collector)
    direction_changes = []
    for i in range(len(clean_path) - 1):
        current_as = clean_path[i]
        next_as = clean_path[i + 1]

        providers = aspa_cache.get_providers(current_as)
        if providers is None:
            direction_changes.append("unknown")
        elif next_as in providers:
            direction_changes.append("up")     # customer → provider (valid upstream)
        else:
            direction_changes.append("not-provider")  # could be peer or customer

    # Step 2: Reverse check (from collector toward origin)
    # ... (similar logic walking backwards)

    # Step 3: Detect valleys
    # If we see UP → DOWN → UP, that's a valley = route leak
    # Return INVALID if valley detected, VALID otherwise
```

#### 4.4 Build the main analysis pipeline

```python
# analyze.py — main pipeline combining ingestion + verification

import csv
from ingest import stream_bgp_data
from aspa_cache import ASPACache
from aspa_verifier import verify_as_path, ASPAResult

def run_analysis(output_csv="output/flagged_routes.csv"):
    """Main analysis pipeline."""

    # 1. Load ASPA cache
    cache = ASPACache()
    cache.load_from_caida_relationships("data/20240101.as-rel2.txt.bz2")
    # cache.load_from_routinator()  # if available

    # 2. Initialize counters
    stats = {"total": 0, "valid": 0, "invalid": 0, "unknown": 0}

    # 3. Open output CSV
    with open(output_csv, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "prefix", "as_path", "result",
            "violation_hops", "peer_asn"
        ])

        # 4. Stream BGP data and validate each path
        for route in stream_bgp_data():
            result, violations = verify_as_path(
                route["as_path"], cache, None
            )

            stats["total"] += 1
            stats[result.value] += 1

            # Log invalid routes
            if result == ASPAResult.INVALID:
                writer.writerow([
                    route["timestamp"],
                    route["prefix"],
                    " ".join(map(str, route["as_path"])),
                    result.value,
                    str(violations),
                    route["peer_asn"],
                ])

    return stats
```

#### 4.5 Output format

**flagged_routes.csv columns:**

| Column | Description |
|--------|-------------|
| `timestamp` | Unix timestamp of the BGP announcement |
| `prefix` | IP prefix being announced (e.g., `1.0.0.0/24`) |
| `as_path` | Full AS path as space-separated ASNs |
| `result` | `invalid` (all entries in this file are invalid) |
| `violation_hops` | List of (index, reason) tuples showing which hops failed |
| `peer_asn` | The ASN of the BGP peer that reported this route |

#### 4.6 Verification checkpoint

Run `python analyze.py` on a small dataset (15-min update window) and confirm:
- The script completes without errors.
- `flagged_routes.csv` is generated with at least some entries.
- Stats printed show a breakdown of valid/invalid/unknown.

### Deliverables
- [x] `aspa_verifier.py` with full ASPA path validation
- [x] `analyze.py` main pipeline
- [x] `output/flagged_routes.csv` generated from real data
- [x] Stats summary printed to console

---

## 7. Phase 5: Exploration & Write-up

### Goal
Analyze the flagged routes, compute meaningful statistics, generate visualizations, and compile a final report.

### Steps

#### 5.1 Statistical analysis

Using the CSV output from Phase 4, compute:

| Metric | Description |
|--------|-------------|
| **Leak rate** | % of total routes flagged as invalid |
| **Coverage rate** | % of routes where ASPA could make a determination (valid + invalid vs unknown) |
| **Top offending ASNs** | Which ASes appear most frequently in invalid paths? |
| **Geographic distribution** | Map offending ASNs to countries/regions (using CAIDA's AS-to-org mapping) |
| **Prefix impact** | How many unique prefixes are affected by leaks? |
| **Temporal pattern** | Are leaks concentrated at specific times? |

#### 5.2 Visualization targets

1. **Pie chart**: Valid vs. Invalid vs. Unknown breakdown
2. **Bar chart**: Top 20 ASNs by number of route leak violations
3. **Time series**: Number of invalid routes per time bucket (5-min intervals)
4. **Heatmap**: Geographic distribution of leak sources (optional, requires AS-to-country mapping)
5. **CDF**: Cumulative distribution of AS path lengths for valid vs. invalid routes

```python
# visualize.py — generate charts from analysis output

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def generate_all_charts(csv_path="output/flagged_routes.csv",
                         stats_path="output/statistics.json"):
    """Generate all visualization charts."""

    df = pd.read_csv(csv_path)

    # Chart 1: Breakdown pie chart
    # Chart 2: Top offending ASNs
    # Chart 3: Time series of invalid routes
    # ...
    pass
```

#### 5.3 Report outline

```
1. Abstract
   - One paragraph summarizing the project, method, and key finding.

2. Introduction
   - What is BGP and why is it insecure?
   - What are route leaks and why do they matter?
   - What is ASPA and how does it fix this?

3. Background & Related Work
   - BGP security history (prefix hijacking incidents)
   - RPKI and ROA (the predecessor to ASPA)
   - ASPA draft standard (cite draft-ietf-sidrops-aspa-verification)
   - Prior measurement studies on BGP security

4. Methodology
   - Data sources (RouteViews, RPKI, CAIDA)
   - ASPA verification algorithm implementation
   - Simulation assumptions (if using CAIDA-derived ASPA records)

5. Results
   - Overall leak detection rate
   - Top offending networks
   - Geographic and temporal patterns
   - Comparison: real ASPA records vs. simulated full deployment

6. Discussion
   - What do these numbers mean for internet security?
   - Limitations of the study
   - Implications for ASPA adoption

7. Conclusion
   - Key takeaways
   - Future work
```

### Deliverables
- [x] `visualize.py` generates all charts
- [x] `output/` directory contains CSV, JSON stats, and PNG charts
- [x] Final report with analysis and findings

---

## 8. Directory Structure

```
Network_Security_BGP/
├── PROJECT_GUIDELINE.md        ← This file
├── README.md                   ← Project README
│
├── data/                       ← Raw data (gitignored)
│   ├── updates.*.bz2          ← Downloaded MRT files
│   ├── rpki_vrps.json         ← RPKI cache export
│   └── *.as-rel2.txt.bz2     ← CAIDA relationship data
│
├── src/                        ← Source code
│   ├── ingest.py              ← Phase 2: BGP data ingestion
│   ├── aspa_cache.py          ← Phase 3: ASPA record loader
│   ├── aspa_verifier.py       ← Phase 4: ASPA validation engine
│   ├── analyze.py             ← Phase 4: Main analysis pipeline
│   └── visualize.py           ← Phase 5: Chart generation
│
├── output/                     ← Analysis output (gitignored)
│   ├── flagged_routes.csv     ← Invalid routes log
│   ├── statistics.json        ← Summary metrics
│   └── charts/                ← Generated visualizations
│       ├── breakdown_pie.png
│       ├── top_offenders.png
│       └── time_series.png
│
├── tests/                      ← Unit tests
│   ├── test_ingest.py
│   ├── test_aspa_cache.py
│   └── test_aspa_verifier.py
│
├── report/                     ← Final report
│   └── report.md
│
├── environment.yml             ← Conda environment spec
└── .gitignore
```

---

## 9. Key Concepts Reference

### The Valley-Free Property

Legitimate BGP routes follow a "valley-free" structure:

```
      Provider          Provider
       /    \            /    \
      /      \          /      \
  Customer  Customer  Customer  Customer

Valid paths go: UP* PEER? DOWN*
  → Zero or more UPs, at most one PEER, then zero or more DOWNs.

Invalid (valley / route leak):
  UP → DOWN → UP  ← traffic goes up, comes down, then goes back up
                     This means a customer is transiting traffic
                     between two providers (route leak!)
```

### ASPA Verification Walk-through Example

```
AS Path: [AS1, AS2, AS3, AS4]   (AS1 = origin, AS4 = collector's peer)

ASPA Records:
  AS1 → providers: {AS2}       ← AS1 says AS2 is its provider
  AS2 → providers: {AS5}       ← AS2 says AS5 is its provider (NOT AS3!)
  AS3 → providers: {AS4}       ← AS3 says AS4 is its provider

Check hop AS1→AS2: AS2 is in AS1's provider set → ✅ valid (upstream)
Check hop AS2→AS3: AS3 is NOT in AS2's provider set
                   AS2 is NOT in AS3's provider set
                   → Neither is provider of the other
                   → Could be peer-to-peer or a LEAK
Check hop AS3→AS4: AS4 is in AS3's provider set → ✅ valid (upstream)

Result: UP → ??? → UP = VALLEY detected → ❌ INVALID (route leak)
```

### Relationship Between ROA and ASPA

```
ROA  = "Who is allowed to ORIGINATE a prefix?"
       (Validates the first AS in the path)

ASPA = "Who is allowed to be an UPSTREAM PROVIDER?"
       (Validates the structure of the entire path)

Together: ROA checks the origin, ASPA checks the path.
```

---

## 10. Risk & Troubleshooting

### Known Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| ASPA adoption is near-zero | Very few real ASPA records to validate against | Use CAIDA AS-relationship data to simulate full deployment |
| pybgpstream installation fails | Cannot ingest BGP data | Build libbgpstream from source; use Docker container as fallback |
| Routinator lacks ASPA endpoint | Cannot query ASPA records via API | Export RPKI objects manually; rely on CAIDA simulation |
| Large MRT files slow processing | Analysis takes too long | Start with small time windows (15 min); use multiprocessing |
| AS path prepending creates noise | Inflated path lengths | Strip consecutive duplicate ASNs before validation |

### Troubleshooting Commands

```bash
# Check if pybgpstream C library is linked correctly
python -c "import pybgpstream; print('OK')"

# Check Routinator status
curl http://127.0.0.1:8323/api/v1/status

# Check how many RPKI objects Routinator has cached
routinator vrps --format json | python3 -c "import sys,json; data=json.load(sys.stdin); print(f'VRPs: {len(data)}')"

# Test BGPStream connectivity to RouteViews
python -c "
import pybgpstream
s = pybgpstream.BGPStream(from_time='2024-01-15 00:00:00', until_time='2024-01-15 00:01:00', collectors=['route-views2'], record_type='updates')
count = sum(1 for _ in s)
print(f'Records: {count}')
"
```

---

## 11. Extended Research (Post-Baseline Enhancements)

Once the baseline pipeline (Phases 1–5) is complete and working, these enhancements push the project from "good" to "excellent" at the master's level. They are organized into three tiers by impact-to-effort ratio.

---

### Tier 1 — Must-Do (Highest Payoff)

#### 11.1 Partial Deployment Curve

Instead of binary "0% vs. 100% ASPA deployment," model incremental adoption:

1. Randomly select X% of ASes to have ASPA records (from CAIDA data).
2. Run the analysis engine with only that subset.
3. Repeat for X = 10%, 20%, 30%, ..., 100%.
4. Plot: **leak detection rate vs. ASPA deployment percentage**.

**Why this matters**: It answers the practical question "How much of the internet needs to deploy ASPA before it becomes useful?" If the curve shows diminishing returns after 50%, that's a powerful policy argument. Most ASPA papers assume binary full/zero deployment — this is a **novel contribution**.

**Deliverables**:
- `src/partial_deployment.py` — sweep script
- `output/charts/partial_deployment_curve.png` — line chart (detection % vs. adoption %)
- `output/partial_deployment_stats.json` — raw data points

**Effort**: Low — subsample the existing CAIDA cache and re-run `analyze.py` in a loop.

#### 11.2 ROA vs. ASPA Comparison

Run **Route Origin Validation (ROV)** on the same dataset alongside ASPA and compare:

- ROV checks: "Is the **origin AS** authorized to announce this prefix?" (using ROA records from Routinator)
- ASPA checks: "Is the **entire path** structurally valid?" (using ASPA records)

**What to show**: A 2×2 contingency table and Venn diagram of:
- Routes caught by ROV only
- Routes caught by ASPA only
- Routes caught by both
- Routes caught by neither

This directly demonstrates why ASPA is needed *in addition to* ROA — they protect against different attack types (origin spoofing vs. path manipulation).

**Deliverables**:
- `src/rov_comparison.py` — ROV checker + combined analysis
- `output/charts/roa_vs_aspa_venn.png` — Venn diagram
- `output/rov_vs_aspa_stats.json` — comparison statistics

**Effort**: Medium — need to parse ROA records and implement basic ROV logic.

---

### Tier 2 — High Value, Moderate Effort

#### 11.3 Per-Country / Per-Region Analysis

Map offending ASNs to countries using RIR delegation files (freely available, ~2 MB each).

**What to show**:
- Bar chart or heatmap of route leak sources by country/region
- Which regions produce the most leaks?
- Which RIRs (ARIN, RIPE, APNIC, etc.) have the best/worst ASPA coverage?

**Deliverables**:
- `src/geo_analysis.py` — country mapping + aggregation
- `data/delegated-*` — RIR delegation files
- `output/charts/leaks_by_country.png` — geographic bar chart
- `output/geo_stats.json` — per-country leak counts

**Effort**: Medium — download RIR files, map ASN → country, aggregate.

#### 11.4 Path Length as Leak Predictor

Compare AS-path length distributions of valid vs. invalid routes. Route leaks tend to create longer paths because the leaked path traverses extra ASes.

**What to show**:
- CDF plot of path lengths for valid vs. invalid routes
- Statistical hypothesis test (Mann-Whitney U or KS test) with p-value
- Mean/median path length comparison table

**Deliverables**:
- `src/path_length_analysis.py` — statistical analysis
- `output/charts/path_length_cdf.png` — CDF comparison plot
- One p-value proving leaked paths are statistically longer

**Effort**: Low — data already exists in the Phase 4 CSVs; ~30 lines of analysis code.

---

### Tier 3 — Nice-to-Have (If Time Permits)

#### 11.5 Real-World Incident Case Study

Pick a documented BGP route leak event and replay it through our engine to prove detection.

| Incident | Date | What Happened |
|----------|------|---------------|
| Verizon / Cloudflare leak | June 2019 | A small PA ISP (AS396531) leaked 20,000+ routes through Verizon, causing global outages |
| Pakistan / YouTube hijack | Feb 2008 | Pakistan Telecom (AS17557) announced YouTube's prefix, black-holing traffic worldwide |
| Rostelecom leak | April 2020 | AS12389 leaked prefixes for Akamai, Cloudflare, and major CDNs |

**What to do**: Download the MRT data from the incident's exact time window, run it through the ASPA engine, and show that our tool flags the offending path. One concrete "we caught it" example is worth more than pages of aggregate statistics.

**Deliverables**:
- `src/incident_replay.py` — incident-specific ingestion + analysis
- `output/incident_case_study.json` — flagged paths from the incident
- Narrative write-up in the final report

**Effort**: Medium — depends on RouteViews archive availability for the exact time window.

#### 11.6 False Positive Analysis

CAIDA's AS-relationship data is *inferred*, not ground truth. Some relationships may be wrong, causing our engine to flag legitimate routes as leaks.

**What to do**:
- Cross-reference flagged routes against multiple data sources (PeeringDB, IRR databases).
- Estimate a false-positive rate by sampling flagged routes and manually checking if the relationship inference seems correct.
- Discuss the implications: "X% of our flagged routes may be false positives due to inference errors."

**Recommendation**: Discuss qualitatively in the report's Limitations section rather than implementing a full automated check.

---

### Implementation Order

| # | Research Item | Key Output | Effort | Status |
|---|---|---|---|---|
| 1 | Partial deployment curve | Line chart (detection % vs. adoption %) | Low | ✅ Done |
| 2 | ROA vs. ASPA comparison | Venn diagram / 2×2 table | Medium | ✅ Done |
| 3 | Per-country analysis | Bar chart by country/region | Medium | ✅ Done |
| 4 | Path length statistics | CDF plot + statistical test | Low | ✅ Done |
| 5 | Incident case study | Single flagged path proof | Medium | ✅ Done |
| 6 | False positive analysis | Qualitative discussion | Low | ☐ |

---

## Execution Order Summary

```
Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4 ──→ Phase 5
 Setup       Ingest      RPKI Cache   Engine       Report
  │            │            │            │            │
  │            │            │            │            │
  ▼            ▼            ▼            ▼            ▼
 conda      ingest.py   routinator   analyze.py   visualize.py
 deps        + test      + CAIDA      + verify     + stats
                                      + CSV        + charts
                                                   + report
```

**We proceed phase by phase. Each phase has a verification checkpoint — we do not move on until the checkpoint passes.**
