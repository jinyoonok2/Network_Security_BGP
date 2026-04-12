# BGP Route Leaks & ASPA Validation — Implementation Guide

> This file covers **how to build and reproduce the environment from scratch**. For what
> the project does, how every script works, and all results with charts, see [README.md](README.md).

## Table of Contents

1. [Technology Stack](#1-technology-stack)
2. [Phase 1 — Environment Setup](#2-phase-1--environment-setup)
3. [Phase 2 — Data Ingestion Setup](#3-phase-2--data-ingestion-setup)
4. [Phase 3 — RPKI and CAIDA Setup](#4-phase-3--rpki-and-caida-setup)
5. [Design Decisions](#5-design-decisions)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Technology Stack

| Component | Tool | Why we chose it |
|-----------|------|-----------------|
| Language | Python 3.10 | Best library ecosystem for BGP research |
| Environment | Miniconda | Isolated dependencies, reproducible builds |
| BGP data parsing | libbgpstream + pybgpstream | Industry-standard MRT parser with direct access to RouteViews archives |
| RPKI cache | Routinator 0.13+ | Most mature open-source RPKI relying party with ASPA support |
| Relationship data | CAIDA AS-relationships serial-2 | Inferred provider-customer pairs for ~75,000 networks — used to simulate full ASPA deployment |
| Data analysis | pandas | Efficient CSV/tabular operations |
| Visualization | matplotlib + seaborn | Publication-quality charts |

---

## 2. Phase 1 — Environment Setup

Everything below was run on Ubuntu. Other Linux distributions will need equivalent package names.

### 2.1 Install Miniconda

```bash
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh
# Follow prompts, then restart terminal
```

### 2.2 Create the conda environment

```bash
conda create -n bgp_aspa python=3.10 -y
conda activate bgp_aspa
```

### 2.3 Install system-level C dependencies

pybgpstream is a Python binding for the C library libbgpstream. It also needs libwandio for reading compressed data.

```bash
sudo apt-get update
sudo apt-get install -y build-essential curl libssl-dev zlib1g-dev

# Option A — from CAIDA's apt repository (preferred)
curl -s https://pkg.caida.org/os/ubuntu/bootstrap.sh | sudo bash
sudo apt-get install -y bgpstream

# Option B — build from source (fallback if the repo is unavailable)
# git clone https://github.com/CAIDA/libbgpstream.git
# cd libbgpstream && mkdir build && cd build
# cmake .. && make && sudo make install && sudo ldconfig
```

### 2.4 Install Python packages

```bash
conda activate bgp_aspa
pip install pybgpstream pandas matplotlib seaborn requests
```

### 2.5 Verify the installation

```bash
python -c "import pybgpstream; print('pybgpstream OK')"
python -c "import pandas; import matplotlib; import seaborn; print('Python packages OK')"
```

Both commands should print their OK messages with no errors.

---

## 3. Phase 2 — Data Ingestion Setup

The ingestion script (`src/ingest.py`) uses pybgpstream to stream routing data directly from the RouteViews archive over the internet. No manual downloads are needed.

### Data source details

| Property | Value |
|----------|-------|
| Archive | University of Oregon RouteViews (`route-views2` collector) |
| Record type | BGP UPDATE messages (not full RIB dumps) |
| Time window | January 15, 2024, 00:00–00:15 UTC |
| Volume | ~322,000 route announcements |
| Format | MRT (Multi-threaded Routing Toolkit binary format), streamed and parsed in memory |

### What pybgpstream does under the hood

1. Connects to the RouteViews HTTP archive.
2. Downloads the MRT file(s) covering the requested time window.
3. Parses each BGP UPDATE message and yields individual route announcements with fields like prefix, AS path, peer ASN, and timestamp.

### Optional: download an MRT file for offline use

```bash
mkdir -p data/
wget -P data/ http://archive.routeviews.org/bgpdata/2024.01/UPDATES/updates.20240115.0000.bz2
```

pybgpstream can read from local files instead of streaming:

```python
stream = pybgpstream.BGPStream(data_interface="singlefile")
stream.set_data_interface_option("singlefile", "upd-file", "data/updates.20240115.0000.bz2")
```

---

## 4. Phase 3 — RPKI and CAIDA Setup

### 4.1 Install Routinator

Routinator is written in Rust, so you need the Rust toolchain first.

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Routinator
cargo install routinator

# Verify
routinator --version
```

### 4.2 Initialize the RPKI cache

```bash
routinator init --accept-arin-rpa
```

This downloads Trust Anchor Locator files from all five Regional Internet Registries (AFRINIC, APNIC, ARIN, LACNIC, RIPE NCC).

### 4.3 Export RPKI data (ROAs + ASPAs)

```bash
routinator vrps --format json --enable-aspa > data/rpki_vrps_with_aspa.json
```

This file contains both ROA records (802,506) and ASPA records (1,543 at the time we ran it). The ASPA count is very low because the standard is still new — this is expected and is itself a finding discussed in the README.

### 4.4 Download CAIDA AS-relationship data

CAIDA publishes inferred customer-provider and peer-peer relationships for nearly every network on the internet.

```bash
mkdir -p data/
# Requires a free CAIDA account
wget -P data/ https://publicdata.caida.org/datasets/as-relationships/serial-2/20240101.as-rel2.txt.bz2
```

**File format:** `<AS1>|<AS2>|<relationship>` where `-1` means provider-to-customer and `0` means peer-to-peer.

We use this to simulate what the internet would look like if every network had published ASPA records.

### 4.5 Download RIR delegation files (for geographic analysis)

The five Regional Internet Registries each publish a file mapping network numbers to countries.

```bash
# ARIN (North America)
wget -O data/delegated-arin.txt https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest

# RIPE NCC (Europe, Middle East, Central Asia)
wget -O data/delegated-ripencc.txt https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest

# APNIC (Asia-Pacific)
wget -O data/delegated-apnic.txt https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest

# LACNIC (Latin America, Caribbean)
wget -O data/delegated-lacnic.txt https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest

# AFRINIC (Africa)
wget -O data/delegated-afrinic.txt https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest
```

---

## 5. Design Decisions

These are choices we made during implementation that are not obvious from reading the code.

### Why two ASPA data sources instead of one?

Only 1,543 networks have published real ASPA records (out of ~75,000 total). If we only used real data, 91.8% of routes would be "Unknown" — we could not draw meaningful conclusions. The CAIDA dataset gives us a "what if everyone adopted ASPA" scenario. Both scenarios are clearly labeled in all output.

### Why a 15-minute UPDATE window instead of a full RIB dump?

A full RIB dump is ~2 GB compressed and contains ~900,000 routes. A 15-minute UPDATE window gives us 322,000 routes — enough for statistically meaningful analysis while keeping processing fast (~5 seconds). The incident replay (Research 5) uses a 1-hour window and processes over 5 million routes, showing the pipeline scales fine.

### Why the shared config.py?

Six scripts all need the same folder paths and the same CSV-loading function. Rather than duplicate that code, `src/config.py` provides `DATA_DIR`, `OUTPUT_DIR`, and `load_ingested_routes()` as a single source of truth.

### Why self-tests in aspa_verifier.py instead of a separate test file?

Running `python src/aspa_verifier.py` executes 8 built-in test cases that cover the main algorithm branches (valid, invalid, unknown, prepend removal, single-hop, peer link). This makes it easy to verify correctness without a test framework — just run the file.

### Why CAIDA relationships are treated as simulated ASPA records

A real ASPA record says "Network X authorizes providers A, B, C." CAIDA's data says "Network X appears to buy transit from A, B, C based on observed routing." The two are different in provenance but functionally identical for our purposes — both map a customer network to its upstream providers. We clearly call CAIDA results "simulated full deployment" everywhere.

---

## 6. Troubleshooting

### Common issues

| Problem | Likely cause | Fix |
|---------|-------------|-----|
| `ModuleNotFoundError: pybgpstream` | C library not installed or conda env not active | Run `conda activate bgp_aspa`, then check `python -c "import pybgpstream"` |
| `pybgpstream` imports but `stream_bgp_data()` returns nothing | No internet connection, or RouteViews archive is temporarily down | Try a different collector or time window; or use offline mode (Section 3) |
| `routinator: command not found` | Rust/cargo bin not in PATH | Run `source $HOME/.cargo/env` or add `~/.cargo/bin` to your PATH |
| `FileNotFoundError: data/rpki_vrps_with_aspa.json` | RPKI export not run | Run `routinator vrps --format json --enable-aspa > data/rpki_vrps_with_aspa.json` |
| `FileNotFoundError: data/20240101.as-rel2.txt.bz2` | CAIDA file not downloaded | Download from CAIDA (requires free account) — see Section 4.4 |
| `analyze.py` runs but all results are "Unknown" | Loaded Routinator data (real) instead of CAIDA (simulated) | This is expected for Routinator — real ASPA adoption is very low. The script runs both scenarios automatically. |
| Charts not generated | matplotlib backend issue | Run `pip install matplotlib` and try again; on headless servers, set `MPLBACKEND=Agg` |

### Quick diagnostic commands

```bash
# Verify pybgpstream C library is linked
python -c "import pybgpstream; print('OK')"

# Verify Routinator is working
routinator --version

# Check how many RPKI objects are in the export
python3 -c "import json; d=json.load(open('data/rpki_vrps_with_aspa.json')); print(f'Records: {len(d)}')"

# Test RouteViews connectivity (fetches 1 minute of data)
python -c "
import pybgpstream
s = pybgpstream.BGPStream(
    from_time='2024-01-15 00:00:00',
    until_time='2024-01-15 00:01:00',
    collectors=['route-views2'],
    record_type='updates')
count = sum(1 for _ in s)
print(f'Records: {count}')
"

# Run the verifier self-tests
python src/aspa_verifier.py
```
