# BGP Route Leak Detection with ASPA

This repository contains the code and generated figures for an empirical BGP route-leak analysis using ASPA-style path validation.

The written report explains the background, methodology, and interpretation. This README focuses on how the codebase is organized, how the scripts connect, what data files are required, and how to reproduce the outputs.

## Project Flow

The project follows one core pipeline, then several analysis scripts reuse the same outputs.

```text
RouteViews BGP updates
        |
        v
src/ingest.py
        |
        v
output/ingested_updates.csv
        |
        +-----------------------------+
        |                             |
        v                             v
src/aspa_cache.py              src/aspa_verifier.py
relationship data              path checking engine
        |                             |
        +-------------+---------------+
                      |
                      v
              src/analyze.py
                      |
                      v
     output/all_results_*.csv, output/statistics_*.json
                      |
                      v
              downstream analysis scripts
```

`src/aspa_cache.py` and `src/aspa_verifier.py` are the shared core. Most later scripts import them instead of reimplementing validation.

## Repository Layout

```text
.
├── src/          Python scripts
├── charts/       Generated figures committed to the repo
├── data/         Required input data, not committed
├── output/       Generated CSV and JSON outputs, not committed
└── README.md
```

`data/` and `output/` are ignored by git because they contain large or reproducible files. `charts/` is committed because the figures are part of the project deliverable.

## Environment

The project was developed in a conda environment named `bgp_aspa`.

```bash
conda activate bgp_aspa
```

Required tools and libraries:

- Python 3.10
- `pybgpstream` and its native dependencies
- `routinator`
- Python plotting and analysis libraries used by the scripts, including `matplotlib`, `numpy`, and `scipy`

## Required Data Files

Place these files in `data/` before running the full pipeline.

| File | Used by |
|---|---|
| `data/rpki_vrps_with_aspa.json` | real RPKI ASPA and ROA analysis |
| `data/20240101.as-rel2.txt.bz2` | main CAIDA simulated full-deployment analysis |
| `data/20200401.as-rel2.txt.bz2` | Rostelecom 2020 incident replay |
| `data/20190601.as-rel2.txt.bz2` | Verizon/DQE 2019 incident replay |
| `data/delegated-*.txt` | country and RIR mapping |

Generate the Routinator file with:

```bash
routinator vrps --format json --enable-aspa > data/rpki_vrps_with_aspa.json
```

Download CAIDA relationship files from the CAIDA AS Relationships dataset. Use the `serial-2` files because this code expects the `as-rel2` format.

## Core Pipeline

### 1. Ingest BGP Updates

```bash
python src/ingest.py
```

This downloads a 15-minute RouteViews update window from `route-views2`:

- Time window: `2024-01-15 00:00:00` to `2024-01-15 00:15:00` UTC
- Output: `output/ingested_updates.csv`
- Rows produced in the project run: `321,950`

Each row contains timestamp, prefix, AS path, and peer ASN.

### 2. Load Relationship Data

`src/aspa_cache.py` builds the in-memory lookup table used by the verifier.

It supports two modes:

- Routinator JSON for real signed ASPA records
- CAIDA AS relationships for simulated full ASPA deployment

The cache stores provider-customer relationships as:

```python
customer_asn -> set(authorized_provider_asns)
```

It also stores peer relationships separately so the verifier can check path shape.

### 3. Verify AS Paths

`src/aspa_verifier.py` is the shared path-checking engine.

```bash
python src/aspa_verifier.py
```

Running the file directly executes its built-in self-tests.

The verifier:

1. Removes consecutive duplicate ASNs caused by prepending.
2. Classifies each adjacent hop as up, down, peer, not authorized, or unknown.
3. Checks the valley-free path shape.
4. Returns `valid`, `invalid`, or `unknown`.

### 4. Run Main Analysis

```bash
python src/analyze.py
```

By default this runs two analyses:

- CAIDA simulated full deployment
- Routinator real ASPA deployment

Main outputs:

| File | Description |
|---|---|
| `output/all_results_caida.csv` | per-route verdicts using CAIDA |
| `output/flagged_routes_caida.csv` | invalid CAIDA routes only |
| `output/statistics_caida.json` | aggregate CAIDA summary |
| `output/all_results_routinator.csv` | per-route verdicts using real ASPA |
| `output/flagged_routes_routinator.csv` | invalid real-ASPA routes only |
| `output/statistics_routinator.json` | aggregate real-ASPA summary |

Main result snapshot:

- CAIDA simulated full deployment: `13.2%` invalid, `0.3%` unknown
- Real ASPA today: `8.2%` invalid, `91.8%` unknown

## Analysis Scripts

Each analysis script uses the same core verifier and writes a JSON output plus one or more charts.

| Script | Purpose | Main output |
|---|---|---|
| `src/partial_deployment.py` | simulate ASPA adoption levels | `output/partial_deployment_stats.json`, `charts/partial_deployment_curve.png` |
| `src/rov_comparison.py` | compare ASPA with ROV | `output/rov_vs_aspa_stats.json`, `charts/roa_vs_aspa_venn.png` |
| `src/geo_analysis.py` | map flagged routes to country and RIR | `output/geo_stats.json`, `charts/leaks_by_country.png`, `charts/leaks_by_rir.png` |
| `src/path_length_analysis.py` | compare path lengths for valid and invalid routes | `charts/path_length_cdf.png` |

Run them after `src/analyze.py` has produced the base result files.

## Incident Replay Scripts

The incident scripts reuse the verifier but fetch different RouteViews windows and use CAIDA relationship snapshots matched to each incident month.

### Rostelecom 2020

```bash
python src/incident_replay.py
```

Inputs:

- RouteViews window: `2020-04-01 19:00:00` to `2020-04-01 20:00:00` UTC
- Relationship file: `data/20200401.as-rel2.txt.bz2`

Outputs:

- `output/incident_case_study.json`
- `charts/incident_aspa_verdicts.png`

Result snapshot:

- All routes in window: `5,115,046`
- Rostelecom routes: `1,183,723`
- Prefix-filtered victim routes: `79,440`
- Prefix-filtered invalid routes: `3,202`
- Detection rate: `4.0%`

### Verizon/DQE 2019

```bash
python src/incident_replay_verizon.py
```

Inputs:

- RouteViews window: `2019-06-24 10:30:00` to `2019-06-24 12:30:00` UTC
- Relationship file: `data/20190601.as-rel2.txt.bz2`

Outputs:

- `output/incident_verizon.json`
- `charts/incident_verizon_verdicts.png`

Result snapshot:

- All routes in window: `5,726,174`
- DQE routes: `474,012`
- Prefix-filtered victim routes: `45,851`
- Prefix-filtered invalid routes: `45,851`
- Detection rate: `100.0%`

### Cross-Incident Comparison

```bash
python src/incident_comparison.py
```

This script does not fetch network data. It reads:

- `output/incident_case_study.json`
- `output/incident_verizon.json`

Output:

- `charts/incident_comparison.png`

The comparison chart shows how ASPA behaves differently for a large carrier leak versus a small ISP leak.

## Recommended Run Order

For a full reproduction:

```bash
conda activate bgp_aspa

python src/ingest.py
python src/analyze.py

python src/partial_deployment.py
python src/rov_comparison.py
python src/geo_analysis.py
python src/path_length_analysis.py

python src/incident_replay.py
python src/incident_replay_verizon.py
python src/incident_comparison.py
```

Some scripts require internet access because they fetch RouteViews data.

## Charts

All charts are written to `charts/`.

| Chart | Generated by |
|---|---|
| `charts/partial_deployment_curve.png` | `src/partial_deployment.py` |
| `charts/roa_vs_aspa_venn.png` | `src/rov_comparison.py` |
| `charts/leaks_by_country.png` | `src/geo_analysis.py` |
| `charts/leaks_by_rir.png` | `src/geo_analysis.py` |
| `charts/path_length_cdf.png` | `src/path_length_analysis.py` |
| `charts/incident_aspa_verdicts.png` | `src/incident_replay.py` |
| `charts/incident_verizon_verdicts.png` | `src/incident_replay_verizon.py` |
| `charts/incident_comparison.png` | `src/incident_comparison.py` |

## Source File Reference

| File | Role |
|---|---|
| `src/config.py` | shared paths and CSV loader |
| `src/ingest.py` | RouteViews ingestion |
| `src/aspa_cache.py` | relationship cache |
| `src/aspa_verifier.py` | ASPA path verifier |
| `src/analyze.py` | main per-route analysis |
| `src/partial_deployment.py` | adoption simulation |
| `src/rov_comparison.py` | ROV and ASPA comparison |
| `src/geo_analysis.py` | country and RIR analysis |
| `src/path_length_analysis.py` | path length statistics |
| `src/incident_replay.py` | Rostelecom incident replay |
| `src/incident_replay_verizon.py` | Verizon/DQE incident replay |
| `src/incident_comparison.py` | two-incident comparison chart |

## Notes

- The report contains the fuller explanation of routing concepts, methodology, and interpretation.
- This README is intended as the implementation guide for reproducing the code outputs.
- `data/` and `output/` are intentionally not committed.
- `charts/` is committed so figures can be viewed without rerunning long scripts.
