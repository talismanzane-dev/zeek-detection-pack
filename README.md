# zeek-detection-pack

[![CI](https://github.com/talismanzane-dev/zeek-detection-pack/actions/workflows/ci.yml/badge.svg)](https://github.com/talismanzane-dev/zeek-detection-pack/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)

A detection-engineering framework for SOC teams: batch analytics over
[Zeek](https://zeek.org) logs that find **C2 beaconing**, **DNS tunneling**,
**DGA domains** and **lateral movement**, map every finding to MITRE ATT&CK,
prove their logic against labelled fixtures in a test harness, and export
Sigma and Suricata rules generated from the same live configuration.
## Detectors

| Detector | Zeek logs | What it scores | ATT&CK | Export |
|---|---|---|---|---|
| [`c2_beaconing`](zdp/analyzers/c2_beaconing.py) | `conn` | Interval regularity (min of CV and MAD-based CV), request-size similarity, session count, response volume per (src, dst, port, proto) | T1071 (.001 web, .004 DNS), T1095 (ICMP) | Suricata `approx`; Sigma not expressible |
| [`dns_tunneling`](zdp/analyzers/dns_tunneling.py) | `dns` | Subdomain entropy, query length, TXT/NULL share, subdomain uniqueness, volume per (src, registered domain) | T1071.004 (+ T1048.003 when exfil-shaped) | Sigma `approx`, Suricata `approx` |
| [`dga`](zdp/analyzers/dga.py) | `dns` | NXDOMAIN burst of unique registered domains **and** lexical anomaly (entropy, Tranco-trained bigram likelihood, digits, consonant runs) | T1568.002 | Sigma `approx`, Suricata `companion` |
| [`lateral_movement`](zdp/analyzers/lateral_movement.py) | `conn`, `smb_files` | New internal admin-service pairs vs. a persistent baseline, executables written to `ADMIN$`/`C$`, admin-port fan-out (scan vs. access) | T1021.001/.002/.003/.004/.006, T1570, T1046 | Sigma `full` (admin-share) + `approx`, Suricata `approx` |

Full scoring tables: [docs/detectors.md](docs/detectors.md) · ATT&CK rationale:
[mappings/attack.md](mappings/attack.md) · Known false positives:
[reports/false_positives.md](reports/false_positives.md).

Each detector module exposes `analyze(log_dir) -> list[Detection]`:

```python
from zdp.analyzers import c2_beaconing

for det in c2_beaconing.analyze("fixtures/c2_beaconing"):
    print(det.ts, det.src, det.dst, det.indicator, det.confidence, det.technique_id)
```

## Architecture

```
zeek logs ──> LogReader ──> Record stream ──> Pipeline / registry ──> [Detection] ──> Sinks
 (conn.log,    (TSV/JSON,     (typed dicts,     (per-log-type dispatch,     (JSONL, stdout,
  dns.log,      auto-detect,   epoch floats,     windowed aggregation,       Sigma export,
  smb_files)    gzip, rotated) compressed IPs)   SQLite StateStore)          Suricata export)
```

- **Reader** (`zdp/reader.py`) sniffs the first line (`#separator` → Zeek TSV,
  `{` → JSON), decodes Zeek escaping, types every field from `#types`,
  normalizes unset fields to `None`, compresses IPv6, drops `.arpa`, sorts by
  `ts` and removes duplicates from merged logs.
- **Windowed batch** (`zdp/pipeline.py`): records are grouped into tumbling
  windows (1 h default, per detector; 50 % overlap for beaconing with
  de-duplication). Large inputs are processed in time-bounded chunks with
  identical results. Analyzers only iterate a window's records, so a streaming
  adapter can be added later.
- **Analyzers** subclass `BaseAnalyzer` (`name`, `required_logs`,
  `configure()`, `analyze(window)`), are discovered through the
  `zdp.analyzers` entry-point group, and run only when their logs exist.
- **`Detection`** (`zdp/models.py`) is a frozen dataclass with stable JSON
  field order: `ts`, `last_ts`, `detector`, `src`, `dst`, `indicator`,
  `confidence`, `severity`, `technique_id`, `tactic`, `evidence`, `uids`.
  `evidence` holds every value used in scoring, so each detection can be
  re-scored by hand.
- **Scoring** is uniform: `confidence = Σ wᵢ·cᵢ` (weights sum to 1), emitted
  only when every hard gate passes and confidence ≥ `min_confidence`.
  Severity: ≥ 0.85 high, ≥ 0.6 medium, else low.
- **StateStore** (`zdp/state.py`) is a SQLite file holding cross-window
  baselines (lateral-movement first-seen pairs, 7-day warm-up, 30-day expiry),
  measured in log time.
- **Policy** (`config/`): internal networks (RFC 1918 + ULA), destination and
  domain allowlists (Tranco top-1k snapshot + DNSBL zones), admin/scanner
  hosts, justified deployment-server allowlist, business hours.

## Quick start (local)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

zdp list                                              # registered analyzers
zdp run --logs /path/to/zeek/logs --out detections.jsonl
zdp view detections.jsonl                             # human-readable table
zdp run --logs fixtures/lateral_movement \
        --overlay fixtures/lateral_movement/site.yaml \
        --state-seed fixtures/lateral_movement/state_seed.json
```

`--overlay site.yaml` adds your site inventory without editing defaults
([tuning guide](docs/tuning.md)); `--state state.db` keeps the lateral
movement baseline across runs.

## Docker lab (one command)

```bash
make lab-demo        # writes a synthetic demo pcap to ./pcaps, then `docker compose up`
# or, with your own captures in ./pcaps:
docker compose up
```

| Service | Image | Does |
|---|---|---|
| `zeek` | `zeek/zeek:lts` | Processes `./pcaps/*.pcap` with [`docker/zeek/local.zeek`](docker/zeek/local.zeek) (JSON logs, SMB writes logged) into `./lab/logs` |
| `analyzer` | built from [`docker/Dockerfile`](docker/Dockerfile) | Runs every detector over `./lab/logs` and rewrites `./lab/out/detections.jsonl` whenever logs change (`ZDP_ONCE=1` for a single pass) |
| `harness` | same | Runs all detectors against the labelled fixtures baked into the image, writes `./lab/out/metrics.json` + `./lab/out/reports/`, then checks `quality_gates.yaml` |
| `viewer` | same (`--profile viewer`) | Tails detections as a table |
| `zeek-live` | `zeek/zeek:lts` (`--profile live`) | Live capture on `$ZEEK_INTERFACE` (adds `NET_ADMIN`/`NET_RAW`, host networking) |

pcap replay needs no privileges. The analyzer image is `python:3.12-slim`,
runs as a non-root user, installs dependencies from `uv.lock`, and has a
`HEALTHCHECK` that runs `zdp selftest`. Lab containers write `./lab/out` as
your user (`make` sets `ZDP_UID`/`ZDP_GID`; plain `docker compose up`
defaults to 1000). Behind a TLS-inspecting proxy, build with
`docker build --secret id=extra_ca,src=<ca-bundle.pem> -f docker/Dockerfile .`.

The demo capture (`tools/gen_demo_pcap.py`) contains a 60 s HTTPS-port
beacon, an iodine-style TXT tunnel, a 40-name NXDOMAIN burst, PsExec-style
`ADMIN$` staging over SMB2, and benign web/DNS. All four detectors fire on
Zeek's output for it (CI's `lab-smoke` job asserts this).

## Test harness

```bash
python harness.py                       # same as: python -m zdp.harness
python -m zdp.harness --fixtures fixtures --out metrics.json --reports reports
python tools/check_gates.py metrics.json quality_gates.yaml
```

- **Fixtures** live in [`fixtures/<scenario>/`](fixtures): Zeek logs (TSV and
  JSON across scenarios), `labels.json` ground truth (positives plus a
  `benign` section documenting deliberate look-alikes), a provenance
  `README.md`, and optionally `site.yaml` (site inventory overlay) and
  `state_seed.json` (lateral baseline). One fixture per detector —
  `c2_beaconing`, `dns_tunneling`, `dga`, `lateral_movement` — plus
  `beacon_jittered`, the pure-negative `benign_office`, and the
  false-positive regression set `fp_traps`. All are synthetic and reproduced
  byte-for-byte by `tools/gen_fixtures.py` (seeded); no production data.
- **Matching** is one-to-one and greedy by confidence: detector and source
  must agree, plus `dst`/`indicator` when labelled (case-insensitive,
  registered-domain level for domains), with ±120 s temporal tolerance.
  Duplicates of a claimed label are ignored by default
  (`--dedup-policy fp` penalizes them).
- **Metrics** — TP, FP, FN, precision, recall, F1 — are computed per detector
  and micro-averaged, only at runtime. `metrics.json` records the framework
  version and config hash; `reports/<detector>.md` lists every TP, FP and FN.
  Both are git-ignored runtime output.
- **Gates.** `quality_gates.yaml` asserts fixture correctness (negative
  scenarios silent, every injected event matched). Per-detector metric floors
  stay `null` (reported as PENDING) until a reviewed baseline run exists.

## Exporting Sigma and Suricata rules

```bash
zdp export --format all --out rules          # or --format sigma | suricata
```

Rules are generated by each analyzer's `to_sigma()` / `to_suricata()` from
the live config, so exported thresholds always equal the Python thresholds.
Every rule declares a fidelity tier (`full`, `approx`, `companion`), IDs are
deterministic (UUIDv5 of detector + signal + config hash), and signals that
cannot be expressed (beaconing in Sigma, the stateful new-pair baseline) are
listed as skipped with the reason. CI validates the output with
`sigma check --fail-on-issues` and `suricata -T --init-errors-fatal` (Suricata 8). Committed
rules: [`rules/`](rules) · rationale: [docs/export_fidelity.md](docs/export_fidelity.md).

## Adding a detector

1. Create `zdp/analyzers/<slug>.py` with a `BaseAnalyzer` subclass: set
   `name`, `required_logs` (and `optional_logs`), and a `DEFAULTS` mapping that
   includes `window_seconds`, `window_overlap`, `min_confidence` and a
   `weights` table summing to 1. Implement `analyze(window)` using only
   `window.records(log_type)`. Use `zdp.scoring` ramps, put every scoring
   input in `evidence`, and build results with `Detection.build(...)`.
   Persist cross-window state only through `self.config.state`.
2. Add a module-level `analyze(log_dir, config=None, state=None)` that calls
   `<Class>.run_on_directory(...)`, like the existing detectors.
3. Register it in `pyproject.toml` under
   `[project.entry-points."zdp.analyzers"]` (and in
   `zdp/registry.py:BUILTIN_ANALYZERS` if it ships in this repo).
4. Mirror `DEFAULTS` under `detectors.<slug>` in `config/default.yaml`; a unit
   test fails if they drift.
5. Add a seeded scenario to `tools/gen_fixtures.py` (positives in `labels`,
   look-alikes in `benign`), regenerate with `make fixtures`, and add
   correctness gates to `quality_gates.yaml`.
6. Write `tests/unit/test_<slug>.py` (gates, scoring, evidence, technique
   mapping) and extend `tests/test_detectors.py`.
7. Optionally implement `to_sigma()` / `to_suricata()` / `export_skips()`,
   then `make export`.
8. Document it in `docs/detectors.md`, `mappings/attack.md` and
   `reports/false_positives.md`.

## Repository layout

```
zdp/                    framework package
  analyzers/            c2_beaconing.py, dns_tunneling.py, dga.py, lateral_movement.py, base.py
  exporters/            Sigma + Suricata serialization and manifest
  harness/              labels.py, matching.py, runner.py, report.py
  data/                 public_suffix_list.dat (pinned), bigram_freq.json (Tranco-trained)
  reader.py pipeline.py registry.py state.py scoring.py models.py config.py policy.py cli.py
config/                 default.yaml, schedules.yaml, allowlists/{networks.yaml,domains.txt}
fixtures/<scenario>/    labelled synthetic Zeek logs (see Test harness)
harness.py              harness entry point
rules/{sigma,suricata}/ exported rules (generated)
mappings/attack.md      ATT&CK mapping table
reports/                false_positives.md (+ runtime reports, git-ignored)
docs/                   detectors, tuning, export fidelity, evaluation
tools/                  gen_fixtures, gen_demo_pcap, train_bigrams, build_domain_allowlist,
                        render_metrics, check_gates, check_no_hardcoded_metrics, ctu13_labels
tests/                  test_detectors.py, test_harness.py, unit/, system/, data/
docker/                 Dockerfile, docker-compose.yml, zeek/local.zeek  (compose.yaml includes it)
quality_gates.yaml      CI gates      uv.lock  pinned dependencies      Makefile
```

Paths reconcile the design spec with the build requirements: fixtures live at
`fixtures/<detector>/` (spec: `tests/fixtures/<scenario>/`), the spec's
`beacon_60s`, `dns_tunnel_txt`, `dga_burst` and `lateral_psexec` scenarios are
the per-detector fixtures, exporters sit in `zdp/exporters/`, and detector
modules are named after their slugs.

## Development

```bash
make check       # ruff, mypy --strict, pytest + coverage, gates, export/fixture/docs drift checks
make help        # all targets
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs on every push
and pull request: lint and `mypy --strict` and tests on Python 3.11 and 3.12,
each detector against its fixture, the harness (metrics and reports uploaded
as artifacts), quality gates, Sigma/Suricata export validation, a Zeek → zdp
lab smoke test with an image build, and docs checks. Tagged releases
([`release.yml`](.github/workflows/release.yml)) push the image to GHCR and
attach the fixture-suite `metrics.json`, exported rules and an SBOM.

## Data and licences

- Code: MIT ([LICENSE](LICENSE)).
- `zdp/data/public_suffix_list.dat`: Public Suffix List snapshot (version in
  its header), Mozilla Public License 2.0.
- `zdp/data/bigram_freq.json` and the Tranco section of `domains.txt`: derived
  from the Tranco list (list ID recorded in the files). Le Pochat et al.,
  "Tranco: A Research-Oriented Top Sites Ranking Hardened Against
  Manipulation", NDSS 2019.
- Fixtures and the demo pcap are synthetic and use RFC 1918/4193 and
  RFC 5737/3849 documentation address ranges. Any real-looking domain names in
  them are illustrative.

## Limitations

- Batch only; streaming is out of scope for v1 (the analyzer interface allows
  a streaming adapter later).
- Beaconing with high jitter or randomized sleep evades CV scoring.
- Lateral-movement baselines key on IP addresses; DHCP/VDI churn degrades
  them until hostname-stable keys are added (v2).
- Thresholds are uncalibrated defaults; tuning is required
  ([docs/tuning.md](docs/tuning.md)).
