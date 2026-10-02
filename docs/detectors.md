# Detectors

All four analyzers share one scoring model:

```
confidence = Σ wᵢ · cᵢ        cᵢ ∈ [0, 1],  Σ wᵢ = 1
```

A detection is emitted only when every **hard gate** passes and
`confidence ≥ min_confidence` (default 0.6). Severity is derived from
confidence (≥ 0.85 high, ≥ 0.6 medium, otherwise low). Component mappings are
linear ramps between two anchors (`zdp.scoring.ramp`), and every value used
in scoring is written to `evidence`, so any detection can be re-scored by
hand from its own JSON.

The thresholds quoted below are the defaults in `config/default.yaml`. They
are design starting points, not calibrated values; see
[tuning.md](tuning.md).

---

## `c2_beaconing` — C2 beaconing (`conn.log`)

**What it finds.** Implants checking in with command-and-control
infrastructure: many outbound sessions to one destination at near-constant
intervals with near-constant request sizes.

**Grouping.** `(id.orig_h, id.resp_h, id.resp_p, proto)` per 1-hour window.
Windows overlap by 50 % so a beacon straddling a boundary is not halved;
duplicate emissions are removed by `(detector, src, dst, indicator, ⌊first ts⌋)`.

**Hard gates.**

| Gate | Default | Why |
|---|---|---|
| connections in window | ≥ 8 | too few points make CV meaningless |
| median inter-arrival | 10 s – 3600 s | below: bulk/keep-alive traffic; above: too sparse for one window |
| direction | internal source → external destination | internal↔internal belongs to `lateral_movement` |
| destination allowlists | `ntp`, `updates`, `saas`, `monitoring` | known periodic services |
| service suppression | `ntp` | NTP is periodic by design |
| split keep-alive | ≥ 50 % `OTH` and median gap ≤ 1 s | one long-lived session that Zeek split into records |

**Metrics.**

- `Δᵢ = tsᵢ₊₁ − tsᵢ`; `CV_int = σ(Δ)/μ(Δ)`; robust `CV_mad = 1.4826·MAD(Δ)/median(Δ)`.
  Scoring uses `min(CV_int, CV_mad)`, so one missed check-in (host asleep,
  network blip) does not hide an otherwise regular beacon.
- `CV_bytes = σ(orig_bytes)/μ(orig_bytes)` over connections with
  `orig_bytes > 0`; unset byte counts are excluded and counted as `n_excluded`.
- `c_count = min(n / 48, 1)` (48 ≈ one hour of 75 s beacons).

**Components.**

| Component | Mapping | Weight |
|---|---|---|
| `interval` | 1.0 at CV ≤ 0.12 → 0.0 at CV ≥ 0.5 | 0.45 |
| `bytes` | 1.0 at CV_bytes ≤ 0.1 → 0.0 at ≥ 0.6 (0 if undefined) | 0.30 |
| `count` | `min(n/48, 1)` | 0.15 |
| `resp_volume` | 1.0 if median `resp_bytes` < 2 KiB, else 0.3 | 0.10 |

**Evidence.** `n_conns`, `median_interval`, `cv_interval`, `cv_mad`,
`cv_score_input`, `cv_bytes`, `median_orig_bytes`, `median_resp_bytes`,
`service`, `proto`, `resp_port`, `n_excluded`, `components`, `weights`.

**ATT&CK.** T1071; T1071.001 for `http`/`ssl`/`quic`; T1071.004 for `dns`;
T1095 for ICMP. Indicator: `dst:port` (`[v6]:port` for IPv6).

**Known blind spot.** High jitter (above roughly 40 %) or randomized sleep
defeats CV scoring. A periodogram/Fourier component is the v2 plan.

---

## `dns_tunneling` — DNS tunneling (`dns.log`)

**What it finds.** C2 or exfiltration encoded in DNS query names, with data
returned in TXT/NULL/CNAME answers (iodine, dnscat2-style channels).

**Grouping.** `(id.orig_h, registered_domain(query))` per 1-hour window.
Registered domains come from the pinned Public Suffix List (private section
included), so `x.s3.amazonaws.com` tenants are separate names and
`example.co.uk` is not collapsed into `co.uk`.

**Hard gates.** ≥ 30 queries per group; registered domain not allowlisted
(Tranco top-1k snapshot + local entries); mean subdomain length ≥ 20.
Excluded before grouping: `SRV` queries and `_`-prefixed labels (AD/Kerberos
discovery). `.arpa` names are dropped by the reader.

**Metrics** (over the subdomain portion only):

- `mean_entropy` — Shannon entropy (bits/char) of the concatenated subdomain
  labels, averaged per query. Base32/64 payloads land well above English text.
- `mean_qlen` — mean full query length.
- `txt_null_ratio` — share of `TXT`/`NULL` queries, with `CNAME` at half weight.
- `unique_sub_ratio` — distinct subdomains / queries.
- `qps_peak` — maximum queries in any 60 s bucket (evidence only).

**Components.**

| Component | Mapping | Weight |
|---|---|---|
| `entropy` | 0 at ≤ 3.0 → 1 at ≥ 4.0 bits/char | 0.30 |
| `query_length` | 0 at ≤ 40 → 1 at ≥ 80 chars | 0.25 |
| `txt_null_ratio` | 0 at ≤ 0.05 → 1 at ≥ 0.4 | 0.15 |
| `unique_subdomain_ratio` | 0 at ≤ 0.5 → 1 at ≥ 0.95 | 0.15 |
| `volume` | 0 at ≤ 30 → 1 at ≥ 300 queries | 0.15 |

**Evidence.** All five metrics, `n_queries`, `mean_subdomain_length`,
`qtype_histogram`, three sample queries (≤ 120 chars), `components`,
`weights`, `secondary_techniques`.

**ATT&CK.** T1071.004. When the uniqueness and volume components are both
≥ 0.9 the traffic is exfiltration-shaped and T1048.003 is added to
`evidence.secondary_techniques`. Indicator: the registered domain.

---

## `dga` — Domain-generation algorithms (`dns.log`)

**What it finds.** Malware iterating a DGA: a burst of NXDOMAIN answers for
lexically random names, ending when it finds the one domain its operator
registered.

**Signal A — NXDOMAIN burst (per `id.orig_h`).** A 300 s sliding window
counts *unique registered domains* answered `NXDOMAIN`. Gate: ≥ 10.
`c_burst = min((n − 10) / 40, 1)`. Names without a public suffix (Chromium's
single-label probes), names in `policy.internal_zones` (search-suffix storms)
and allowlisted domains never count. Because the count is over registered
domains, a host hammering one dead name scores zero.

**Signal B — lexical anomaly (per second-level label, length ≥ 6, IDNs
skipped).**

| Feature | Mapping | Weight in `c_lexical` |
|---|---|---|
| entropy of the SLD | 0 at ≤ 2.8 → 1 at ≥ 3.8 bits/char | 0.35 |
| bigram mean log-probability | anchors **from the bundled table** (below) | 0.35 |
| digit ratio | 0 at 0 → 1 at ≥ 0.3 | 0.15 |
| longest consonant run | 0 at ≤ 2 → 1 at ≥ 5 | 0.15 |

`c_lexical` is the mean over the top-K (K = 20) most anomalous candidates in
the burst.

**Final score.** `confidence = 0.5·c_burst + 0.5·c_lexical`, with a hard gate
`c_lexical ≥ 0.4`: a burst of dictionary-like names never fires.

**Evidence.** `n_nxdomain_unique`, `n_nxdomain_events`, `burst_start`,
`burst_end`, `c_burst`, `c_lexical`, `bigram_anchors`, up to 20 candidates
with per-domain feature values and component scores.

**ATT&CK.** T1568.002. Indicator: the bursting host.

### Bigram table: training and calibration

`zdp/data/bigram_freq.json` is a first-order character Markov model over
`[a-z0-9-]` with start/end markers, built by `tools/train_bigrams.py`:

1. Take the top 100,000 entries of the Tranco list (the bundled table was
   trained on list `8PXYV`; the ID and permalink are recorded in the file).
2. Reduce each entry to its second-level label with the pinned PSL (private
   suffixes included), drop IDNs and labels outside `[a-z0-9-]`, and
   de-duplicate, so `google.com` and `google.de` contribute one `google`.
3. Count transitions over `^label$` and convert them to natural-log
   conditional probabilities with add-one smoothing.
4. **Calibrate from the table itself.** `zero_at` is the 10th percentile of
   mean log-probability over training labels of at least 6 characters (so
   roughly nine in ten popular names score 0); `one_at` is the median over
   20,000 seeded uniform-random `[a-z0-9]` labels drawn with the same length
   histogram. Both anchors, the procedure parameters and the length histogram
   are stored in the JSON.

The scorer reads the anchors from the file (`bigram: {zero_at: table,
one_at: table}` in the config), and a unit test re-derives `one_at` from the
shipped table to prove it was produced by this procedure. To retrain:

```bash
curl -L -o top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip && unzip top-1m.csv.zip
python tools/train_bigrams.py --tranco top-1m.csv --list-id <LIST_ID>
python tools/build_domain_allowlist.py --tranco top-1m.csv --list-id <LIST_ID> --top 1000
```

---

## `lateral_movement` — Lateral movement (`conn.log` + `smb_files.log`)

Three sub-signals; each can emit on its own.

**1. New internal pair on an admin service.** Internal→internal sessions on
445, 135, 3389, 5985, 5986 or 22 that are at least partially established
(`SF`, `S1`, `RSTO`, `OTH`; pure `S0`/`REJ` scans belong to fan-out) for an
`(orig_h, resp_h, resp_p)` tuple absent from the StateStore baseline.

- Warm-up: nothing is emitted until the baseline covers 7 days of log time;
  run status reports `baseline_warmup`.
- Score: `0.5`, `+0.2` if the source is not in `admin_hosts`, `+0.15` outside
  business hours (`config/schedules.yaml`). New ports of the same pair within
  10 minutes collapse into one candidate.
- Baseline entries expire after 30 days without observation.

**2. Admin-share file activity.** `smb_files.log` paths matching
`(?i)\\\\[^\\]+\\(ADMIN\$|C\$|[A-Z]\$)` (after collapsing Zeek's escaped
backslashes).

| Activity | Score |
|---|---|
| executable/script (`.exe .dll .ps1 .bat .vbs .sct`) written | 0.9 |
| executable/script opened (no logged write) | 0.75 |
| any other file written | 0.6 |
| reads of non-executables, `IPC$` alone | not scored (`IPC$` counted in evidence) |

Zeek logs only `FILE_OPEN` in `smb_files.log` by default. The lab's
`docker/zeek/local.zeek` adds `SMB::FILE_WRITE` to
`SMB::logged_file_actions` so writes become visible.

**3. Fan-out.** One internal source reaching ≥ 10 distinct internal hosts on
admin ports within 10 minutes: `c = min(0.4 + (n − 10)/50, 1)`, which reaches
the default emission threshold at 20 hosts. If more than 80 % of attempts are
`S0`/`REJ` the evidence says `pattern: scan`, the technique is T1046
(Discovery) and severity drops one band; otherwise `pattern: access`.

**Merge.** Signals 1 and 2 on the same `(orig_h, resp_h)` within 10 minutes
merge into one detection: `confidence = min(c₁ + 0.5·c₂, 1)`, with both
evidence blocks and the merge arithmetic in `evidence.merge`.

**Exclusions.** `scanner_hosts` and `lateral_allow_sources` (each entry needs
a written justification) are excluded from every signal.

**ATT&CK.** By port: 445/139 → T1021.002, 3389 → T1021.001, 135 → T1021.003,
22 → T1021.004, 5985/5986 → T1021.006; admin-share activity → T1021.002 with
T1570 as a secondary technique for executables; scan-pattern fan-out → T1046.
