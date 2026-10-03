# False-positive report

Known false-positive conditions per detector, the mitigation built into the
framework, and the fixture that regression-tests it. **Measured FP rates are
placeholders**: they will be filled only from a harness run over a real
dataset (CTU-13 first; see [docs/evaluation.md](../docs/evaluation.md)).
Synthetic fixtures prove that a mitigation works, not how often a condition
occurs in your network.

How to fill a slot: run `python -m zdp.harness --fixtures <dataset> --suite
<name>`, read the per-detector false positives from `reports/<detector>.md`,
attribute each to a row below (or add a row), and record the count with the
dataset, framework version and config hash it came from.

## c2_beaconing

| FP source | Why it triggers | Mitigation in zdp | Regression fixture | Measured FP rate |
|---|---|---|---|---|
| NTP, OS/AV update polling, telemetry agents | Highly regular intervals, near-identical payload sizes | `service=ntp` suppression; destination allowlists (`networks.yaml` → `ntp`, `updates`, `saas`, `monitoring`) | `fp_traps` (NTP 64 s), `c2_beaconing` & `benign_office` (allowlisted 300 s update check) | PLACEHOLDER: compute from CTU-13 run |
| Keep-alives (WebSocket, long-poll, MQTT, VPN heartbeats) | Fixed-interval tiny packets | Zeek-split long-lived sessions (mostly `OTH`, near-zero gaps) suppressed; `median_interval ≥ 10 s` gate | `fp_traps` (XMPP-style OTH keep-alive) | PLACEHOLDER: compute from CTU-13 run |
| Scheduled tasks / cron to internal APIs | Perfect periodicity | Internal-destination gate; allowlist NAT'd egress targets | `fp_traps` (SCCM policy polling) | PLACEHOLDER: compute from CTU-13 run |
| Monitoring probes (Pingdom/Nagios-style egress checks) | Regular and size-consistent | `monitoring` allowlist; low-response-volume component partially discriminates | — (site-specific) | PLACEHOLDER: compute from CTU-13 run |
| Clock-skew / merged logs | Artificial regularity from batching | Reader sorts by `ts` and drops duplicate `uid`s | unit tests (`tests/unit/test_reader.py`) | PLACEHOLDER: compute from CTU-13 run |

Known false-negative risk: implants with jitter above roughly 40 % or
randomized sleep schedules defeat CV scoring. Periodogram analysis is the
planned v2 mitigation.

## dns_tunneling

| FP source | Why it triggers | Mitigation in zdp | Regression fixture | Measured FP rate |
|---|---|---|---|---|
| CDN / cloud cache-busting hostnames | High entropy, unique subdomains, volume | PSL-aware grouping (private suffixes such as `cloudfront.net` split per tenant); Tranco allowlist; TXT and length components stay near zero | `fp_traps` (`<hex>.assets.example.org`) | PLACEHOLDER: compute from CTU-13 run |
| DNSBL / reputation lookups | Long, structured, high-volume names | DNSBL zones in `domains.txt`; reversed-IP labels have low entropy | `fp_traps` (`zen.spamhaus.org`) | PLACEHOLDER: compute from CTU-13 run |
| EDR / AV cloud hash lookups | Hex subdomains: high entropy plus volume | Vendor-domain allowlist (primary tuning burden — see `docs/tuning.md`) | — (vendor-specific) | PLACEHOLDER: compute from CTU-13 run |
| Kerberos / AD service discovery | Long names, bursty | `SRV` qtype and `_`-label exclusion | `dns_tunneling`, `fp_traps` | PLACEHOLDER: compute from CTU-13 run |
| IPv6 reverse zones (`ip6.arpa`) | 63+ labels | `.arpa` dropped at the reader | `fp_traps` | PLACEHOLDER: compute from CTU-13 run |

## dga

| FP source | Why it triggers | Mitigation in zdp | Regression fixture | Measured FP rate |
|---|---|---|---|---|
| Chromium random-prefix probes | Random 7–15 char NXDOMAINs at browser start | Names without a public suffix never count toward a burst | `dga`, `fp_traps` | PLACEHOLDER: compute from CTU-13 run |
| Search-suffix expansion storms | Many NXDOMAINs from one host | Registered-domain dedup; `internal_zones` exclusion | `dga` (`corp.example.org`) | PLACEHOLDER: compute from CTU-13 run |
| Misconfigured app hammering a dead domain | NXDOMAIN volume | Unique-registered-domain dedup → burst component stays at zero | `fp_traps` | PLACEHOLDER: compute from CTU-13 run |
| Short / branded random-looking domains | Poor bigram scores on short labels | Minimum SLD length 6; Tranco allowlist; top-K averaging | unit tests | PLACEHOLDER: compute from CTU-13 run |
| DGA-like CDN / ad-tech names that resolve | High-entropy SLDs | Burst requires NXDOMAIN; lexical gate means neither signal fires alone | unit tests | PLACEHOLDER: compute from CTU-13 run |

## lateral_movement

| FP source | Why it triggers | Mitigation in zdp | Regression fixture | Measured FP rate |
|---|---|---|---|---|
| Vulnerability scanners | Admin-port fan-out, auth attempts, `IPC$` | `scanner_hosts` excluded from all lateral signals; scan-pattern fan-out mapped to T1046 at reduced severity | `fp_traps` (120-host credentialed scan) | PLACEHOLDER: compute from CTU-13 run |
| SCCM / WSUS / Intune deployment | Executable writes to admin shares at scale | `lateral_allow_sources` (justification mandatory) | `fp_traps` (ccmsetup push) | PLACEHOLDER: compute from CTU-13 run |
| IT admin ad-hoc work | Genuinely new RDP/WinRM pairs | `admin_hosts` removes the +0.2 component; business-hours schedule removes +0.15; remains an expected medium-severity triage item | `lateral_movement` (admin RDP decoy) | PLACEHOLDER: compute from CTU-13 run |
| Backup / AV servers touching `C$` / `ADMIN$` | File writes to admin shares | `lateral_allow_sources`; evidence carries full path + name | `fp_traps` (backup agent) | PLACEHOLDER: compute from CTU-13 run |
| DHCP churn / VDI re-provisioning | IP reuse poisons the "new pair" baseline | Baseline entries expire after 30 days; hostname-stable keys planned (v2) | — | PLACEHOLDER: compute from CTU-13 run |
| Baseline warm-up | Everything is new on day one | New-pair signal disabled until the baseline is 7 days old; warm-up surfaced in run status | `tests/unit/test_lateral_movement.py` | PLACEHOLDER: compute from CTU-13 run |

## Export-rule false positives

The exported Sigma and Suricata rules at `approx` / `companion` tier are
deliberately weaker than the Python analyzers. Replaying the synthetic demo
capture through Suricata shows, for example, that the beaconing session-count
rule also alerts on busy but irregular benign host pairs: it cannot score
interval regularity. Per-rule FP rate: PLACEHOLDER: compute from CTU-13 run.
