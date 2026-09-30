# Export fidelity

`zdp export` translates detector logic into Sigma and Suricata **from the live
configuration**: thresholds in exported rules always equal the Python
thresholds for the config that produced them. Stateful, statistical analytics
cannot be fully expressed in either format, so every exported rule declares a
fidelity tier:

| Tier | Meaning |
|---|---|
| `full` | Semantically equivalent to the Python detector (or sub-signal) |
| `approx` | Captures a sub-signal with thresholding; weaker than the Python logic |
| `companion` | Indicator-style pre-filter meant to run alongside zdp, not replace it |

Where the tier is recorded:

- **Sigma** — a `# zdp-tier:` header comment, a `[tier]` suffix in every
  document's `title` and a `zdp fidelity tier:` prefix in `description`.
  (Sigma's tag validator rejects custom namespaces, so the tier is not a tag;
  ATT&CK tags are present as `attack.*`.)
- **Suricata** — a comment above each rule and `zdp_tier` in `metadata`,
  alongside `zdp_detector`, `zdp_signal`, `zdp_rule_id`, `zdp_config_hash`,
  `mitre_technique_id` and `mitre_tactic_id`.
- **`rules/MANIFEST.json`** — every rule with its tier, plus the signals that
  were not exported and why.

Both outputs are validated in CI: `sigma check --fail-on-issues` (pySigma)
and `suricata -T` against Suricata 8.

## Per-rule rationale

### c2_beaconing

| Format | Rule | Tier | Rationale |
|---|---|---|---|
| Suricata | `session_count_tcp_<port>` (80, 443, 8080, 8443) | approx | `threshold: type both, track by_both` counts new TCP sessions per (src, dst) pair per window at the analyzer's `min_connections`. It cannot measure interval regularity or request-size similarity, and Suricata cannot key a threshold on port, so the port is fixed in the rule header. Replaying the demo capture shows it also alerts on busy, irregular benign pairs — the expected cost of `approx`. |
| Sigma | — | not exported | Sigma has no log model for per-flow inter-arrival statistics. The exporter records a skip notice instead of emitting a misleading rule. |

### dns_tunneling

| Format | Rule | Tier | Rationale |
|---|---|---|---|
| Sigma | base event: query length ≥ `query_length.one_at`, or `TXT`/`NULL` with length ≥ `query_length.zero_at`; `.arpa`, `_`-labels and `SRV` filtered | approx (base) | Single-event filter feeding the correlation below. |
| Sigma | `event_count` correlation ≥ `min_queries` per `id.orig_h` per window | approx | Captures volume of suspicious queries per host. Cannot group by registered domain (no PSL in Sigma) or score entropy and uniqueness. |
| Suricata | `long_query`: `dns.query; pcre:"/^.{N,}$/"` with per-source threshold | approx | Length plus rate only. |
| Suricata | `txt_rate`, `null_rate`: `dns.rrtype` 16 / 10 with per-source threshold | approx | TXT/NULL rate only; mail servers' TXT lookups (SPF/DKIM) need suppression. |

### dga

| Format | Rule | Tier | Rationale |
|---|---|---|---|
| Sigma | base event: `rcode_name: NXDOMAIN`, single-label names and internal zones filtered | approx (base) | Mirrors Signal A's inclusion rules. |
| Sigma | `value_count` correlation on `query` ≥ `nx_burst_min` per `id.orig_h` within the burst window | approx | Signal A only: counts distinct full names rather than registered domains and has no lexical (Signal B) gate, so it is noisier than the analyzer. |
| Suricata | `nxdomain_rate`: `dns.rcode:3` with per-destination threshold | companion | Counts NXDOMAIN responses (not unique domains) — a cheap pre-filter for hosts worth running the analyzer on. |

### lateral_movement

| Format | Rule | Tier | Rationale |
|---|---|---|---|
| Sigma | `admin_share_write` on `product: zeek, service: smb_files` | **full** | Signal 2 maps cleanly onto single events: admin-share path regex (tolerant of Zeek's escaped backslashes, equivalent to the analyzer's normalization), internal source and destination, executable extensions, write actions, and the same allowlist filters. Only the score branches whose score meets `min_confidence` are included, so emission conditions match the analyzer. The analyzer aggregates per host pair per window; the rule fires per event. |
| Sigma | `fanout`: `value_count` of `id.resp_h` per `id.orig_h` within 10 minutes | approx | Uses the host count at which the analyzer's fan-out score first reaches `min_confidence` (20 by default). Cannot separate scan from access patterns. |
| Suricata | `admin_share_connect` (flowbit setter, no alert) + `admin_share_exec_transfer` | approx | `smb.share` marks flows that connected to `ADMIN$`/drive shares; `file.name` with executable extensions alerts on the same flow. Suricata cannot bind a file to the specific tree it was written to. |
| Suricata | `fanout`: SYN threshold to admin ports per source | approx | Counts session attempts, not distinct targets. |
| Sigma, Suricata | `new_admin_pair` | not exported | Needs a persistent first-seen baseline with a 7-day warm-up; neither format can express stateful baselines. |

## Rule identity

Sigma `id`s are UUIDv5 over `(detector, signal, config hash)`; Suricata SIDs
are derived from the same UUID inside the local range 1,000,000–1,999,999.
Re-exporting an unchanged configuration is byte-identical (CI checks this),
so downstream SIEMs update rules in place. Changing a detector's parameters
or the site policy produces new identifiers for that detector only.
