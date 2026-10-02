# Tuning and calibraton

The default thresholds are design starting points from the specification.
They have **not** been calibrated on production traffic, and no claim about
detection performance is made anywhere in this repository. Tuning is
mandatory before you rely on the output.

## 1. Describe your site (overlay, not edits)

Keep `config/default.yaml` untouched and put site facts in an overlay:

```yaml
# site.yaml
site:
  networks:
    internal: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7, 100.64.0.0/10]
    allowlists:
      updates: [192.0.2.80/32]          # vendor update mirror (from proxy logs)
      monitoring: [198.51.100.25/32]
    admin_hosts: [10.1.8.0/28]          # jump hosts / PAWs
    scanner_hosts: [10.1.9.50/32]       # Nessus / Qualys / OpenVAS
    lateral_allow_sources:
      - cidr: 10.1.9.10/32
        justification: "SCCM primary site server: client push installs via ADMIN$"
  allow_domains: [corp-saas.example, edr-cloud.example]
  internal_zones: [corp.example.org]
  schedule:
    business_hours: {timezone: Europe/London, start: "07:30", end: "19:00"}

detectors:                              # threshold overrides go here too
  dns_tunneling:
    min_queries: 50
```

```bash
zdp run --logs /data/zeek --overlay site.yaml --out detections.jsonl
```

Overlays are deep-merged (lists replace). The effective config hash changes
with every overlay and is recorded in each harness run and exported rule.

## 2. Calibration procedure

Do this per detector, on at least two weeks of your own logs.

1. **Baseline run.** Run all detectors with defaults and a persistent state
   store: `zdp run --logs <day> --state state.db --overlay site.yaml` once per
   day of logs, in order. Lateral new-pair output stays empty for the first
   seven days by design.
2. **Triage every detection** as true positive, benign-but-expected, or
   false positive, and write the outcome as `labels.json` (positives) plus
   notes (`benign` section) next to a copy of the logs. You now have a site
   fixture.
3. **Find the margin.** For each false positive, read `evidence.components`:
   which component drove the score? Prefer fixing the *cause* (allowlist the
   destination, add the scanner, mark the internal zone) over raising
   `min_confidence`, which blinds the detector everywhere.
4. **Move one anchor at a time** and re-run the harness on your site fixture
   (`python -m zdp.harness --fixtures site-fixtures --suite site-<name>`).
   Record the version, config hash and resulting counts in your change notes.
5. **Regression-proof it.** Add a minimal reproduction of each FP class to
   `fp_traps` (via `tools/gen_fixtures.py`) so a future change cannot
   reintroduce it.

### Detector-specific notes

- **c2_beaconing.** Most noise comes from software update agents, telemetry
  and SaaS keep-alives. Allowlist by destination category. If you lower
  `min_connections`, also consider raising `interval_cv.one_at` — CV
  estimates from very few points are noisy.
- **dns_tunneling.** The primary tuning burden is EDR/AV cloud lookups that
  encode file hashes as hex subdomains: they have high entropy and volume.
  Allowlist the vendor's registered domain. Do not lower the entropy anchors
  to compensate; that also hides real tunnels.
- **dga.** Make sure `internal_zones` lists every internal DNS suffix, or
  search-suffix storms will at least show up as large NXDOMAIN volumes. The
  bigram anchors come from the bundled table; retrain it (see
  [detectors.md](detectors.md#bigram-table-training-and-calibration)) rather
  than hand-editing numbers.
- **lateral_movement.** Populate `admin_hosts`, `scanner_hosts` and
  `lateral_allow_sources` first; most of the noise is the IT department
  doing its job. Expect medium-severity new-pair detections for genuine
  admin work — they are triage candidates, not auto-block signals.

## 3. Setting quality gates

`quality_gates.yaml` holds two kinds of gate:

- **Fixture correctness assertions** (enforced now): negative scenarios must
  stay silent and every injected event must be matched. They test logic.
- **Per-detector metric floors** (`min_precision`, `min_recall`), all `null`
  today. `tools/check_gates.py` reports them as PENDING.

Set a floor only after a baseline run on a real labelled dataset has been
reviewed, and set it as a *minimum acceptance bar* below the reviewed result
(to absorb legitimate noise), never as an advertised performance figure.
Commit the floor together with a link to the run artifact that justified it.

## 4. Where metric values may appear

Precision, recall and F1 exist only as runtime harness output
(`metrics.json`, `reports/*.md`). The only committed place a value may appear
is the README block written by `tools/render_metrics.py` from a benchmark
`metrics.json` (never from the synthetic `fixtures` suite). CI runs
`tools/check_no_hardcoded_metrics.py` to keep it that way.
