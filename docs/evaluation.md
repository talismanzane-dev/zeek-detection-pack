# Evaluation procedure (CTU-13 and other labelled datasets)

**Status: no benchmark has been run.** Every performance figure in this
repository is a placeholder until the procedure below has been executed and
its output reviewed. The bundled `fixtures/` suite is synthetic: it verifies
that detector logic does what it claims, and its results must never be
reported as performance.

## What gets measured

`python -m zdp.harness` matches detections to `labels.json` ground truth
(detector + source must agree, plus destination/indicator when the label
specifies them, with ±120 s temporal tolerance; one-to-one greedy assignment
by confidence) and computes TP, FP, FN, precision, recall and F1 per detector
and micro-averaged overall. Zero denominators are reported as 0.0 and flagged
in `undefined`. Output records the framework version and config hash.

## CTU-13

CTU-13 (Garcia et al., Computers & Security 45, 2014; Stratosphere Lab, CTU
Prague) contains 13 botnet captures with Argus bidirectional flows labelled
Background, Normal or Botnet. Download it from the Stratosphere Lab website;
it is not redistributed here.

1. **Zeek logs.** For each scenario, run Zeek on the capture:

   ```bash
   mkdir -p data/ctu13/42 && cd data/ctu13/42
   zeek -C -r /path/to/botnet-capture-20110810-neris.pcap /path/to/repo/docker/zeek/local.zeek
   ```

2. **Candidate labels.** Derive `c2_beaconing` labels from the C2-labelled
   botnet flows (`From-Botnet…-CC…`):

   ```bash
   python tools/ctu13_labels.py --binetflow capture20110810.binetflow \
       --scenario ctu13-42 --out-dir data/ctu13/42
   ```

   This writes `labels.json` and a `site.yaml` declaring the university's
   network (`147.32.0.0/16`) as internal — CTU-13 hosts use public addresses,
   so the RFC 1918 default would gate everything out.

   Check the timezone: binetflow `StartTime` values are local capture time
   (`--timezone`, default `Europe/Prague`). Compare one flow against the pcap
   before trusting the windows.

3. **Review the labels.** CTU-13 labels describe botnet flows, not beaconing
   specifically. Read the candidates, delete ones that are not periodic C2,
   and note each decision. Record the reviewer and date in the scenario's
   `README.md`.

4. **Run the harness.**

   ```bash
   python -m zdp.harness --fixtures data/ctu13 --suite ctu13 \
       --out metrics/benchmark.json --reports reports/ctu13
   ```

5. **Publish.** Re-render the README block from the benchmark file and commit
   both:

   ```bash
   python tools/render_metrics.py --metrics metrics/benchmark.json
   ```

   `render_metrics.py` refuses to render the synthetic `fixtures` suite as a
   benchmark. Then fill the "Measured FP rate" slots in
   `reports/false_positives.md` from `reports/ctu13/*.md`, stating dataset,
   version and config hash.

## Coverage caveats

- CTU-13 labels support `c2_beaconing` evaluation directly. `dns_tunneling`,
  `dga` and `lateral_movement` need datasets labelled for those behaviours
  (e.g. a tunnelling testbed capture, DGA feeds replayed as NXDOMAIN
  traffic, or a purple-team exercise captured with Zeek). Until such data is
  evaluated, their metrics stay placeholders.
- The lateral-movement new-pair signal needs seven days of baseline. Short
  captures exercise only the admin-share and fan-out signals unless a
  `state_seed.json` baseline is supplied.
- The ±120 s tolerance and `dedup_policy: ignore` are harness defaults; report
  them alongside any result, and use `--dedup-policy fp` to measure alert
  volume.
