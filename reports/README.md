# reports/

Per-detector markdown reports (`<detector>.md`) and `summary.md` are **runtime
output** of the harness and are git-ignored:

```bash
python -m zdp.harness --fixtures fixtures --out metrics.json --reports reports
```

Every number in them is computed from `labels.json` ground truth during that
run and is stamped with the framework version and config hash. CI uploads them
as build artifacts. No metric value is ever committed to this directory.

The one hand-maintained file here is [`false_positives.md`](false_positives.md):
known false-positive conditions per detector, with placeholder slots for FP
rates to be measured on real data.
