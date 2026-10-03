# metrics/

Home for **reviewed benchmark** harness output, e.g. `benchmark.json` from a
CTU-13 run ([procedure](../docs/evaluation.md)). `tools/render_metrics.py`
renders the README metrics block from `metrics/benchmark.json`; while it is
absent the block shows placeholders.

Never place synthetic-fixture results here: they test detector logic and are
not performance measurements (the renderer refuses the `fixtures` suite).
