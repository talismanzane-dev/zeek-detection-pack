#!/usr/bin/env python3
"""Run every detector against the labeled fixtures and report metrics.

Equivalent to ``python -m zdp.harness``; see ``zdp/harness/runner.py``.
Precision, recall and F1 are computed here at runtime from ``labels.json``
ground truth — they are never stored in the repository.

    python harness.py --fixtures fixtures --out metrics.json --reports reports
"""

from zdp.harness.runner import main

if __name__ == "__main__":
    raise SystemExit(main())
