#!/usr/bin/env python3
"""Backward-compatible entry point.

The project moved from a single script into the ``password_auditor`` package.
This shim keeps ``python password_analyzer.py ...`` working. Prefer:

    python -m password_auditor --help
"""

from password_auditor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
