#!/usr/bin/env python3
"""Thin wrapper — the attestation verifier lives in pkgintegrity.attest
(also reachable as `pkgattest attest`). Kept so demo scripts and docs that
call verify.py keep working."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgintegrity.attest import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
