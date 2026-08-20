#!/usr/bin/env python3
"""Thin wrapper — `pkgattest verify-image`. Kept so demo scripts and docs
that call verify_image.py keep working."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgintegrity.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["verify-image"] + sys.argv[1:]))
