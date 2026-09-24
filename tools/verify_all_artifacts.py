#!/usr/bin/env python3
"""Compatibility entry point; use tools/verify_evidence.py."""

import runpy
from pathlib import Path

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).with_name("verify_evidence.py")), run_name="__main__")
