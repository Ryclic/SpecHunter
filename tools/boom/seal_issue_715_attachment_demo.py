#!/usr/bin/env python3
"""Seal the original issue #715 case study from checked-in evidence files."""

import json
import sys
from pathlib import Path

from spechunter.attachment_case import build_seal


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_absolute():
        print("usage: seal_issue_715_attachment_demo.py /ABSOLUTE/output.json", file=sys.stderr)
        return 2
    output = Path(sys.argv[1])
    output.write_text(json.dumps(build_seal(output.parent), indent=2) + "\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
