#!/usr/bin/env python3
"""Verify safe fresh-table SETTABLE groups are physically reordered."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


PROFILE = re.compile(r"Fresh table write order: groups=(\d+); writes=(\d+); signature=([0-9a-f]{8})\.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_log", type=Path)
    args = parser.parse_args()
    match = PROFILE.search(args.build_log.read_text("utf-8", errors="replace"))
    if not match:
        raise SystemExit("fresh-table write-order profile was not found")
    groups, writes, signature = int(match.group(1)), int(match.group(2)), match.group(3)
    if groups < 1 or writes < 3 or signature == "00000000":
        raise SystemExit(f"fresh-table writes were not materially reordered: {match.group(0)}")

    root = Path(__file__).resolve().parents[1]
    generator = (root / "IronBrew2/Obfuscator/VM Generation/Generator.cs").read_text()
    for anchor in ("RandomizeFreshTableWrites", "write.B <= 255", "write.BackReferences.Count", "shuffled.Shuffle"):
        if anchor not in generator:
            raise SystemExit(f"safe table-write reorder architecture is missing: {anchor}")

    print(f"PASS fresh table write order: groups={groups}, writes={writes}, signature={signature}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
