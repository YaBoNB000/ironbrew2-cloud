#!/usr/bin/env python3
"""Create test-only skip/duplicate attacks against the generation overlay."""

from __future__ import annotations

import argparse
from pathlib import Path
import re

IDENT = r"[A-Za-z_]\w*"


def instrument(source_path: Path, output_dir: Path) -> None:
    source = source_path.read_text("latin1")
    slots = re.search(
        rf"local\s+({IDENT})\s*=\s*32\s*\+\s*\(\(.*?\)\s*%\s*104729\s*\)\s*;.*?"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*523645\s*;",
        source,
        re.S,
    )
    if not slots:
        raise ValueError("generation stage slot was not found")
    stage_slot = slots.group(2)

    initialize = list(re.finditer(
        rf"({IDENT})\[{re.escape(stage_slot)}\]\s*=\s*1\s*;", source
    ))
    if len(initialize) != 1:
        raise ValueError(f"expected one generation-stage initialization, found {len(initialize)}")
    skip = source[:initialize[0].start()] + initialize[0].group(0).replace("= 1", "= 2").replace("=1", "=2") + source[initialize[0].end():]

    increment = list(re.finditer(
        rf"({IDENT})\[{re.escape(stage_slot)}\]\s*=\s*({IDENT})\s*\+\s*1\s*;", source
    ))
    if len(increment) != 1:
        raise ValueError(f"expected one generation-stage increment, found {len(increment)}")
    duplicate_statement = re.sub(r"\s*\+\s*1", "", increment[0].group(0))
    duplicate = source[:increment[0].start()] + duplicate_statement + source[increment[0].end():]

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "generation-skip.lua").write_text(skip, "latin1")
    (output_dir / "generation-duplicate.lua").write_text(duplicate, "latin1")
    print("PASS generated test-only generation skip/duplicate attacks")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    try:
        instrument(args.generated_vm, args.output_dir)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
