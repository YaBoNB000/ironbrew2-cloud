#!/usr/bin/env python3
"""Verify branch-free code is split into randomized authenticated micro-blocks."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_v4_payload import parse_and_verify


LIMIT = re.compile(r"Synthetic micro-block limit: ([3-6])\.")


def verify(generated: Path, build_log: Path) -> None:
    info = parse_and_verify(generated)
    match = LIMIT.search(build_log.read_text("utf-8", errors="replace"))
    if not match:
        raise ValueError("build-local synthetic micro-block limit was not logged")
    limit = int(match.group(1))
    blocks = info.root.blocks
    if len(blocks) < 3:
        raise ValueError(f"straight-line fixture was not split materially: {len(blocks)} blocks")
    if any(block.count < 1 or block.count > limit for block in blocks):
        raise ValueError(f"a block exceeds build-local limit {limit}")
    route_tokens = [block.route_token for block in blocks]
    if any(token == 0 for token in route_tokens) or len(set(route_tokens)) != len(route_tokens):
        raise ValueError("synthetic micro-blocks do not use unique nonzero route tokens")
    starts = sorted(block.start_pc for block in blocks)
    boundaries = starts + [info.root.instruction_count + 1]
    if starts[0] != 1 or any(right - left > limit for left, right in zip(boundaries, boundaries[1:])):
        raise ValueError(f"straight-line micro-block cuts exceed selected limit {limit}: {starts}")
    if sum(bool(block.successors) for block in blocks) < len(blocks) - 2:
        raise ValueError("synthetic micro-block successor chain is incomplete")

    root = Path(__file__).resolve().parents[1]
    context = (root / "IronBrew2/Obfuscator/ObfuscationContext.cs").read_text()
    serializer = (root / "IronBrew2/Bytecode Library/Bytecode/Serializer.cs").read_text()
    if "MaxBlockInstructions = 3 + schemaRandom.Next(4)" not in context:
        raise ValueError("micro-block limit is not randomized per build")
    if "_context.MaxBlockInstructions" not in serializer:
        raise ValueError("serializer does not consume the build-local micro-block limit")

    print(
        "PASS synthetic micro-blocks: "
        f"limit={limit}, blocks={len(blocks)}, physical={info.root.instruction_count}, "
        "route-tokens=unique"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("build_log", type=Path)
    args = parser.parse_args()
    try:
        verify(args.generated, args.build_log)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
