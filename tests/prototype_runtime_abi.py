#!/usr/bin/env python3
"""Verify prototype-local Chunk and Block proxy layout derivation."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_v4_payload as payload

MASK32 = 0xFFFFFFFF


def walk(proto: payload.Prototype, path: tuple[int, ...] = ()):
    yield path, proto
    for index, child in enumerate(proto.children):
        yield from walk(child, path + (index,))


def verify(path: Path) -> None:
    info = payload.parse_and_verify(path)
    chunk_layouts: list[tuple[int, ...]] = []
    block_layouts: list[tuple[int, ...]] = []
    for _path, proto in walk(info.root):
        length = proto.end - proto.start
        chunk_layouts.append(tuple(payload.derive_permutation(
            16, proto.k1, proto.k2, proto.k3,
            (payload.SCHEMA_DOMAIN + length * 257) & MASK32,
        )))
        for block in proto.blocks:
            block_layouts.append(tuple(payload.derive_permutation(
                10, proto.k1, proto.k2, proto.k3,
                (payload.SCHEMA_DOMAIN + (block.start_pc + block.verifier % 65536) * 257) & MASK32,
            )))
    if any(sorted(layout) != list(range(len(layout))) for layout in chunk_layouts + block_layouts):
        raise ValueError("prototype-local runtime ABI is not a permutation")
    if len(chunk_layouts) > 1 and len(set(chunk_layouts)) < 2:
        raise ValueError("all prototypes reused one Chunk layout")
    if len(block_layouts) > 1 and len(set(block_layouts)) < 2:
        raise ValueError("all blocks reused one Block layout")
    source = path.read_text("latin1")
    if re.search(r"\b(?:NewPrototypeRecord|Layout|Storage|Proxy)\b", source):
        raise ValueError("stable prototype-ABI identifier leaked")
    print(
        f"PASS prototype-local runtime ABI: prototypes={len(chunk_layouts)} "
        f"chunk-layouts={len(set(chunk_layouts))} blocks={len(block_layouts)} "
        f"block-layouts={len(set(block_layouts))}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    args = parser.parse_args()
    try:
        verify(args.generated)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
