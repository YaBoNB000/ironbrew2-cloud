#!/usr/bin/env python3
"""Verify prototype-local instruction-column decoder families and round trips."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_v4_payload as payload


def walk(prototype: payload.Prototype):
    yield prototype
    for child in prototype.children:
        yield from walk(child)


def verify(path: Path) -> set[int]:
    info = payload.parse_and_verify(path)
    modes: set[int] = set()
    columns = changed = 0
    for prototype in walk(info.root):
        mode = payload.prototype_decoder_mode(prototype)
        if mode not in range(4):
            raise ValueError(f"invalid prototype decoder mode: {mode}")
        modes.add(mode)
        for block in prototype.blocks:
            for offset, spans in enumerate(block.record_column_spans):
                pc = block.start_pc + offset
                for role, (_frame, start, end) in spans.items():
                    encoded = info.body[start:end]
                    decoded = payload.decode_prototype_column(
                        encoded, prototype, block, role, pc
                    )
                    rebuilt = payload.encode_prototype_column(
                        decoded, prototype, block, role, pc
                    )
                    if rebuilt != encoded:
                        raise ValueError(
                            f"prototype decoder round trip failed at pc={pc}, role={role}, mode={mode}"
                        )
                    columns += 1
                    changed += encoded != decoded
    if columns == 0 or changed == 0:
        raise ValueError("prototype decoder families did not transform any instruction column")

    code = path.read_text("latin1")
    leaked = re.search(
        r"\b(?:PrototypeDecoderMode|DecodePrototypeColumn|DecoderMode)\b", code
    )
    if leaked:
        raise ValueError(f"stable prototype-decoder identifier leaked: {leaked.group(0)}")
    print(
        f"PASS prototype decoder families: modes={','.join(map(str, sorted(modes)))} "
        f"columns={columns} transformed={changed}"
    )
    return modes


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
