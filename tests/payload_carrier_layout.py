#!/usr/bin/env python3
"""Validate one generated payload-carrier layout and emit its Build metadata."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from verify_v4_payload import is_base91_literal, parse_and_verify, scan_string_literals


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("build_log", type=Path)
    args = parser.parse_args()

    source = args.generated.read_text("latin1")
    log = args.build_log.read_text("utf-8", errors="replace")
    match = re.search(
        r"Payload carrier: segments=(\d+); carrier=(\d+); assembly=(\d+); stages=([0-9,]+)\.",
        log,
    )
    if not match:
        raise SystemExit("missing payload-carrier Build record")

    expected_count = int(match.group(1))
    carrier = int(match.group(2))
    assembly = int(match.group(3))
    stage_counts = tuple(int(value) for value in match.group(4).split(","))
    if not 7 <= expected_count <= 14:
        raise SystemExit(f"payload-carrier segment count is outside 7–14: {expected_count}")
    if carrier not in range(4) or assembly not in range(4):
        raise SystemExit(f"unknown payload-carrier topology: carrier={carrier}, assembly={assembly}")
    if len(stage_counts) != 5 or min(stage_counts) < 1 or sum(stage_counts) != expected_count:
        raise SystemExit(f"invalid five-stage payload distribution: {stage_counts}")
    if "__IB2_GUARD_STAGE_" in source:
        raise SystemExit("an internal payload-carrier stage marker leaked into generated output")

    literals = [
        literal
        for literal in scan_string_literals(source)
        if len(literal.content) >= 1024 and is_base91_literal(literal.content)
    ]
    literals.sort(key=lambda literal: literal.content_start)
    if len(literals) != expected_count:
        raise SystemExit(
            f"Build log reports {expected_count} payload segments, source contains {len(literals)}"
        )

    lengths = [len(literal.content) for literal in literals]
    ratio = max(lengths) / min(lengths)
    if ratio < 2.0:
        raise SystemExit(f"payload segments remain near-uniform: max/min={ratio:.3f}")

    # A stage may contain several adjacent assignments, but crossing each of the
    # five guard lanes traverses real guard code. Four material source gaps prove
    # the data is interleaved rather than emitted as one contiguous data prefix.
    gaps = [
        literals[index + 1].content_start - literals[index].content_end
        for index in range(len(literals) - 1)
    ]
    interleaved_gaps = sum(gap >= 128 for gap in gaps)
    if interleaved_gaps < 4:
        raise SystemExit(
            f"payload assignments do not span all five guard stages: gaps={gaps}"
        )

    # This authenticates the reconstructed bytes and all payload framing, so a
    # physically randomized carrier cannot silently change logical read order.
    parse_and_verify(args.generated)

    print(json.dumps({
        "segments": expected_count,
        "carrier": carrier,
        "assembly": assembly,
        "stages": stage_counts,
        "minimum": min(lengths),
        "maximum": max(lengths),
        "ratio": round(ratio, 3),
        "interleaved_gaps": interleaved_gaps,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
