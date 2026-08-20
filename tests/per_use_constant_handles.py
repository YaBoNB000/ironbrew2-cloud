#!/usr/bin/env python3
"""Verify repeated logical constants receive independent random use handles."""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from static_attack_baseline import analyze
from verify_v4_payload import parse_and_verify


def verify(generated: Path, expected_value: str) -> None:
    info = parse_and_verify(generated)
    report = analyze(generated, [])
    matching = [
        item for item in report.decoded_constants
        if item["type"] == "string" and item["value"] == expected_value
    ]
    if len(matching) < 2:
        raise ValueError(f"repeated logical string did not produce multiple capsules: {matching}")
    handles = [item["index"] for item in matching]
    if len(set(handles)) != len(handles):
        raise ValueError(f"repeated string reused a stable constant handle: {handles}")
    if any(not 1 <= handle <= 65535 for handle in handles):
        raise ValueError(f"constant handle is outside uint16 operand space: {handles}")
    if handles == sorted(handles) and handles == list(range(handles[0], handles[0] + len(handles))):
        raise ValueError(f"constant handles are sequential rather than randomized: {handles}")

    all_handles = [capsule.index for _, proto in _prototypes(info.root) for capsule in proto.capsules]
    duplicates = [handle for handle, count in _counts(all_handles).items() if count > 1]
    if duplicates:
        raise ValueError(f"capsule handle was reused within the payload: {duplicates}")

    root = Path(__file__).resolve().parents[1]
    serializer = (root / "IronBrew2/Bytecode Library/Bytecode/Serializer.cs").read_text()
    for anchor in ("AssignConstantHandle", "constantsByHandle", "_random.Next(1, 65536)"):
        if anchor not in serializer:
            raise ValueError(f"serializer per-use handle architecture is missing: {anchor}")

    print(
        "PASS per-use constant handles: "
        f"value-occurrences={len(matching)}, handles={handles}, all-capsules={len(all_handles)}"
    )


def _prototypes(root, path=()):
    yield path, root
    for index, child in enumerate(root.children):
        yield from _prototypes(child, path + (index,))


def _counts(values):
    result = defaultdict(int)
    for value in values:
        result[value] += 1
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("--expect", required=True)
    args = parser.parse_args()
    try:
        verify(args.generated, args.expect)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
