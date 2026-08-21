#!/usr/bin/env python3
"""Verify Base91 carrier segments are consumed incrementally without concatenation."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only
from verify_v4_payload import is_base91_literal, parse_and_verify, scan_string_literals

IDENT = r"[A-Za-z_]\w*"


def verify(path: Path) -> None:
    source = path.read_text("latin1")
    literals = [
        literal
        for literal in scan_string_literals(source)
        if len(literal.content) >= 1024 and is_base91_literal(literal.content)
    ]
    if not literals:
        raise ValueError("no Base91 carrier segments were found")
    for literal in literals:
        before = source[max(0, literal.content_start - 4):literal.content_start - 1]
        after = source[literal.content_end + 1:literal.content_end + 5]
        if ".." in before or re.match(r"\s*\.\.", after):
            raise ValueError("a large Base91 carrier segment is concatenated directly")

    code = _code_only(source)
    recursive_consumer = re.search(
        rf"local\s+function\s+({IDENT})\s*\(\s*({IDENT})\s*\).*?"
        rf"if\s+{IDENT}\(\s*\2\s*\)\s*==\s*(['\"])table\3\s*then\s*"
        rf"for\s+({IDENT})\s*=\s*1\s*,\s*#\2\s+do\s*\1\(\s*\2\[\4\]\s*\)",
        source,
        re.S,
    )
    if not recursive_consumer:
        raise ValueError("recursive table/segment Base91 consumer was not found")
    if not re.search(rf"if\s*#{IDENT}\s*>=\s*2048\s+then", source):
        raise ValueError("decoded payload is not flushed into bounded chunks")
    if not re.search(rf"{IDENT}\s*%\s*2048\s*\+\s*1", source):
        raise ValueError("chunk-aware payload byte accessor was not found")

    parse_and_verify(path)
    if re.search(r"\b(?:PayloadParts|ConsumePayloadPart)\b", code):
        raise ValueError("stable streaming-carrier identifier leaked")
    print(
        f"PASS streaming Base91 carrier: segments={len(literals)} "
        "direct-concatenations=0"
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
