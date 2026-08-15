#!/usr/bin/env python3
"""Verify that a generated Lua file embeds an IronBrew2 v3 payload header."""

from pathlib import Path
import re
import sys


def decode_base91(data: str) -> bytes:
    output = bytearray()
    value = -1
    accumulator = 0
    bits = 0
    for character in data:
        code = ord(character)
        digit = code - 33
        if code > 39:
            digit -= 1
        if code > 92:
            digit -= 1
        if not 0 <= digit <= 90:
            continue
        if value < 0:
            value = digit
            continue
        value += digit * 91
        accumulator += value << bits
        bits += 13 if value % 8192 > 88 else 14
        while bits >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            bits -= 8
        value = -1
    if value >= 0:
        accumulator += value << bits
        bits += 7
        while bits >= 8:
            output.append(accumulator & 0xFF)
            accumulator >>= 8
            bits -= 8
    return bytes(output)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {Path(sys.argv[0]).name} generated.lua")
    source = Path(sys.argv[1]).read_text("latin1")
    match = re.search(r"\blocal\s+[A-Za-z_]\w*\s*=\s*'([^']{12,})'", source)
    if not match:
        raise SystemExit("could not locate the first base91 payload segment")
    prefix = decode_base91(match.group(1))
    if len(prefix) < 9:
        raise SystemExit("decoded payload prefix is shorter than the fixed header")
    flags = prefix[8]
    version = flags >> 4
    features = flags & 0x0F
    if version != 3:
        raise SystemExit(f"expected payload version 3, found {version}")
    if features not in (6, 7):
        raise SystemExit(f"unexpected v3 feature bits (block flow + dispatcher required): {features}")
    print(f"PASS generated payload header: v{version}, features={features}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
