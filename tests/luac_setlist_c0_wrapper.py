#!/usr/bin/env python3
"""Test-only luac wrapper that turns one SETLIST C=1 into C=0 + data word.

IronBrew2 normally invokes this wrapper twice. The validation compile is left
untouched; only temp/t1.lua, the bytecode consumed by the obfuscator, is patched.
"""

from pathlib import Path
import os
import subprocess
import sys


def read_uint(data: bytearray, offset: int, size: int, byteorder: str) -> int:
    return int.from_bytes(data[offset : offset + size], byteorder)


def patch_setlist(path: Path) -> None:
    data = bytearray(path.read_bytes())
    if data[:6] != b"\x1bLua\x51\x00":
        raise SystemExit("expected a Lua 5.1 binary chunk")

    byteorder = "little" if data[6] == 1 else "big"
    int_size, size_t_size, instruction_size = data[7], data[8], data[9]
    if instruction_size != 4:
        raise SystemExit("SETLIST test requires 32-bit Lua instructions")

    position = 12
    source_length = read_uint(data, position, size_t_size, byteorder)
    position += size_t_size + source_length
    position += int_size * 2 + 4  # line range and four one-byte function fields

    sizecode_offset = position
    sizecode = read_uint(data, position, int_size, byteorder)
    position += int_size
    code_offset = position
    words = [
        read_uint(data, code_offset + index * 4, 4, byteorder)
        for index in range(sizecode)
    ]

    # Lua 5.1 opcode 34 is SETLIST. The fixture deliberately emits B=1, C=1,
    # so replacing C with zero and appending data word 1 preserves semantics.
    candidates = [
        index
        for index, word in enumerate(words)
        if (word & 0x3F) == 34
        and ((word >> 23) & 0x1FF) == 1
        and ((word >> 14) & 0x1FF) == 1
    ]
    if len(candidates) != 1:
        raise SystemExit(f"expected one patchable SETLIST, found {len(candidates)}")

    index = candidates[0]
    words[index] &= ~(0x1FF << 14)
    words.insert(index + 1, 1)
    encoded_code = b"".join(word.to_bytes(4, byteorder) for word in words)

    data[sizecode_offset : sizecode_offset + int_size] = len(words).to_bytes(
        int_size, byteorder
    )
    data[code_offset : code_offset + sizecode * 4] = encoded_code
    path.write_bytes(data)


def main() -> None:
    real_luac = os.environ.get("IB2_REAL_LUAC")
    if not real_luac:
        raise SystemExit("IB2_REAL_LUAC is required")

    arguments = sys.argv[1:]
    subprocess.run([real_luac, *arguments], check=True)

    if not arguments or Path(arguments[-1]).name != "t1.lua":
        return
    try:
        output = Path(arguments[arguments.index("-o") + 1])
    except (ValueError, IndexError):
        raise SystemExit("luac wrapper expected an output after -o")
    patch_setlist(output)


if __name__ == "__main__":
    main()
