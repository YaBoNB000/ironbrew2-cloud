#!/usr/bin/env python3
"""Verify that terminal opcode leaves compose shared semantic fragments."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only

IDENT = r"[A-Za-z_]\w*"
ACCESS = rf"{IDENT}(?:\[\d+\])?"


def verify(vm_path: Path, final_path: Path | None) -> None:
    source = vm_path.read_text("latin1")
    code = _code_only(source)
    declarations = list(re.finditer(
        rf"local\s+function\s+({IDENT})\s*\(([^)]*)\)", code
    ))
    segments: list[tuple[str, list[str], str]] = []
    for index, declaration in enumerate(declarations):
        end = declarations[index + 1].start() if index + 1 < len(declarations) else len(code)
        params = [item.strip() for item in declaration.group(2).split(",") if item.strip()]
        segments.append((declaration.group(1), params, code[declaration.end():end]))

    reads: list[tuple[str, str]] = []
    writes: list[tuple[str, str]] = []
    binary: tuple[str, str] | None = None
    unary: tuple[str, str] | None = None
    pc: tuple[str, str] | None = None
    for name, params, body in segments:
        if len(params) == 2:
            index_name, mode = map(re.escape, params)
            direct = re.search(rf"return\s+({ACCESS})\s*\[\s*{index_name}\s*\]\s*;", body)
            raw = re.search(rf"return\s+({IDENT})\s*\(\s*({ACCESS})\s*,\s*{index_name}\s*\)\s*;", body)
            raw_fallback = re.search(
                rf"local\s+{IDENT}\s*=\s*({IDENT})\s*\(\s*({ACCESS})\s*,\s*{index_name}\s*\)\s*;",
                body,
            )
            raw_storage = raw.group(2) if raw else raw_fallback.group(2) if raw_fallback else None
            if direct and raw_storage and direct.group(1) == raw_storage:
                reads.append((name, direct.group(1)))
            if len(re.findall(rf"then\s+return\s+(?:not\s+|[-#])?{re.escape(params[1])}\s*;", body)) >= 3:
                unary = (name, body)
        elif len(params) == 3:
            first, second, third = map(re.escape, params)
            direct_write = re.search(
                rf"({ACCESS})\s*\[\s*{first}\s*\]\s*=\s*{second}\s*;", body
            )
            raw_write = re.search(
                rf"{IDENT}\s*\(\s*({ACCESS})\s*,\s*{first}\s*,\s*{second}\s*\)\s*;", body
            )
            if direct_write and raw_write and direct_write.group(1) == raw_write.group(1) and re.search(
                rf"return\s+{second}\s*;", body
            ):
                writes.append((name, direct_write.group(1)))
            operation_count = len(re.findall(
                rf"then\s+return\s+{second}\s*(?:\.\.|[+\-*/%^])\s*{third}\s*;", body
            ))
            if operation_count >= 7:
                binary = (name, body)
            if (re.search(rf"then\s+return\s+{first}\s*\+", body)
                    and re.search(rf"then\s+return\s+{second}\s*;", body)
                    and re.search(rf"else\s+return\s+{first}\s*\+\s*{second}\s*;", body)):
                pc = (name, body)

    if len(reads) != 2 or len({access for _, access in reads}) != 2:
        raise ValueError(f"expected shared stack/environment readers, found {reads}")
    if len(writes) != 1:
        raise ValueError(f"expected one shared destination/writeback fragment, found {writes}")
    if binary is None or unary is None or pc is None:
        raise ValueError("binary, unary and PC-transition fragment families were not all found")

    roles = {
        "stack-read": reads[0][0],
        "environment-read": reads[1][0],
        "writeback": writes[0][0],
        "binary": binary[0],
        "unary": unary[0],
        "pc": pc[0],
    }
    # Reader order is not semantically important. The stack reader is the one
    # sharing storage with the writeback fragment.
    write_storage = writes[0][1]
    for role in ("stack-read", "environment-read"):
        name = roles[role]
        storage = next(access for candidate, access in reads if candidate == name)
        if storage == write_storage:
            roles["stack-read"], roles["environment-read"] = name, roles["environment-read" if role == "stack-read" else "stack-read"]
            break

    calls = {role: len(re.findall(rf"\b{re.escape(name)}\s*\(", code)) - 1 for role, name in roles.items()}
    minimums = {"stack-read": 5, "environment-read": 1, "writeback": 5, "binary": 0, "unary": 0, "pc": 5}
    for role, minimum in minimums.items():
        if calls[role] < minimum:
            raise ValueError(f"{role} fragment is not shared across enough leaves: {calls[role]} < {minimum}")

    final_code = _code_only(final_path.read_text("latin1")) if final_path else ""
    leaked = re.search(
        r"\bHandler(?:ReadStack|ReadEnvironment|WriteStack|Binary|Unary|Pc|Fragment(?:Index|Value|Mode|Left|Right|Current|Target))\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable handler-fragment identifier leaked: {leaked.group(0)}")

    summary = ", ".join(f"{role}={calls[role]}" for role in minimums)
    print(f"PASS shared handler fragments: {summary}; operation-tokens=build-random")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("generated_output", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        verify(args.generated_vm, args.generated_output)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
