#!/usr/bin/env python3
"""Verify SETTABLE key/value operands use separate tokenized materializers."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only

IDENT = r"[A-Za-z_]\w*"


def verify(vm_path: Path, final_path: Path | None) -> None:
    source = vm_path.read_text("latin1")
    code = _code_only(source)

    commit = re.search(
        rf"local\s+function\s+({IDENT})\s*\(\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*\)\s*"
        rf"\2\s*\[\s*\3\s*\]\s*=\s*\4\s*;\s*return\s+\4\s*;\s*end\s*;",
        code,
    )
    if not commit:
        raise ValueError("shared table commit fragment was not found")
    commit_name = commit.group(1)

    writer = re.search(
        rf"local\s+function\s+({IDENT})\s*\(\s*({IDENT})\s*,\s*({IDENT})\s*\)"
        rf"(?P<body>.*?)return\s+{re.escape(commit_name)}\s*\(.*?\)\s*;\s*end\s*;",
        code[commit.end():],
        re.S,
    )
    if not writer:
        raise ValueError("tokenized table writer was not found after its commit fragment")
    writer_name, mode_name, fields_name = writer.group(1, 2, 3)
    body = writer.group("body")

    acquisitions = re.findall(
        rf"({IDENT})\s*\(\s*{re.escape(mode_name)}\s*,\s*{re.escape(fields_name)}\s*\)",
        body,
    )
    if len(set(acquisitions)) != 2:
        raise ValueError(f"key/value do not use two independent acquisition fragments: {acquisitions}")
    branch_tokens = re.findall(
        rf"(?:if|elseif)\s+{re.escape(mode_name)}\s*==\s*(\([^;]+?\))\s+then",
        body,
    )
    if len(branch_tokens) != 4 or len(set(branch_tokens)) < 3:
        raise ValueError(f"table operand modes are not four build-random token branches: {branch_tokens}")
    call_count = len(re.findall(rf"\b{re.escape(writer_name)}\s*\(", code)) - 1
    if call_count < 4:
        raise ValueError(f"all four SETTABLE forms were not routed through the writer: {call_count}")

    root = Path(__file__).resolve().parents[1]
    opcode_source = (root / "IronBrew2/Obfuscator/Opcodes/OpSetTable.cs").read_text()
    context_source = (root / "IronBrew2/Obfuscator/ObfuscationContext.cs").read_text()
    if opcode_source.count("HandlerTableWrite(") != 4:
        raise ValueError("not all SETTABLE opcode variants use the shared writer")
    if "TableWriteTokens" not in context_source:
        raise ValueError("build context does not carry table-write operation tokens")

    final_code = _code_only(final_path.read_text("latin1")) if final_path else ""
    leaked = re.search(
        r"\bHandlerTable(?:Write|AcquireKey|AcquireValue|Commit|Target|Key|Value|Mode)\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable table materializer identifier leaked: {leaked.group(0)}")

    print(
        "PASS table key/value materialization: "
        f"writer-calls={call_count}, mode-tokens=4, acquisition-fragments=2, commit-fragment=1"
    )


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
