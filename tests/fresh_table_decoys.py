#!/usr/bin/env python3
"""Verify safe fresh-table writes receive temporary decoy insert/cleanup paths."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only
from verify_v4_payload import parse_and_verify
from table_write_order import PROFILE


def verify(generated: Path, generated_vm: Path, build_log: Path) -> None:
    info = parse_and_verify(generated)
    match = PROFILE.search(build_log.read_text("utf-8", errors="replace"))
    if not match:
        raise ValueError("fresh-table write profile was not found")
    expected_writes = int(match.group(2))
    descriptors = [descriptor for block in info.root.blocks for descriptor in block.descriptors]
    fresh = [descriptor for descriptor in descriptors if descriptor >= 128 and descriptor & 1 == 0]
    if len(fresh) != expected_writes:
        raise ValueError(f"fresh descriptor count mismatch: {len(fresh)} != {expected_writes}")
    if any((descriptor - 128) >= 64 for descriptor in fresh):
        raise ValueError("fresh-table write was unsafely fused with another instruction")

    root = Path(__file__).resolve().parents[1]
    instruction = (root / "IronBrew2/Bytecode Library/IR/Instruction.cs").read_text()
    generator = (root / "IronBrew2/Obfuscator/VM Generation/Generator.cs").read_text()
    serializer = (root / "IronBrew2/Bytecode Library/Bytecode/Serializer.cs").read_text()
    for source, anchor in (
        (instruction, "FreshTableWrite"),
        (generator, "HandlerTableDecoyKey={}"),
        (generator, "HandlerTableDecoyKey,nil"),
        (serializer, "instruction.FreshTableWrite ? 128 : 0"),
    ):
        if anchor not in source:
            raise ValueError(f"fresh-table decoy architecture is missing: {anchor}")

    code = _code_only(generated_vm.read_text("latin1"))
    final_code = _code_only(generated.read_text("latin1"))
    leaked = re.search(
        r"\b(?:FreshTableWrite|IsFreshTableWrite|MaterializeFreshTableSlot|HandlerTable(?:Fresh|DecoyKey|DecoyValue))\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable fresh-table decoy identifier leaked: {leaked.group(0)}")

    print(
        "PASS fresh-table decoys: "
        f"flagged-writes={len(fresh)}, temporary-table-keys={len(fresh)}, cleanup=setter-trampoline"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("build_log", type=Path)
    args = parser.parse_args()
    try:
        verify(args.generated, args.generated_vm, args.build_log)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
