#!/usr/bin/env python3
"""Verify physical IR fusion and its combined runtime operand descriptor."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only
from verify_v4_payload import collect_fused_counts, count_instruction_records, parse_and_verify


def verify(generated: Path, generated_vm: Path | None) -> None:
    info = parse_and_verify(generated)
    counts = collect_fused_counts(info.root)
    physical = count_instruction_records(info.root)
    fused = [count for count in counts if count]
    logical = physical + sum(fused)
    if len(fused) < 8:
        raise ValueError(f"too few physical IR-fusion records: {len(fused)}")
    if logical - physical < 16:
        raise ValueError(f"IR fusion did not materially reduce records: {physical}/{logical}")
    if max(fused) > 5 or min(fused) < 1:
        raise ValueError(f"invalid fused supplemental member count: {sorted(set(fused))}")
    widths = {count + 1 for count in fused}
    if min(widths) < 2 or max(widths) > 6:
        raise ValueError(f"fused sequence widths are invalid: {sorted(widths)}")

    descriptors = [descriptor for _, proto in _prototypes(info.root)
                   for block in proto.blocks for descriptor in block.descriptors]
    if sum(descriptor >= 64 and descriptor & 1 == 0 for descriptor in descriptors) != len(fused):
        raise ValueError("fusion descriptor flag/count does not match physical fused records")

    root = Path(__file__).resolve().parents[1]
    opcode_source = (root / "IronBrew2/Obfuscator/Opcodes/OpSuperOperator.cs").read_text()
    generator_source = (root / "IronBrew2/Obfuscator/VM Generation/Generator.cs").read_text()
    serializer_source = (root / "IronBrew2/Bytecode Library/Bytecode/Serializer.cs").read_text()
    if "GetInstruction(Chunk, InstrPoint, Flow)" in opcode_source or "InstrPoint = InstrPoint + 1" in opcode_source:
        raise ValueError("fusion handler still fetches and replays serialized member instructions")
    if "Inst=FusedOperands[" not in opcode_source:
        raise ValueError("fusion handler does not consume the combined operand bundle")
    if "FusedStack=Setmetatable" not in opcode_source or "RawEqual(FusedValue,FusedValues[FusedKey])" not in opcode_source:
        raise ValueError("fusion handler does not generate one cross-member register dataflow")
    for barrier in ("case Opcode.Closure:", "case Opcode.Close:", "case Opcode.SetList:",
                    "case Opcode.Call:", "case Opcode.PushStack:",
                    "case Opcode.VarArg when instruction.B == 0:"):
        if barrier not in generator_source:
            raise ValueError(f"IR fusion safety barrier is missing: {barrier}")
    if "chunk.Instructions = loweredInstructions" not in serializer_source:
        raise ValueError("serializer does not physically lower fused IR sequences")
    if "fusedInstructions.Skip(1)" not in serializer_source:
        raise ValueError("serializer does not emit supplemental fused operands")

    if generated_vm:
        final_code = _code_only(generated.read_text("latin1"))
        vm_code = _code_only(generated_vm.read_text("latin1"))
        leaked = re.search(
            r"\b(?:FusedOperands|FusedValues|FusedWritten|FusedStack|FusedKey|FusedValue|FusedInstruction(?:Fields|Constants)?|FusedConstantFields|FusedDescriptor|FusedCount|FusedIndex|FusedType|FusedMask|IsFused|MaterializeFusedSlot)\b",
            vm_code + "\n" + final_code,
        )
        if leaked:
            raise ValueError(f"stable IR-fusion identifier leaked: {leaked.group(0)}")

    ratio = physical / logical
    print(
        "PASS IR-native fusion: "
        f"physical/logical={physical}/{logical} ({ratio:.3f}), fused-records={len(fused)}, widths={sorted(widths)}, "
        "barriers=CFG/CLOSURE/CLOSE/SETLIST/CALL/var-return"
    )


def _prototypes(root, path=()):
    yield path, root
    for index, child in enumerate(root.children):
        yield from _prototypes(child, path + (index,))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("generated_vm", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        verify(args.generated, args.generated_vm)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
