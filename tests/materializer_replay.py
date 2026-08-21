#!/usr/bin/env python3
"""Verify invocation-local authenticated writable instruction generations."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only
from static_attack_baseline import prototypes
from verify_v4_payload import parse_and_verify

IDENT = r"[A-Za-z_]\w*"


def verify(vm_path: Path, final_path: Path | None) -> None:
    source = vm_path.read_text("latin1")
    code = _code_only(source)
    if final_path is None:
        raise ValueError("generation verifier requires the final payload")
    info = parse_and_verify(final_path)
    programs = [
        program
        for _path, prototype in prototypes(info.root)
        for block in prototype.blocks
        for descriptor, program in zip(block.descriptors, block.generation_programs)
        if descriptor & 1 == 0
    ]
    if not programs or min(map(len, programs)) < 2 or max(map(len, programs)) > 5:
        raise ValueError("instruction generation programs are outside 2–5 rewrites")
    families = {family for program in programs for family, _mask in program}
    if len(families) < 3 or not families.issubset({0, 1, 2, 3}):
        raise ValueError(f"generation rewrite-family coverage is insufficient: {families}")
    if any(mask == 0 for program in programs for _family, mask in program):
        raise ValueError("generation program contains a zero rewrite mask")

    offsets = [
        104729, 209458, 314187, 418916, 523645, 628374, 733103,
        837832, 942561, 1047290, 1152019, 1256748,
    ]
    slot_match = re.search(
        rf"local\s+({IDENT})\s*=\s*32\s*\+\s*\(\(.*?\)\s*%\s*104729\s*\)\s*;",
        code,
        re.S,
    )
    if not slot_match:
        raise ValueError("prototype-derived generation overlay base slot was not found")
    base = slot_match.group(1)
    for offset in offsets:
        if not re.search(rf"local\s+{IDENT}\s*=\s*{re.escape(base)}\s*\+\s*{offset}\s*;", code):
            raise ValueError(f"generation overlay slot +{offset} is missing")

    required_shapes = (
        r"if\s+[^;]*<\s*2\s+or\s+[^;]*>\s*5\s+then",
        r"while\s+true\s+do|if\s+[^;]*<\s*[^;]*then",
    )
    if not all(re.search(pattern, code, re.S) for pattern in required_shapes):
        raise ValueError("variable generation bounds/replay branch were not found")

    root = Path(__file__).resolve().parents[1]
    generator = (root / "IronBrew2/Obfuscator/VM Generation/Generator.cs").read_text()
    serializer = (root / "IronBrew2/Bytecode Library/Bytecode/Serializer.cs").read_text()
    for anchor in (
        "ApplyGenerationRewrite", "BeginGenerationSeal", "AdvanceGenerationSeal",
        "ComputeGenerationGuard", "MaterializeGenerationProgramSlot",
        "MaterializeGenerationSealSlot", "MaterializeGenerationGuardSlot",
    ):
        if anchor not in generator:
            raise ValueError(f"generation runtime architecture is missing: {anchor}")
    if "generationCount = 2 + _random.Next(4)" not in serializer:
        raise ValueError("serializer does not generate 2–5 rewrite programs")
    if "generationOpcode" not in serializer or "generationA" not in serializer:
        raise ValueError("wire opcode/A fields are not stored as generation-0 values")
    if "MaterializeStage < 4" in generator:
        raise ValueError("legacy fixed four-stage materializer remains")

    # Top-level VM execution still requests the invocation-local overlay and may
    # accept a synthetic materializer Enum before the final generated instruction.
    access = rf"{IDENT}(?:\[\d+\])?"
    fetches = re.findall(
        rf"({access})\s*,\s*({access})\s*=\s*({IDENT})\([^;]*,\s*true\s*\)\s*;\s*"
        rf"if\s+\2\s*==\s*nil\s+then",
        code,
        re.S,
    )
    if len(fetches) != 1:
        raise ValueError(f"expected one top-level generation fetch, found {len(fetches)}")

    final_code = _code_only(final_path.read_text("latin1"))
    leaked = re.search(
        r"\b(?:Generation(?:Count|Program|Record|Index|Family|Mask|Seal|Guard|Completed)|"
        r"ApplyGenerationRewrite|BeginGenerationSeal|AdvanceGenerationSeal|ComputeGenerationGuard|"
        r"MaterializeGeneration(?:Program|Seal|Guard)Slot)\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable instruction-generation identifier leaked: {leaked.group(0)}")

    counts = sorted({len(program) for program in programs})
    print(
        "PASS authenticated writable instruction generations: "
        f"records={len(programs)}, generations={counts}, families={sorted(families)}, "
        "overlay=invocation-local, same-PC=replay, guard=state-bound"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("generated_output", type=Path, nargs="?")
    args = parser.parse_args()
    try:
        verify(args.generated_vm, args.generated_output)
    except (OSError, ValueError, IndexError, KeyError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
