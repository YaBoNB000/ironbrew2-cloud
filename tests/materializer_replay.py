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
    families = {record[0] for program in programs for record in program}
    if len(families) < 3 or not families.issubset({0, 1, 2, 3}):
        raise ValueError(f"generation rewrite-family coverage is insufficient: {families}")
    if any(record[1] == 0 for program in programs for record in program):
        raise ValueError("generation program contains a zero rewrite mask")
    selector_lanes = {record[2] for program in programs for record in program}
    if selector_lanes != {1, 2, 3}:
        raise ValueError(f"selector-lane program coverage is incomplete: {selector_lanes}")
    if any(record[3] == 0 for program in programs for record in program):
        raise ValueError("selector-lane program contains a zero recipe token")

    offsets = [
        104729, 209458, 314187, 418916, 523645, 628374, 733103,
        837832, 942561, 1047290, 1152019, 1256748, 1361477,
        1466206, 1570935, 1675664, 1780393, 1885122, 1989851,
    ]
    slot_matches = list(re.finditer(
        rf"local\s+({IDENT})\s*=\s*32\s*\+\s*\(\(.*?\)\s*%\s*104729\s*\)\s*;",
        code,
        re.S,
    ))
    if len(slot_matches) < 2:
        raise ValueError("selector validator and generation overlay base slots were not found")
    slot_match = slot_matches[1]
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
        "ComputeGenerationGuard", "GenerationFieldDigest",
        "MaterializeGenerationProgramSlot", "MaterializeGenerationSealSlot",
        "MaterializeGenerationGuardSlot", "MaterializeGenerationProgramSealSlot",
        "PrepareSelectorLane", "ResolveDialectMode", "MaterializeSelectorSealSlot",
    ):
        if anchor not in generator:
            raise ValueError(f"generation runtime architecture is missing: {anchor}")
    if "generationCount = 2 + _random.Next(4)" not in serializer:
        raise ValueError("serializer does not generate 2–5 rewrite programs")
    if "generationOpcode" not in serializer or "generationA" not in serializer:
        raise ValueError("wire opcode/A fields are not stored as generation-0 values")
    if "MaterializeStage < 4" in generator:
        raise ValueError("legacy fixed four-stage materializer remains")

    # Top-level execution requests the invocation-local overlay exactly once;
    # ResolveDialectMode consumes and validates its selector seal before routing.
    function_defs = list(re.finditer(rf"local\s+function\s+({IDENT})\s*\(", code[:slot_match.start()]))
    if not function_defs:
        raise ValueError("generation fetch function declaration was not found")
    get_instruction = function_defs[-1].group(1)
    access = rf"{IDENT}(?:\[\d+\])?"
    fetches = re.findall(
        rf"({access})\s*,\s*({access})\s*=\s*{re.escape(get_instruction)}\([^;]*,\s*true\s*\)\s*;",
        code,
        re.S,
    )
    if len(fetches) != 1:
        raise ValueError(f"expected one sealed selector-lane fetch, found {len(fetches)}")

    final_code = _code_only(final_path.read_text("latin1"))
    leaked = re.search(
        r"\b(?:Generation(?:Count|Program|Record|Index|Family|Mask|Seal|Guard|Completed)|"
        r"ApplyGenerationRewrite|BeginGenerationSeal|AdvanceGenerationSeal|ComputeGenerationGuard|"
        r"GenerationFieldDigest|PrepareSelectorLane|ValidateSelectorLane|"
        r"Selector(?:Lane|Source|Mask|Value|Recipe|Completed|Seal|Final|RawLane|Target)|"
        r"Materialize(?:Generation(?:Program|Seal|Guard|ProgramSeal)|Selector(?:Lane|Value|Recipe|Completed|Seal|Final))Slot)\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable instruction-generation identifier leaked: {leaked.group(0)}")

    counts = sorted({len(program) for program in programs})
    print(
        "PASS authenticated writable instruction generations: "
        f"records={len(programs)}, generations={counts}, families={sorted(families)}, "
        f"selector-lanes={[0, *sorted(selector_lanes)]}, overlay=invocation-local, "
        "same-PC=replay, guard=state-bound, program=committed"
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
