#!/usr/bin/env python3
"""Verify P3 mode-dependent, generation-local selector-lane migration."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only
from static_attack_baseline import prototypes
from static_decompiler import analyze_decompiler
from verify_v4_payload import parse_and_verify


LANE_NAMES = {
    "opcode-carrier",
    "descriptor-digest",
    "supplemental-operands",
    "mode-synthetic",
}


def verify(vm_path: Path, final_path: Path) -> None:
    info = parse_and_verify(final_path)
    programs = [
        program
        for _path, prototype in prototypes(info.root)
        for block in prototype.blocks
        for descriptor, program in zip(block.descriptors, block.generation_programs)
        if descriptor & 1 == 0
    ]
    if not programs:
        raise ValueError("fixture has no selector-lane generation programs")
    raw_lanes = {record[2] for program in programs for record in program}
    if raw_lanes != {1, 2, 3}:
        raise ValueError(f"post-rewrite selector lanes are incomplete: {raw_lanes}")
    if any(
        left[2] == right[2]
        for program in programs
        for left, right in zip(program, program[1:])
    ):
        raise ValueError("a physical record reused one selector lane across adjacent generations")
    recipes = [record[3] for program in programs for record in program]
    if any(recipe <= 3 for recipe in recipes) or len(set(recipes)) < max(8, len(recipes) // 2):
        raise ValueError("selector recipe tokens are absent or coupled to lane identifiers")

    report = analyze_decompiler(final_path)
    if set(report.selector_lanes) != LANE_NAMES:
        raise ValueError(f"attacker did not recover all selector-lane families: {report.selector_lanes}")
    if report.selector_lane_transitions < report.physical_instructions:
        raise ValueError("attacker did not replay selector-lane transitions")
    for instruction in report.instructions:
        state = instruction["state"]
        trace = state["selector_lane_trace"]
        if len(trace) != state["replay_depth"] + 1 or trace[0] != "opcode-carrier":
            raise ValueError("generation-0 opcode lane or complete migration trace is absent")
        if any(left == right for left, right in zip(trace, trace[1:])):
            raise ValueError("attacker trace contains a non-migrating same-PC generation")

    source = _code_only(vm_path.read_text("latin1"))
    root = Path(__file__).resolve().parents[1]
    generator = (root / "IronBrew2/Obfuscator/VM Generation/Generator.cs").read_text()
    vm_strings = (root / "IronBrew2/Obfuscator/VM Generation/VMStrings.cs").read_text()
    closure = (root / "IronBrew2/Obfuscator/Opcodes/OpClosure.cs").read_text()
    required = (
        "PrepareSelectorLane", "ResolveDialectMode", "MaterializeSelectorLaneSlot",
        "MaterializeSelectorSealSlot", "SelectorRawLane", "SelectorRecipe",
        "1 + ((SelectorRawLane - 1 + CurrentDialectMode % 3) % 3)",
    )
    for anchor in required:
        if anchor not in generator:
            raise ValueError(f"selector-lane runtime architecture is missing: {anchor}")
    if 'T("InstrPoint") + "," + enumName + ");"' not in generator:
        raise ValueError("dialect resolver does not consume the selector before routing")
    if "if Enum == nil then" in vm_strings:
        raise ValueError("legacy stable opcode-selector fallback remains")
    if "local Mvm,Menum=GetInstruction" not in closure or "if Menum==OP_MOVE" not in closure:
        raise ValueError("closure inline fetch bypasses the migrated selector result")

    final_code = _code_only(final_path.read_text("latin1"))
    leaked = re.search(
        r"\b(?:PrepareSelectorLane|ValidateSelectorLane|Selector(?:Lane|Source|Mask|Value|Recipe|"
        r"Completed|Seal|Final|RawLane|Target)|MaterializeSelector(?:Lane|Value|Recipe|Completed|Seal|Final)Slot)\b",
        source + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable selector-lane identifier leaked: {leaked.group(0)}")

    print(
        "PASS mode-dependent selector-lane migration: "
        f"records={len(programs)}, raw-lanes={sorted(raw_lanes)}, "
        f"recovered={sorted(report.selector_lanes)}, transitions={report.selector_lane_transitions}, "
        "generation0=opcode, recipes=independent, selector-use=seal-validated"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("generated_output", type=Path)
    args = parser.parse_args()
    try:
        verify(args.generated_vm, args.generated_output)
    except (OSError, ValueError, IndexError, KeyError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
