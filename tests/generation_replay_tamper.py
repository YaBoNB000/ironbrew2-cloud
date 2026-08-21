#!/usr/bin/env python3
"""Create test-only skip/duplicate attacks against the generation overlay."""

from __future__ import annotations

import argparse
from pathlib import Path
import re

IDENT = r"[A-Za-z_]\w*"


def instrument(source_path: Path, output_dir: Path) -> None:
    source = source_path.read_text("latin1")
    slots = re.search(
        rf"local\s+({IDENT})\s*=\s*32\s*\+\s*\(\(.*?\)\s*%\s*104729\s*\)\s*;.*?"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*523645\s*;",
        source,
        re.S,
    )
    if not slots:
        raise ValueError("generation stage slot was not found")
    base_slot, stage_slot = slots.groups()
    program_slot_match = re.search(
        rf"local\s+({IDENT})\s*=\s*{re.escape(base_slot)}\s*\+\s*1047290\s*;",
        source,
    )
    program_seal_slot_match = re.search(
        rf"local\s+({IDENT})\s*=\s*{re.escape(base_slot)}\s*\+\s*1361477\s*;",
        source,
    )
    if not program_slot_match or not program_seal_slot_match:
        raise ValueError("generation program/commitment slots were not found")
    program_slot = program_slot_match.group(1)
    program_seal_slot = program_seal_slot_match.group(1)

    initialize = list(re.finditer(
        rf"({IDENT})\[{re.escape(stage_slot)}\]\s*=\s*1\s*;", source
    ))
    if len(initialize) != 1:
        raise ValueError(f"expected one generation-stage initialization, found {len(initialize)}")
    skip = source[:initialize[0].start()] + initialize[0].group(0).replace("= 1", "= 2").replace("=1", "=2") + source[initialize[0].end():]

    increment = list(re.finditer(
        rf"({IDENT})\[{re.escape(stage_slot)}\]\s*=\s*({IDENT})\s*\+\s*1\s*;", source
    ))
    if len(increment) != 1:
        raise ValueError(f"expected one generation-stage increment, found {len(increment)}")
    duplicate_statement = re.sub(r"\s*\+\s*1", "", increment[0].group(0))
    duplicate = source[:increment[0].start()] + duplicate_statement + source[increment[0].end():]

    program_assignment = list(re.finditer(
        rf"({IDENT})\[{re.escape(program_slot)}\]\s*=\s*({IDENT})\s*;",
        source,
    ))
    if len(program_assignment) != 1:
        raise ValueError(
            f"expected one generation-program initialization, found {len(program_assignment)}"
        )
    flow_cache_name = program_assignment[0].group(1)
    program_name = program_assignment[0].group(2)
    commitment_assignment = list(re.finditer(
        rf"{re.escape(flow_cache_name)}\[{re.escape(program_seal_slot)}\]\s*=\s*({IDENT})\s*;",
        source,
    ))
    if len(commitment_assignment) != 1:
        raise ValueError(
            f"expected one generation-program commitment, found {len(commitment_assignment)}"
        )
    mutation_point = commitment_assignment[0].end()
    mask_mutation = (
        f"{program_name}[1][2]=({program_name}[1][2]+1)%4294967296;"
    )
    reorder_mutation = (
        f"{program_name}[1],{program_name}[2]={program_name}[2],{program_name}[1];"
    )
    lane_mutation = (
        f"{program_name}[1][3]={program_name}[1][3]%3+1;"
    )
    recipe_mutation = (
        f"{program_name}[1][4]=({program_name}[1][4]+1)%4294967296;"
    )
    mask = source[:mutation_point] + mask_mutation + source[mutation_point:]
    reorder = source[:mutation_point] + reorder_mutation + source[mutation_point:]
    lane = source[:mutation_point] + lane_mutation + source[mutation_point:]
    recipe = source[:mutation_point] + recipe_mutation + source[mutation_point:]

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "generation-skip.lua").write_text(skip, "latin1")
    (output_dir / "generation-duplicate.lua").write_text(duplicate, "latin1")
    (output_dir / "generation-mask.lua").write_text(mask, "latin1")
    (output_dir / "generation-reorder.lua").write_text(reorder, "latin1")
    (output_dir / "generation-lane.lua").write_text(lane, "latin1")
    (output_dir / "generation-recipe.lua").write_text(recipe, "latin1")
    print("PASS generated test-only generation skip/duplicate/mask/reorder/lane/recipe attacks")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    try:
        instrument(args.generated_vm, args.output_dir)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
