#!/usr/bin/env python3
"""Validate the final-output attacker's extensible VM execution-state model."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from static_decompiler import analyze_decompiler

STATE_FIELDS = {
    "prototype", "block_start", "predecessors", "mode", "physical_pc",
    "generation", "replay_depth", "selector_lane", "column_state",
}


def verify(path: Path, uploaded_loader: bool) -> None:
    report = analyze_decompiler(path)
    if report.state_model_version != 1:
        raise ValueError(f"unexpected attacker state-model version: {report.state_model_version}")
    if report.execution_states < 1 or report.execution_states > report.logical_instructions:
        raise ValueError("execution-state cardinality is outside the logical instruction range")
    if report.dialect_modes != [0] or report.mode_transitions != 0:
        raise ValueError(f"pre-P1 VM unexpectedly reports dialect dynamics: {report.dialect_modes}")
    if report.generations != [0] or report.max_generation != 0 or report.replay_transitions != 0:
        raise ValueError("pre-P2 VM unexpectedly reports mutable instruction generations")
    if report.selector_lanes != ["canonical-opcode"]:
        raise ValueError(f"pre-P3 selector-lane baseline changed: {report.selector_lanes}")
    if report.unknown_instructions != report.logical_instructions - report.classified_instructions:
        raise ValueError("UNKNOWN instructions were hidden or guessed as classified semantics")

    predecessor_edges = set()
    for instruction in report.instructions:
        state = instruction.get("state")
        if not isinstance(state, dict) or set(state) != STATE_FIELDS:
            raise ValueError(f"instruction is missing a complete attacker state key: {state}")
        if len(state["column_state"]) != 16:
            raise ValueError("column-state fingerprint is absent")
        for predecessor in state["predecessors"]:
            predecessor_edges.add((tuple(state["prototype"]), predecessor, state["block_start"]))
    if len(predecessor_edges) != report.block_predecessor_edges:
        raise ValueError("block predecessor edges disagree with instruction state keys")

    if uploaded_loader:
        rendered = "\n".join(report.rendered)
        markers = (
            "_ENV.getgenv()",
            '["SCRIPT_KEY"]=',
            ':HttpGet("https://luavon.w0n.cn/api/v1/scripts/1/load")',
            "_ENV.loadstring(",
            "results=discard",
            "RETURN",
        )
        missing = [marker for marker in markers if marker not in rendered]
        if missing:
            raise ValueError(f"uploaded loader baseline is no longer completely recovered: {missing}")
        if report.logical_instructions != 11 or report.classified_instructions != 11:
            raise ValueError("uploaded loader logical/classified baseline changed")
        if (report.calls, report.self_calls, report.table_writes,
                report.discarded_calls, report.returns) != (4, 1, 1, 1, 1):
            raise ValueError("uploaded loader semantic counts changed")

    print(
        "PASS attacker execution-state model: "
        f"states={report.execution_states}, predecessors={report.block_predecessor_edges}, "
        f"modes={report.dialect_modes}, generations={report.generations}, "
        f"selector-lanes={report.selector_lanes}, unknown={report.unknown_instructions}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("--uploaded-loader", action="store_true")
    args = parser.parse_args()
    try:
        verify(args.generated, args.uploaded_loader)
    except (OSError, ValueError, IndexError, KeyError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
