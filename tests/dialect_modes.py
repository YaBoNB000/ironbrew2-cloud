#!/usr/bin/env python3
"""Verify authenticated block/edge-local VM dialect modes and handler recipes."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only, derive_runtime_layout
from static_attack_baseline import prototypes
from static_decompiler import analyze_decompiler, recover_dialect_handler_bodies
from verify_v4_payload import parse_and_verify

PROFILE = re.compile(
    r"Dialect lattice: modes=(\d+); used=(\d+); paths=(\d+); signature=([0-9a-f]{8})\."
)


def verify(generated: Path, vm_path: Path, build_log: Path) -> None:
    profile = PROFILE.search(build_log.read_text("utf-8", errors="replace"))
    if not profile:
        raise ValueError("dialect lattice profile was not found")
    mode_count, used_count, path_count = map(int, profile.group(1, 2, 3))
    if not 3 <= mode_count <= 5 or used_count < 3:
        raise ValueError(f"dialect mode coverage is incomplete: {profile.group(0)}")

    source = generated.read_text("latin1")
    layout = derive_runtime_layout(source, include_attack_details=True)
    if layout["continuation"]["dialect_modes"] != mode_count:
        raise ValueError("runtime dialect count disagrees with build profile")
    opcode_count = int(layout["continuation"]["opcodes"])
    if path_count != mode_count * opcode_count:
        raise ValueError("dialect continuation path count is incomplete")
    details = layout["continuation"]["attack_details"]
    runtime_tokens = {int(item["token"]) for item in details["dialect_modes"]}
    if len(runtime_tokens) != mode_count:
        raise ValueError("runtime mode tokens are missing or reused")
    if any(int(item["modulus"]) != opcode_count for item in details["dialect_modes"]):
        raise ValueError("a dialect affine selector has the wrong modulus")

    info = parse_and_verify(generated)
    payload_tokens: set[int] = set()
    distinct_predecessor_target = False
    for _path, prototype in prototypes(info.root):
        payload_tokens.add(prototype.initial_mode)
        incoming: dict[int, list[int]] = {}
        for block in prototype.blocks:
            for destination, mode in block.successor_modes.items():
                payload_tokens.add(mode)
                incoming.setdefault(destination, []).append(mode)
        for block in prototype.blocks:
            expected_modes = set(incoming.get(block.start_pc, []))
            if block.start_pc == 1:
                expected_modes.add(prototype.initial_mode)
            # Unreachable compiler artifacts receive one authenticated fallback
            # mode but never gain a synthetic CFG predecessor.
            if expected_modes and expected_modes != set(block.accepted_modes):
                raise ValueError(
                    f"target block {block.start_pc} accepted-mode manifest disagrees with incoming edges"
                )
        distinct_predecessor_target |= any(
            len(values) >= 2 and len(set(values)) >= 2 for values in incoming.values()
        )
    if not payload_tokens.issubset(runtime_tokens) or len(payload_tokens) < 3:
        raise ValueError("payload entry/edge modes are not live runtime tokens")
    if not distinct_predecessor_target:
        raise ValueError("no target block receives distinct predecessor mode tokens")

    dialect_handlers, _layout = recover_dialect_handler_bodies(source)
    if set(dialect_handlers) != runtime_tokens:
        raise ValueError("final-output attacker did not recover every dialect handler family")
    differing_handlers = 0
    for canonical in range(opcode_count):
        fingerprints = {
            hashlib.sha256(_code_only(handlers[canonical]).encode("latin1")).hexdigest()
            for handlers in dialect_handlers.values()
        }
        differing_handlers += len(fingerprints) > 1
    if differing_handlers < opcode_count // 2:
        raise ValueError("dialect modes reuse too many identical terminal recipes")

    report = analyze_decompiler(generated)
    if set(report.dialect_modes) != payload_tokens:
        raise ValueError("attacker execution states missed a reachable payload mode")
    expected_selector_lanes = {
        "opcode-carrier", "descriptor-digest", "supplemental-operands", "mode-synthetic"
    }
    if (report.mode_transitions < 2 or set(report.selector_lanes) != expected_selector_lanes
            or report.selector_lane_transitions < report.physical_instructions):
        raise ValueError("attacker did not model edge-local modes and P3 selector migrations")

    leaked = re.search(
        r"\b(?:DialectMode(?:Count|Tokens|Slot|Seal|Valid|Key)|CurrentDialectMode|DialectEnum)\b",
        _code_only(source) + "\n" + _code_only(vm_path.read_text("latin1")),
    )
    if leaked:
        raise ValueError(f"stable dialect identifier leaked: {leaked.group(0)}")

    print(
        "PASS authenticated VM dialect lattice: "
        f"modes={mode_count}, used={used_count}, paths={path_count}, "
        f"payload-modes={len(payload_tokens)}, multi-predecessor=distinct, "
        f"variant-handlers={differing_handlers}/{opcode_count}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("--build-log", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.generated, args.generated_vm, args.build_log)
    except (OSError, ValueError, IndexError, KeyError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
