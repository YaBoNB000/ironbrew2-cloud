#!/usr/bin/env python3
"""Verify invocation-local instruction materialization and PC replay wiring."""

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

    # Recover ten private overlay slots: PC, opcode/A/B/C, replay stage, the
    # lazy constant-field map/resolver, IR-fusion operands and fresh-table flag. Neither lazy
    # constant object may be dropped before all four replay passes complete.
    slots = re.search(
        rf"local\s+({IDENT})\s*=\s*32\s*\+\s*\(\(.*?\)\s*%\s*104729\s*\)\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*104729\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*209458\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*314187\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*418916\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*523645\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*628374\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*733103\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*837832\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*942561\s*;",
        code,
        re.S,
    )
    if not slots:
        raise ValueError("prototype-derived field/lazy-constant materializer slots were not found")
    index_slot, opcode_slot, a_slot, b_slot, c_slot, stage_slot, constant_slot, resolver_slot, fused_slot, fresh_slot = slots.groups()

    pending = re.search(
        rf"if\s+({IDENT})\s+and\s+({IDENT})\s+and\s+\2\[{re.escape(index_slot)}\]\s*==\s*({IDENT})\s+then"
        rf".*?if\s+({IDENT})\s*<\s*4\s+then\s*\2\[{re.escape(stage_slot)}\]\s*=\s*\4\s*\+\s*1\s*;"
        rf".*?\2\[{re.escape(index_slot)}\]\s*,\s*\2\[{re.escape(opcode_slot)}\]\s*,\s*\2\[{re.escape(a_slot)}\]\s*,\s*"
        rf"\2\[{re.escape(b_slot)}\]\s*,\s*\2\[{re.escape(c_slot)}\]\s*,\s*\2\[{re.escape(stage_slot)}\]\s*,\s*"
        rf"\2\[{re.escape(constant_slot)}\]\s*,\s*\2\[{re.escape(resolver_slot)}\]\s*,\s*"
        rf"\2\[{re.escape(fused_slot)}\]\s*,\s*\2\[{re.escape(fresh_slot)}\]\s*=\s*"
        rf"nil\s*,\s*nil\s*,\s*nil\s*,\s*nil\s*,\s*nil\s*,\s*nil\s*,\s*nil\s*,\s*nil\s*,\s*nil\s*,\s*nil\s*;"
        rf".*?return\s+({IDENT})\s*;",
        code,
        re.S,
    )
    if not pending:
        raise ValueError("four-stage field/lazy-constant materialization path was not found")

    # The final replay must wrap the four raw fields in a lazy operand proxy
    # before clearing both resolver slots from FlowCache.
    flow_cache = pending.group(2)
    binder_call = re.search(
        rf"local\s+({IDENT})\s*=\s*{re.escape(flow_cache)}\[{re.escape(constant_slot)}\]\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*{re.escape(flow_cache)}\[{re.escape(resolver_slot)}\]\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*({IDENT})\s*\(\s*{IDENT}\s*,\s*\1\s*,\s*\2\s*\)\s*;",
        pending.group(0),
        re.S,
    )
    if not binder_call:
        raise ValueError("lazy operand proxy was not bound at the final replay")

    # Every selected VM loop must request a top-level materializer and accept a
    # canonical Enum override before falling back to the prototype opcode bank.
    access = rf"{IDENT}(?:\[\d+\])?"
    top_level_fetches = re.findall(
        rf"({access})\s*,\s*({access})\s*=\s*({IDENT})\([^;]*,\s*true\s*\)\s*;\s*"
        rf"if\s+\2\s*==\s*nil\s+then",
        code,
        re.S,
    )
    if len(top_level_fetches) != 1:
        raise ValueError(f"expected one selected top-level materializer fetch, found {len(top_level_fetches)}")

    mode = re.search(
        rf"local\s+function\s+({IDENT})\s*\([^)]*,\s*({IDENT})\s*\)\s*"
        rf"local\s+({IDENT})\s*=\s*\(.*?\+\s*\2\s*\)\s*%\s*4\s*;\s*"
        rf"if\s+\3\s*==\s*0\s+then\s+return\s+(\d+)\s*;\s*"
        rf"elseif\s+\3\s*==\s*1\s+then\s+return\s+(\d+)\s*;\s*"
        rf"elseif\s+\3\s*==\s*2\s+then\s+return\s+(\d+)\s*;\s*"
        rf"else\s+return\s+(\d+)\s*;\s*end\s*;\s*end\s*;",
        code,
        re.S,
    )
    if not mode:
        raise ValueError("four-mode staged materializer selector was not found")
    opcode_ids = tuple(map(int, mode.groups()[3:]))
    if len(set(opcode_ids)) != 4:
        raise ValueError(f"materializer modes do not use four distinct opcode leaves: {opcode_ids}")

    # Name randomization must cover the new runtime roles in both unminified and
    # production output. Comments are removed before this identifier check.
    final_code = _code_only(final_path.read_text("latin1")) if final_path else ""
    leaked = re.search(
        r"\b(?:AllowMaterializer|SelectMaterializerEnum|BindInstructionOperands|Instruction(?:Fields|ConstantFields|ConstantResolver|DecodedFields|DecodedValues|RemainingConstants|FieldKey|ConstantIndex)|Materialize(?:IndexSlot|OpcodeSlot|ASlot|BSlot|CSlot|StageSlot|ConstantFieldsSlot|ConstantResolverSlot|FusedSlot|FreshTableSlot|Stage|Mode|Enum|Target|Delta)|Materialized(?:Instruction|Fields|ConstantFields|ConstantResolver))\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable materializer identifier leaked: {leaked.group(0)}")

    print(
        "PASS invocation-local materializer replay: "
        f"overlay-slots=derived, stages=4, fields=opcode/A/B/C+lazy-constants+fused-operands+fresh-table, modes=4, opcode-leaves={opcode_ids}"
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
