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

    # Recover the two private overlay slots. They are prototype-key-derived and
    # deliberately outside the seven permuted FlowCache state roles.
    slots = re.search(
        rf"local\s+({IDENT})\s*=\s*32\s*\+\s*\(\(.*?\)\s*%\s*104729\s*\)\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*\1\s*\+\s*104729\s*;",
        code,
        re.S,
    )
    if not slots:
        raise ValueError("prototype-derived materializer overlay slots were not found")
    index_slot, instruction_slot = slots.groups()

    pending = re.search(
        rf"if\s+({IDENT})\s+and\s+({IDENT})\s+and\s+\2\[{re.escape(index_slot)}\]\s*==\s*({IDENT})\s+then"
        rf".*?\2\[{re.escape(index_slot)}\]\s*,\s*\2\[{re.escape(instruction_slot)}\]\s*=\s*nil\s*,\s*nil\s*;"
        rf".*?return\s+({IDENT})\s*;",
        code,
        re.S,
    )
    if not pending:
        raise ValueError("materialized instruction consume/replay path was not found")

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
        rf"local\s+({IDENT})\s*=\s*\(.*?\)\s*%\s*4\s*;\s*"
        rf"if\s+\1\s*==\s*0\s+then\s+({IDENT})\s*=\s*(\d+)\s*;\s*"
        rf"elseif\s+\1\s*==\s*1\s+then\s+\2\s*=\s*(\d+)\s*;\s*"
        rf"elseif\s+\1\s*==\s*2\s+then\s+\2\s*=\s*(\d+)\s*;\s*"
        rf"else\s+\2\s*=\s*(\d+)\s*;\s*end\s*;",
        code,
        re.S,
    )
    if not mode:
        raise ValueError("four-mode prototype materializer selector was not found")
    opcode_ids = tuple(map(int, mode.groups()[2:]))
    if len(set(opcode_ids)) != 4:
        raise ValueError(f"materializer modes do not use four distinct opcode leaves: {opcode_ids}")

    # Name randomization must cover the new runtime roles in both unminified and
    # production output. Comments are removed before this identifier check.
    final_code = _code_only(final_path.read_text("latin1")) if final_path else ""
    leaked = re.search(
        r"\b(?:AllowMaterializer|Materialize(?:IndexSlot|InstructionSlot|Mode|Enum|Target|Delta)|MaterializedInstruction)\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable materializer identifier leaked: {leaked.group(0)}")

    print(
        "PASS invocation-local materializer replay: "
        f"overlay-slots=derived, modes=4, opcode-leaves={opcode_ids}"
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
