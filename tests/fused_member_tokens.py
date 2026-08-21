#!/usr/bin/env python3
"""Verify IR-fusion members execute through randomized token state machines."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_layout import _code_only

IDENT = r"[A-Za-z_]\w*"
PROFILE = re.compile(r"Fused member tokens: operators=(\d+); members=(\d+); signature=([0-9a-f]{8})\.")


def verify(vm_path: Path, final_path: Path | None, build_log: Path) -> None:
    profile = PROFILE.search(build_log.read_text("utf-8", errors="replace"))
    if not profile:
        raise ValueError("fused member-token profile was not found")
    operators, members, signature = int(profile.group(1)), int(profile.group(2)), profile.group(3)
    if operators < 1 or members < operators * 2 or signature in ("00000000", "811c9dc5"):
        raise ValueError(f"fused member-token profile is degenerate: {profile.group(0)}")

    source = vm_path.read_text("latin1")
    code = _code_only(source)
    machines = list(re.finditer(
        rf"local\s+({IDENT})\s*=\s*(\d+)\s*;\s*(?:do\s+)?local\s+({IDENT})\s*=\s*0\s*;\s*"
        rf"(?:do\s+)?while\s+\1\s*~=\s*0\s+do\s*if\s+\3\s*>\s*(\d+)\s+then.*?end\s*;"
        rf"(?P<body>.*?)else\s+{IDENT}\s*\([^;]+\)\s*;\s*end\s*;\s*end\s*;",
        code,
        re.S,
    ))
    if len(machines) != operators:
        raise ValueError(f"member-token state-machine count mismatch: {len(machines)} != {operators}")
    tokens: list[int] = []
    for machine in machines:
        pc = machine.group(1)
        branches = [int(value) for value in re.findall(
            rf"(?:if|elseif)\s+{re.escape(pc)}\s*==\s*(\d+)\s+then",
            machine.group("body"),
        )]
        expected_width = int(machine.group(4))
        if len(branches) != expected_width or len(set(branches)) != expected_width:
            raise ValueError(f"fusion member branches are incomplete: {branches}/{expected_width}")
        tokens.extend(branches)
    if len(tokens) != members or len(set(tokens)) != members:
        raise ValueError("fused member tokens were reused across handlers")

    root = Path(__file__).resolve().parents[1]
    opcode = (root / "IronBrew2/Obfuscator/Opcodes/OpSuperOperator.cs").read_text()
    for anchor in ("MemberTokens", "MemberBranchOrder", "FusedProgramCounter", "FusedProgramStep"):
        if anchor not in opcode:
            raise ValueError(f"IR fusion token-program architecture is missing: {anchor}")

    final_code = _code_only(final_path.read_text("latin1")) if final_path else ""
    leaked = re.search(
        r"\b(?:FusedHead|FusedProgramCounter|FusedProgramStep|MemberTokens|MemberBranchOrder)\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable fused-member token identifier leaked: {leaked.group(0)}")

    print(
        "PASS fused member tokens: "
        f"operators={operators}, members={members}, unique-tokens={len(set(tokens))}, signature={signature}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("generated_output", type=Path, nargs="?")
    parser.add_argument("--build-log", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args.generated_vm, args.generated_output, args.build_log)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
