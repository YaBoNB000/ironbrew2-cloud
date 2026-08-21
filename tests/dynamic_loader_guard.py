#!/usr/bin/env python3
"""Verify per-CALL dynamic-loader validation is present and randomized."""

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
    validator = re.search(
        rf"({IDENT})\s*=\s*function\s*\(\s*({IDENT})\s*\)\s*"
        rf"if\s+not\s+({IDENT})\s*\(\s*\2\s*,\s*({IDENT})\s*\)\s*then\s+return\s+\2\s*;\s*end\s*;"
        rf"(?P<body>.*?)return\s+\2\s*;\s*end\s*;",
        code,
        re.S,
    )
    if not validator:
        raise ValueError("per-call dynamic-loader validator was not found")
    validator_name, callee, _, saved_loader = validator.group(1, 2, 3, 4)
    body = validator.group("body")
    if not re.search(rf"{IDENT}\s*\(.*?\)\s*;.*?{re.escape(saved_loader)}", body, re.S):
        raise ValueError("current environment loader identity is not re-read")
    if not re.search(
        r"\(\s*114\s*\).*?\(\s*101\s*\).*?\(\s*116\s*\).*?\(\s*117\s*\).*?"
        r"\(\s*114\s*\).*?\(\s*110\s*\).*?\(\s*32\s*\)",
        body,
        re.S,
    ):
        raise ValueError("dynamic compile challenge is not assembled from character codes")
    # The validator itself is assigned as `name = function(...)`, so every
    # `name(...)` occurrence is a live call (there is no declaration call to
    # subtract). The trampoline intentionally shares exactly this use.
    if len(re.findall(rf"\b{re.escape(validator_name)}\s*\(", code)) < 1:
        raise ValueError("no live CALL trampoline uses the dynamic-loader validator")
    if len(re.findall(r"return\s+[^;]*\(\s*\)\s*;", body)) < 1:
        raise ValueError("compiled loader challenge is not executed")

    root = Path(__file__).resolve().parents[1]
    generator = (root / "IronBrew2/Obfuscator/VM Generation/Generator.cs").read_text()
    if ("HandlerCallValidateTarget" not in generator
            or "GuardValidateCallTarget(HandlerCallTarget)" not in generator):
        raise ValueError("shared CALL trampoline does not validate its saved local target")
    if "GuardValidateCallTarget(Stk[Inst[OP_A]])" in generator:
        raise ValueError("legacy validate-write-reread-call handler shape is still present")

    final_code = _code_only(final_path.read_text("latin1")) if final_path else ""
    leaked = re.search(
        r"\bGuard(?:ValidateCallTarget|Dynamic(?:Calls|Challenge|Source|CompileOK|Loaded|RunOK|Result|ConstantsOK|Constants)|CurrentLoader)\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable dynamic-loader guard identifier leaked: {leaked.group(0)}")

    print("PASS per-call loadstring guard: identity/provenance/compile/run/constants, saved-target CALL trampoline")


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
