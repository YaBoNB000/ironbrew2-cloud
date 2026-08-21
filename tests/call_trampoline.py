#!/usr/bin/env python3
"""Verify tokenized CALL/TAILCALL lowering and its randomized shared runtime."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


def verify(
    vm_path: Path,
    final_path: Path | None,
    build_log: Path,
    bytecode_listing: Path | None,
) -> None:
    root = Path(__file__).resolve().parents[1]
    context_source = (root / "IronBrew2/Obfuscator/ObfuscationContext.cs").read_text()
    call_source = (root / "IronBrew2/Obfuscator/Opcodes/OpCall.cs").read_text()
    tail_source = (root / "IronBrew2/Obfuscator/Opcodes/OpTailCall.cs").read_text()
    generator = (root / "IronBrew2/Obfuscator/VM Generation/Generator.cs").read_text()

    if "CallModeTokens" not in context_source or "enum CallMode" not in context_source:
        raise ValueError("build-random CALL mode-token ABI is missing")
    call_modes = re.findall(r"CallTrampoline\.Emit\(context,\s*CallMode\.([A-Za-z]+)\)", call_source)
    tail_modes = re.findall(r"CallMode\.(Tail[A-Za-z]+)", tail_source)
    if len(call_modes) != 16 or len(set(call_modes)) != 16:
        raise ValueError(f"expected 16 distinct CALL B/C modes, found {call_modes}")
    if len(tail_modes) != 3 or len(set(tail_modes)) != 3:
        raise ValueError(f"expected three distinct TAILCALL B modes, found {tail_modes}")
    forbidden_leaf_shapes = ("Stk[", "Unpack(", "_R(", "GuardValidateCallTarget")
    if any(shape in call_source + tail_source for shape in forbidden_leaf_shapes):
        raise ValueError("a terminal CALL/TAILCALL opcode still embeds a complete invocation dataflow")

    required_runtime = (
        "HandlerCallAcquireTarget",
        "HandlerCallValidateTarget",
        "HandlerCallAcquireArguments",
        "HandlerCallInvoke",
        "HandlerCallTailInvoke",
        "HandlerCallForward",
        "callPhaseOrder.Shuffle(r)",
        "ApplyRuntimeSlotPermutation(vm, idents[\"HandlerCallFrame\"]",
        "GuardValidateCallTarget(HandlerCallTarget)",
    )
    missing = [item for item in required_runtime if item not in generator]
    if missing:
        raise ValueError(f"CALL trampoline runtime is incomplete: {missing}")
    if "NeedsDynamicCallGuard" in generator or "GuardValidateCallTarget(Stk[Inst[OP_A]])" in generator:
        raise ValueError("legacy validate-write-reread-call handler shape is still present")
    if "return HandlerCallTailInvoke(" not in generator:
        raise ValueError("TAILCALL does not reach its invoke dispatcher through direct return")
    if "return HandlerCallTarget(Unpack(" not in generator:
        raise ValueError("TAILCALL leaves do not directly return the saved callee")
    if "return _R(HandlerCallTarget(Unpack(" not in generator:
        raise ValueError("ordinary CALL leaves do not capture exact multiple-result counts")

    match = re.search(
        r"Call trampolines: modes=(\d+); phases=(\d+); frame=([1-4](?:,[1-4]){3}); signature=([0-9a-f]{8})\.",
        build_log.read_text(),
    )
    if not match:
        raise ValueError("build log is missing the CALL trampoline profile")
    modes, phases = map(int, match.group(1, 2))
    frame = tuple(map(int, match.group(3).split(",")))
    if modes != 19 or phases != 92:
        raise ValueError(f"unexpected CALL trampoline coverage: modes={modes}, phases={phases}")
    if sorted(frame) != [1, 2, 3, 4]:
        raise ValueError(f"CALL frame is not a four-slot permutation: {frame}")

    generated = vm_path.read_text("latin1")
    if final_path:
        generated += "\n" + final_path.read_text("latin1")
    stable = re.search(
        r"\b(?:HandlerCall(?:AcquireTarget|ValidateTarget|AcquireArguments|Invoke[A-D]?|TailInvoke[A-D]?|Forward)?|HandlerCall(?:Mode|Instruction|Top|Frame|State|Steps|Results|ResultCount|Target))\b",
        generated,
    )
    if stable:
        raise ValueError(f"stable CALL trampoline identifier leaked: {stable.group(0)}")

    if bytecode_listing:
        listing = bytecode_listing.read_text()

        def width(value: int) -> str:
            if value == 0:
                return "top"
            if value == 1:
                return "none"
            if value == 2:
                return "single"
            return "fixed"

        call_pairs = {
            (width(int(match.group(1))), width(int(match.group(2))))
            for match in re.finditer(r"\bCALL\s+\d+\s+(\d+)\s+(\d+)", listing)
        }
        expected_pairs = {
            (argument, result)
            for argument in ("top", "none", "single", "fixed")
            for result in ("top", "none", "single", "fixed")
        }
        missing_pairs = sorted(expected_pairs - call_pairs)
        if missing_pairs:
            raise ValueError(f"CALL semantic fixture misses B/C families: {missing_pairs}")
        tail_arguments = {
            width(int(match.group(1)))
            for match in re.finditer(r"\bTAILCALL\s+\d+\s+(\d+)\s+\d+", listing)
        }
        if tail_arguments != {"top", "none", "fixed"}:
            raise ValueError(f"TAILCALL fixture argument coverage is incomplete: {tail_arguments}")
        if not re.search(r"\bSELF\s+", listing):
            raise ValueError("CALL semantic fixture does not contain SELF")

    print(
        "PASS tokenized CALL trampoline: "
        f"modes={modes}, phases={phases}, frame={frame}, signature={match.group(4)}, "
        "target/validation/arguments/invoke/forward split, direct tail leaves"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("generated_output", type=Path, nargs="?")
    parser.add_argument("--build-log", type=Path, required=True)
    parser.add_argument("--bytecode-listing", type=Path)
    args = parser.parse_args()
    try:
        verify(args.generated_vm, args.generated_output, args.build_log, args.bytecode_listing)
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
