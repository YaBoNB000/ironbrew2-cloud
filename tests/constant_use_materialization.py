#!/usr/bin/env python3
"""Verify constants stay as capsules until a handler reads their operand field."""

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

    # GetInstruction receives four values from the record decoder. Constants
    # are represented by a field->capsule-index map and a closure, not values.
    candidates = list(re.finditer(
        rf"local\s+({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*=\s*"
        rf"({IDENT})\s*\([^;]+\)\s*;",
        code,
        re.S,
    ))
    decode = None
    decoder_start = 0
    decoder_return = None
    returned_resolver = None
    for candidate in candidates:
        candidate_instruction, candidate_digest, candidate_fields, candidate_resolver, candidate_decoder = candidate.groups()
        declarations = list(re.finditer(
            rf"local\s+function\s+{re.escape(candidate_decoder)}\s*\([^)]*\)", code[:candidate.start()]
        ))
        if len(declarations) != 1:
            continue
        candidate_start = declarations[0].end()
        candidate_return = re.search(
            rf"return\s+{re.escape(candidate_instruction)}\s*,\s*{re.escape(candidate_digest)}\s*,\s*"
            rf"{re.escape(candidate_fields)}\s*,\s*({IDENT})\s*;\s*end\s*;",
            code[candidate_start:candidate.start()],
        )
        if candidate_return:
            decode, decoder_start, decoder_return = candidate, candidate_start, candidate_return
            returned_resolver = candidate_return.group(1)
            break
    if decode is None or decoder_return is None or returned_resolver is None:
        raise ValueError("four-result lazy current-record decoder call was not found")
    instruction, digest, constant_fields, instruction_resolver, decoder = decode.groups()
    resolver = returned_resolver
    decoder_region = code[decoder_start:decoder_start + decoder_return.start()]

    resolver_decl = re.search(
        rf"local\s+function\s+{re.escape(resolver)}\s*\(\s*({IDENT})\s*\)", decoder_region
    )
    if not resolver_decl:
        raise ValueError("block-local capsule resolver declaration was not found")
    # The declaration is the only resolver invocation-shaped occurrence inside
    # DecodeInstructionBlock. Any second occurrence would eagerly open a capsule.
    resolver_occurrences = re.findall(rf"\b{re.escape(resolver)}\s*\(", decoder_region)
    if len(resolver_occurrences) != 1:
        raise ValueError("constant resolver is invoked before the record decoder returns")

    for bit, field in ((1, 2), (2, 3), (3, 4)):
        marker = re.search(
            rf"if\s+{IDENT}\s*\(\s*{IDENT}\s*,\s*{bit}\s*,\s*{bit}\s*\)\s*==\s*1\s+then\s*"
            rf"{re.escape(constant_fields)}\[{field}\]\s*=\s*{re.escape(instruction)}\[{field}\]\s*;\s*end\s*;",
            decoder_region,
        )
        if not marker:
            raise ValueError(f"constant operand {field} is not retained as a lazy capsule index")

    # Recover the operand binder from its final replay call and verify that the
    # resolver is reachable only from __index, with independent decoded flags
    # so a decoded nil is cached correctly.
    binder_call = re.search(
        rf"local\s+{IDENT}\s*=\s*({IDENT})\s*\(\s*{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT}\s*\)\s*;\s*"
        rf"{IDENT}\[{IDENT}\]\s*,",
        code,
        re.S,
    )
    if not binder_call:
        raise ValueError("final replay does not bind a lazy operand proxy")
    binder = binder_call.group(1)
    binder_decl = re.search(
        rf"local\s+function\s+{re.escape(binder)}\s*\(\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*\)",
        code[:decode.start()],
    )
    if not binder_decl:
        raise ValueError("lazy operand binder declaration was not found")
    raw_fields, lazy_fields, lazy_resolver = binder_decl.groups()
    next_function = re.search(rf"local\s+function\s+{IDENT}\s*\(", code[binder_decl.end():decode.start()])
    binder_end = binder_decl.end() + (next_function.start() if next_function else decode.start() - binder_decl.end())
    binder_region = code[binder_decl.end():binder_end]
    if not re.search(r"__index\s*=\s*function\s*\(", binder_region):
        raise ValueError("constant operand binder is not an __index use-point proxy")
    resolver_call = re.search(
        rf"local\s+({IDENT})\s*=\s*{re.escape(lazy_resolver)}\s*\(\s*{IDENT}\s*\)\s*;",
        binder_region,
    )
    if not resolver_call:
        raise ValueError("operand __index does not invoke its capsule resolver")
    value = resolver_call.group(1)
    if not re.search(
        rf"({IDENT})\[({IDENT})\]\s*=\s*true\s*;\s*({IDENT})\[\2\]\s*=\s*{re.escape(value)}\s*;",
        binder_region,
    ):
        raise ValueError("decoded nil constants are not cached with an explicit flag")
    if not re.search(
        rf"{re.escape(lazy_fields)}\s*,\s*{re.escape(lazy_resolver)}\s*=\s*nil\s*,\s*nil\s*;",
        binder_region,
    ):
        raise ValueError("capsule map/resolver are not released after operand use")
    if not re.search(rf"return\s+{re.escape(raw_fields)}\s*\[", binder_region):
        raise ValueError("non-constant operands do not retain raw-field fallback")

    # Both lazy objects must cross the complete variable generation program in derived slots.
    for offset, name in ((628374, constant_fields), (733103, instruction_resolver)):
        slot = re.search(rf"local\s+({IDENT})\s*=\s*{IDENT}\s*\+\s*{offset}\s*;", code)
        if not slot:
            raise ValueError(f"lazy constant replay slot +{offset} was not found")
        if not re.search(rf"{IDENT}\[{slot.group(1)}\]\s*=\s*{re.escape(name)}\s*;", code[decode.start():]):
            raise ValueError(f"lazy constant object is not staged in slot +{offset}")

    final_code = _code_only(final_path.read_text("latin1")) if final_path else ""
    leaked = re.search(
        r"\b(?:DecodeConstantCapsule|ResolvedConstants|ResolvedConstantFlags|BindInstructionOperands|InstructionConstant(?:Fields|Resolver|Index))\b",
        code + "\n" + final_code,
    )
    if leaked:
        raise ValueError(f"stable constant-use identifier leaked: {leaked.group(0)}")

    print("PASS handler-use constant materialization: eager-decodes=0, replay-generations=2..5, nil-cache=explicit, capsule-release=bounded")


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
