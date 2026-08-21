#!/usr/bin/env python3
"""Final-output-only structural decompiler for protected Lua call/data flows.

The implementation deliberately consumes only the shipped Lua file. It adapts
to the public payload format, runtime ABI, continuation graph, fused-member
token programs and CALL trampoline rather than relying on compiler logs or the
original source. Its output is an attack measurement, not a secrecy boundary.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import static_attack_baseline as baseline
import verify_v4_payload as payload
from runtime_layout import _arithmetic_value, _code_only, derive_runtime_layout

ARITHMETIC_RAW = r"\(\s*\d+\s*[+\-*]\s*\d+\s*\)"
IDENT = r"[A-Za-z_]\w*"


@dataclass
class DecodedOperand:
    kind: str
    value: Any
    handle: int | None = None


@dataclass
class AttackExecutionState:
    """Attacker-side state key; later phases populate mode/generation dynamics."""

    prototype: tuple[int, ...]
    block_start: int
    predecessors: tuple[int, ...]
    predecessor_modes: tuple[tuple[int, int], ...]
    mode: int
    reachable_modes: tuple[int, ...]
    physical_pc: int
    generation: int
    replay_depth: int
    generation_trace: tuple[str, ...]
    selector_lane: str
    selector_lane_trace: tuple[str, ...]
    column_state: str


@dataclass
class LogicalInstruction:
    state: AttackExecutionState
    prototype: tuple[int, ...]
    physical_pc: int
    member: int
    canonical_id: int
    semantic: str
    a: DecodedOperand
    b: DecodedOperand
    c: DecodedOperand
    argument_mode: str | None = None
    result_mode: str | None = None
    tail: bool = False
    fused: bool = False


@dataclass
class DecompilerReport:
    file: str
    state_model_version: int
    prototypes: int
    physical_instructions: int
    logical_instructions: int
    execution_states: int
    classified_instructions: int
    unknown_instructions: int
    block_predecessor_edges: int
    dialect_modes: list[int]
    mode_transitions: int
    generations: list[int]
    max_generation: int
    replay_transitions: int
    selector_lanes: list[str]
    selector_lane_transitions: int
    fused_programs: int
    fused_members: int
    calls: int
    self_calls: int
    new_tables: int
    table_writes: int
    discarded_calls: int
    returns: int
    recovered_strings: list[str]
    rendered: list[str] = field(default_factory=list)
    instructions: list[dict[str, Any]] = field(default_factory=list)


def _keyword_positions(source: str, start: int = 0):
    for match in re.finditer(r"\b(?:if|then|else|end)\b", source[start:]):
        yield start + match.start(), match.group(0)


def _parse_if(source: str, start: int) -> tuple[str, str, str, int]:
    match = re.match(r"\s*if\b", source[start:])
    if not match:
        raise ValueError("selector branch does not begin with if")
    if_start = start + match.end()
    then_position = next(
        (position for position, word in _keyword_positions(source, if_start) if word == "then"),
        None,
    )
    if then_position is None:
        raise ValueError("selector if is missing then")
    condition = source[if_start:then_position]
    branch_start = then_position + 4
    depth = 1
    else_position = None
    end_position = None
    for position, word in _keyword_positions(source, branch_start):
        if word == "if":
            depth += 1
        elif word == "end":
            depth -= 1
            if depth == 0:
                end_position = position
                break
        elif word == "else" and depth == 1 and else_position is None:
            else_position = position
    if else_position is None or end_position is None:
        raise ValueError("selector if/else/end structure is incomplete")
    return condition, source[branch_start:else_position], source[else_position + 4:end_position], end_position + 3


def _entry_token(branch: str, state: str, u32: str, xor: str, mask: str) -> int | None:
    pattern = (
        rf"{re.escape(state)}\s*=\s*{re.escape(u32)}\(\s*{re.escape(xor)}\(\s*"
        rf"({ARITHMETIC_RAW})\s*,\s*{re.escape(mask)}\s*\)\s*\)\s*;"
    )
    matches = re.findall(pattern, branch)
    return _arithmetic_value(matches[0]) if len(matches) == 1 else None


def _evaluate_condition(condition: str, enum_accessor: str, value: int) -> bool:
    match = re.search(
        rf"{re.escape(enum_accessor)}\s*(==|~=|<=|>)\s*({ARITHMETIC_RAW})",
        condition,
    )
    if not match:
        raise ValueError(f"unsupported opcode selector condition: {condition.strip()}")
    operator, expression = match.groups()
    right = _arithmetic_value(expression)
    return {
        "==": value == right,
        "~=": value != right,
        "<=": value <= right,
        ">": value > right,
    }[operator]


def _evaluate_selector(details: dict[str, Any], canonical: int, mode_token: int | None = None) -> int:
    state = details["dispatch_state"]
    u32 = details["dispatch_u32"]
    xor = details["dispatch_xor"]
    mask = details["dispatch_mask"]
    dialects = details.get("dialect_modes") or []
    if dialects and mode_token is not None:
        dialect = next((item for item in dialects if int(item["token"]) == mode_token), None)
        if dialect is None:
            raise ValueError(f"unknown dialect mode token {mode_token}")
        selector = str(dialect["selector"])
        enum_accessor = details["dialect_enum_accessor"]
        selector_value = (
            canonical * int(dialect["multiplier"]) + int(dialect["addend"])
        ) % int(dialect["modulus"])
    else:
        selector = details["selector"]
        enum_accessor = details["enum_accessor"]
        selector_value = canonical

    def evaluate(branch: str) -> int:
        token = _entry_token(branch, state, u32, xor, mask)
        if token is not None:
            return token
        first_if = re.search(r"\bif\b", branch)
        if not first_if:
            raise ValueError("opcode selector leaf has no entry assignment")
        condition, yes, no, _end = _parse_if(branch, first_if.start())
        return evaluate(yes if _evaluate_condition(condition, enum_accessor, selector_value) else no)

    return evaluate(selector)


def recover_dialect_handler_bodies(
    source: str,
) -> tuple[dict[int, dict[int, str]], dict[str, Any]]:
    layout = derive_runtime_layout(source, include_attack_details=True)
    continuation = layout["continuation"]
    details = continuation["attack_details"]
    transitions = {int(key): int(value) for key, value in details["transitions"].items()}
    terminal_bodies = {int(key): value for key, value in details["terminal_bodies"].items()}
    mode_tokens = [int(item["token"]) for item in details.get("dialect_modes") or []] or [0]
    dialect_handlers: dict[int, dict[int, str]] = {}
    for mode_token in mode_tokens:
        handlers: dict[int, str] = {}
        for canonical in range(int(continuation["opcodes"])):
            token = _evaluate_selector(details, canonical, mode_token)
            seen: set[int] = set()
            while token in transitions:
                if token in seen:
                    raise ValueError("continuation path cycles while mapping handlers")
                seen.add(token)
                token = transitions[token]
            if token not in terminal_bodies:
                raise ValueError(
                    f"canonical opcode {canonical} in dialect {mode_token} has no terminal handler"
                )
            handlers[canonical] = terminal_bodies[token]
        dialect_handlers[mode_token] = handlers
    return dialect_handlers, layout


def recover_handler_bodies(source: str) -> tuple[dict[int, str], dict[str, Any]]:
    dialect_handlers, layout = recover_dialect_handler_bodies(source)
    primary_mode = next(iter(dialect_handlers))
    return dialect_handlers[primary_mode], layout


def _decoded_columns(
    info: payload.PayloadInfo,
    prototype: payload.Prototype,
    block: payload.Block,
    offset: int,
) -> dict[int, bytes]:
    pc = block.start_pc + offset
    columns: dict[int, bytes] = {}
    for role, (_frame, start, end) in block.record_column_spans[offset].items():
        columns[role] = payload.decode_prototype_column(
            info.body[start:end], prototype, block, role, pc
        )
    return columns


def _operand_mask16(pc: int, k1: int, k2: int, k3: int, slot: int) -> int:
    return baseline.opcode_mask(pc + slot * 257, k2, k3, k1)


def _operand_mask32(pc: int, k1: int, k2: int, k3: int, slot: int) -> int:
    return _operand_mask16(pc, k1, k2, k3, slot) | (
        _operand_mask16(pc, k1, k2, k3, slot + 4) << 16
    )


def _block_mask32(block: payload.Block, prototype: payload.Prototype, pc: int, slot: int) -> int:
    return payload.block_field_mask(block.entry_state, pc, slot, prototype) | (
        payload.block_field_mask(block.entry_state, pc, slot + 4, prototype) << 16
    )


def _resolve_operand(
    info: payload.PayloadInfo,
    prototype: payload.Prototype,
    block: payload.Block,
    descriptor: int,
    bit: int,
    value: int,
) -> DecodedOperand:
    if descriptor & (bit << 3):
        capsule = block.capsules.get(value)
        if capsule is None:
            raise ValueError(f"constant handle {value} is absent from block {block.start_pc}")
        kind, decoded = baseline.decode_constant(info, prototype, capsule)
        return DecodedOperand(kind, decoded, value)
    return DecodedOperand("register", value)


def decode_instruction_members(
    info: payload.PayloadInfo,
    prototype: payload.Prototype,
    block: payload.Block,
    offset: int,
    final_a: int | None = None,
) -> list[tuple[int, int, int, int, int]]:
    """Return `(descriptor, A, B, C, member_index)` for one physical record."""
    columns = _decoded_columns(info, prototype, block, offset)
    pc = block.start_pc + offset
    descriptor = columns[0][0] ^ (
        payload.block_field_mask(block.entry_state, pc, 7, prototype) & 0xFF
    )
    if descriptor & 1:
        data = int.from_bytes(columns[3], "little")
        return [(descriptor, 0, data, 0, 0)]
    plain_descriptor = descriptor - (128 if descriptor >= 128 else 0)
    fused = plain_descriptor >= 64
    head_descriptor = plain_descriptor - (64 if fused else 0)
    descriptors = [head_descriptor]
    if fused:
        fused_count = columns[0][1]
        descriptors.extend(columns[0][2:2 + fused_count])

    a_cursor = b_cursor = c_cursor = 0
    members: list[tuple[int, int, int, int, int]] = []
    for member_index, member_descriptor in enumerate(descriptors):
        instruction_type = (member_descriptor >> 1) & 3
        a_raw = columns[2][a_cursor:a_cursor + 2]
        a_cursor += 2
        if member_index == 0:
            a = int.from_bytes(a_raw, "little") ^ _operand_mask16(
                pc, prototype.k1, prototype.k2, prototype.k3, 1
            ) ^ payload.block_field_mask(block.entry_state, pc, 1, prototype)
        else:
            a = int.from_bytes(a_raw, "little")
        if member_index == 0 and final_a is not None:
            a = final_a
        b = c = 0
        if instruction_type == 0:
            b_raw = columns[3][b_cursor:b_cursor + 2]
            c_raw = columns[4][c_cursor:c_cursor + 2]
            b_cursor += 2
            c_cursor += 2
            b = int.from_bytes(b_raw, "little")
            c = int.from_bytes(c_raw, "little")
            if member_index == 0:
                b ^= _operand_mask16(pc, prototype.k1, prototype.k2, prototype.k3, 2)
                b ^= payload.block_field_mask(block.entry_state, pc, 2, prototype)
                c ^= _operand_mask16(pc, prototype.k1, prototype.k2, prototype.k3, 3)
                c ^= payload.block_field_mask(block.entry_state, pc, 3, prototype)
        else:
            b_raw = columns[3][b_cursor:b_cursor + 4]
            b_cursor += 4
            b = int.from_bytes(b_raw, "little")
            if member_index == 0:
                b ^= _operand_mask32(pc, prototype.k1, prototype.k2, prototype.k3, 2)
                b ^= _block_mask32(block, prototype, pc, 2)
            if instruction_type in (2, 3):
                b -= 1 << 16
            if instruction_type == 3:
                c_raw = columns[4][c_cursor:c_cursor + 2]
                c_cursor += 2
                c = int.from_bytes(c_raw, "little")
                if member_index == 0:
                    c ^= _operand_mask16(pc, prototype.k1, prototype.k2, prototype.k3, 3)
                    c ^= payload.block_field_mask(block.entry_state, pc, 3, prototype)
        members.append((member_descriptor, a, b, c, member_index))
    return members


def _normalize_arithmetic(source: str) -> str:
    return re.sub(ARITHMETIC_RAW, lambda match: str(_arithmetic_value(match.group(0))), source)


def _function_segments(source: str, name: str | None = None) -> list[tuple[str, list[str], str]]:
    declarations = list(re.finditer(
        rf"local\s+function\s+({IDENT})\s*\(([^)]*)\)", source
    ))
    output: list[tuple[str, list[str], str]] = []
    for index, declaration in enumerate(declarations):
        function_name = declaration.group(1)
        if name is not None and function_name != name:
            continue
        end = declarations[index + 1].start() if index + 1 < len(declarations) else len(source)
        params = [item.strip() for item in declaration.group(2).split(",") if item.strip()]
        output.append((function_name, params, source[declaration.end():end]))
    return output


def _token_branches(body: str, state: str) -> dict[int, str]:
    headers = list(re.finditer(
        rf"(?:if|elseif)\s+{re.escape(state)}\s*==\s*(\d+)\s*then",
        body,
    ))
    return {
        int(header.group(1)): body[
            header.end():headers[index + 1].start() if index + 1 < len(headers) else len(body)
        ]
        for index, header in enumerate(headers)
    }


def _call_function_name(handlers: dict[int, str], inst: str, top: str) -> str:
    counts: dict[str, int] = {}
    pattern = re.compile(
        rf"\b({IDENT})\s*\(\s*\d+\s*,\s*{re.escape(inst)}\s*,\s*{re.escape(top)}\s*\)"
    )
    for body in handlers.values():
        for match in pattern.finditer(_normalize_arithmetic(body)):
            counts[match.group(1)] = counts.get(match.group(1), 0) + 1
    if not counts:
        raise ValueError("could not identify the shared CALL trampoline from terminal handlers")
    return max(counts, key=counts.get)


def recover_call_modes(
    source: str,
    handlers: dict[int, str],
    layout: dict[str, Any],
) -> tuple[str, dict[int, dict[str, Any]]]:
    details = layout["continuation"]["attack_details"]
    roles = details["role_accessors"]
    call_name = _call_function_name(handlers, roles["Inst"], roles["Top"])
    candidates = []
    for _name, params, body in _function_segments(source, call_name):
        normalized = _normalize_arithmetic(body)
        if len(params) == 3 and "while true do" in normalized:
            mode_comparisons = len(re.findall(rf"(?:if|elseif)\s+{re.escape(params[0])}\s*==\s*\d+\s*then", normalized))
            if mode_comparisons >= 19:
                candidates.append((params, normalized))
    if len(candidates) != 1:
        raise ValueError(f"expected one shared CALL state machine, found {len(candidates)}")
    params, body = candidates[0]
    mode_name, instruction_name, top_name = params
    state_match = re.search(
        rf"local\s+({IDENT})\s*;\s*if\s+{re.escape(mode_name)}\s*==",
        body,
    )
    if not state_match:
        raise ValueError("CALL mode-to-state map was not found")
    state = state_match.group(1)
    loop_at = body.find("while true do")
    mode_region = body[:loop_at]
    mode_states = {
        int(match.group(1)): int(match.group(2))
        for match in re.finditer(
            rf"(?:if|elseif)\s+{re.escape(mode_name)}\s*==\s*(\d+)\s*then\s*"
            rf"{re.escape(state)}\s*=\s*(\d+)\s*;",
            mode_region,
        )
    }
    if len(mode_states) != 19:
        raise ValueError(f"CALL mode map is incomplete: {len(mode_states)}/19")
    branches = _token_branches(body[loop_at:], state)

    raw_plans: dict[int, dict[str, Any]] = {}
    argument_function = None
    result_function = None
    for mode_token, initial_state in mode_states.items():
        current = initial_state
        path: list[str] = []
        seen: set[int] = set()
        while current:
            if current in seen or current not in branches:
                raise ValueError("CALL phase-token path is cyclic or incomplete")
            seen.add(current)
            phase = branches[current]
            path.append(phase)
            transitions = re.findall(rf"{re.escape(state)}\s*=\s*(\d+)\s*;", phase)
            if transitions:
                current = int(transitions[-1])
                continue
            current = 0
        if len(path) not in (4, 5):
            raise ValueError(f"CALL mode has an invalid phase width: {len(path)}")
        argument_call = re.search(
            rf"({IDENT})\s*\(\s*(\d+)\s*,\s*{IDENT}\s*,\s*{re.escape(instruction_name)}\s*,\s*{re.escape(top_name)}\s*\)",
            path[2],
        )
        if not argument_call:
            raise ValueError("CALL argument-acquisition phase was not recovered")
        if argument_function is not None and argument_function != argument_call.group(1):
            raise ValueError("CALL modes use inconsistent argument fragments")
        argument_function = argument_call.group(1)
        tail = len(path) == 4
        result_token = None
        if not tail:
            result_call = re.search(rf"return\s+({IDENT})\s*\(\s*(\d+)\s*,", path[4])
            if not result_call:
                raise ValueError("CALL result-forwarding phase was not recovered")
            if result_function is not None and result_function != result_call.group(1):
                raise ValueError("CALL modes use inconsistent result fragments")
            result_function = result_call.group(1)
            result_token = int(result_call.group(2))
        raw_plans[mode_token] = {
            "argument_token": int(argument_call.group(2)),
            "result_token": result_token,
            "tail": tail,
            "phase_width": len(path),
        }

    if argument_function is None or result_function is None:
        raise ValueError("CALL argument/result helper names were not recovered")
    argument_segments = [
        (params, _normalize_arithmetic(body))
        for _name, params, body in _function_segments(source, argument_function)
        if len(params) == 4
    ]
    if not argument_segments:
        raise ValueError("CALL argument helper definition was not found")
    argument_params, argument_body = max(
        argument_segments,
        key=lambda item: (
            int(bool(re.search(rf"return\s+{re.escape(item[0][1])}\s*;", item[1]))),
            len(re.findall(rf"{re.escape(item[0][1])}\s*\[", item[1])),
            len(re.findall(rf"(?:if|elseif)\s+{re.escape(item[0][0])}\s*==", item[1])),
        ),
    )
    argument_branches = _token_branches(argument_body, argument_params[0])
    argument_modes: dict[int, str] = {}
    for token, branch in argument_branches.items():
        if re.search(rf"\b{re.escape(argument_params[3])}\b", branch):
            mode = "top"
        elif re.search(rf"\b{re.escape(argument_params[2])}\s*\[", branch):
            mode = "fixed"
        elif re.search(r"\+\s*1\s*;", branch):
            mode = "single"
        else:
            mode = "none"
        argument_modes[token] = mode
    if set(argument_modes.values()) != {"top", "fixed", "single", "none"}:
        raise ValueError(f"CALL argument token semantics are incomplete: {argument_modes}")

    result_segments = [
        (params, _normalize_arithmetic(body))
        for _name, params, body in _function_segments(source, result_function)
        if len(params) == 6
    ]
    if not result_segments:
        raise ValueError("CALL result helper definition was not found")
    result_params, result_body = max(
        result_segments,
        key=lambda item: len(re.findall(rf"(?:if|elseif)\s+{re.escape(item[0][0])}\s*==", item[1])),
    )
    result_branches = _token_branches(result_body, result_params[0])
    result_modes: dict[int, str] = {}
    for token, branch in result_branches.items():
        if "for " in branch:
            mode = "variable" if re.search(rf"\b{re.escape(result_params[4])}\b", branch) else "fixed"
        elif re.search(rf"\b{re.escape(result_params[3])}\s*\[\s*1\s*\]", branch):
            mode = "single"
        else:
            mode = "discard"
        result_modes[token] = mode
    if set(result_modes.values()) != {"variable", "fixed", "single", "discard"}:
        raise ValueError(f"CALL result token semantics are incomplete: {result_modes}")

    plans: dict[int, dict[str, Any]] = {}
    for mode_token, plan in raw_plans.items():
        plans[mode_token] = {
            **plan,
            "argument_mode": argument_modes[plan["argument_token"]],
            "result_mode": "tail" if plan["tail"] else result_modes[plan["result_token"]],
        }
    return call_name, plans


def recover_fragment_names(
    source: str,
    handlers: dict[int, str],
    layout: dict[str, Any],
    call_name: str,
) -> dict[str, str]:
    details = layout["continuation"]["attack_details"]
    stack = details["role_accessors"]["Stk"]
    normalized_source = _normalize_arithmetic(source)
    segments = _function_segments(normalized_source)
    stack_reader = stack_writer = environment_reader = None
    for name, params, body in segments:
        compact = re.sub(r"\s+", "", body)
        if len(params) == 2:
            index = re.escape(params[0])
            stack_access = re.escape(stack)
            if re.search(rf"return{stack_access}\[{index}\];", compact) and stack in compact:
                stack_reader = name
            direct = re.findall(rf"return({IDENT}(?:\[\d+\])?)\[{index}\];", compact)
            if direct and direct[0] != stack and "~=nil" in compact:
                environment_reader = name
        elif len(params) == 3:
            index, value = map(re.escape, params[:2])
            stack_access = re.escape(stack)
            if re.search(rf"{stack_access}\[{index}\]={value};", compact) and re.search(
                rf"return{value};", compact
            ):
                stack_writer = name
    if not stack_reader or not stack_writer or not environment_reader:
        raise ValueError(
            f"shared operand fragments were not recovered: stack={stack_reader}, "
            f"write={stack_writer}, environment={environment_reader}"
        )

    inst = details["role_accessors"]["Inst"]
    table_counts: dict[str, int] = {}
    for body in handlers.values():
        normalized = _normalize_arithmetic(body)
        for match in re.finditer(
            rf"\b({IDENT})\s*\(\s*\d+\s*,\s*{re.escape(inst)}\s*\)\s*;",
            normalized,
        ):
            if match.group(1) != call_name:
                table_counts[match.group(1)] = table_counts.get(match.group(1), 0) + 1
    return {
        "call": call_name,
        "table": max(table_counts, key=table_counts.get) if table_counts else "",
        "stack_read": stack_reader,
        "stack_write": stack_writer,
        "environment_read": environment_reader,
    }


def expand_fused_handler(body: str, inst: str) -> list[tuple[str, int]]:
    normalized = _normalize_arithmetic(body)
    prefix = re.search(
        rf"local\s+({IDENT})\s*=\s*{re.escape(inst)}\s*\[\s*5\s*\]\s*;\s*"
        rf"(?:do\s+)?local\s+({IDENT})\s*=\s*{re.escape(inst)}\s*;",
        normalized,
    )
    if not prefix:
        return []
    operands, head = prefix.groups()
    stack_match = re.search(rf"local\s+({IDENT})\s*=\s*{IDENT}\s*\(\s*\{{\}}\s*,\s*\{{\s*__index", normalized)
    if not stack_match:
        raise ValueError("fused stack proxy was not recovered")
    fused_stack = stack_match.group(1)
    machine = re.search(
        rf"local\s+({IDENT})\s*=\s*(\d+)\s*;\s*(?:do\s+)?local\s+({IDENT})\s*=\s*0\s*;\s*"
        rf"(?:do\s+)?while\s+\1\s*~=\s*0\s+do",
        normalized,
    )
    if not machine:
        raise ValueError("fused member-token state machine was not recovered")
    state, initial, step = machine.group(1), int(machine.group(2)), machine.group(3)
    branches = _token_branches(normalized[machine.end():], state)
    current = initial
    members: list[tuple[str, int]] = []
    seen: set[int] = set()
    pending_slot: int | None = None
    while current:
        if current in seen or current not in branches:
            raise ValueError("fused member-token path is cyclic or incomplete")
        seen.add(current)
        branch = branches[current]
        assignment = re.search(
            rf"{re.escape(inst)}\s*=\s*(?P<source>{re.escape(head)}|"
            rf"{re.escape(operands)}\s*\[\s*(?P<slot>\d+)\s*\])\s*;",
            branch,
        )
        finish = re.search(
            rf"{re.escape(step)}\s*=\s*{re.escape(step)}\s*\+\s*1\s*;\s*"
            rf"{re.escape(state)}\s*=\s*(\d+)\s*;",
            branch,
        )
        if not finish:
            raise ValueError("fused member phase has no bounded transition")
        if assignment:
            slot = int(assignment.group("slot")) if assignment.group("slot") else 0
            semantic = branch[assignment.end():finish.start()]
            if semantic.strip():
                # Compatibility with the previous one-state member program.
                members.append((f"__FUSED_STACK__={fused_stack};" + semantic, slot))
            else:
                if pending_slot is not None:
                    raise ValueError("fused member selected two operand slots before execution")
                pending_slot = slot
        else:
            if pending_slot is None:
                raise ValueError("fused execute phase has no preceding operand selection")
            semantic = branch[:finish.start()]
            members.append((f"__FUSED_STACK__={fused_stack};" + semantic, pending_slot))
            pending_slot = None
        current = int(finish.group(1))
    if pending_slot is not None:
        raise ValueError("fused member program ended after selection without execution")
    return members


def _call_token(body: str, function_name: str, inst: str, top: str) -> int | None:
    normalized = _normalize_arithmetic(body)
    match = re.search(
        rf"\b{re.escape(function_name)}\s*\(\s*(\d+)\s*,\s*{re.escape(inst)}\s*,\s*{re.escape(top)}\s*\)",
        normalized,
    )
    return int(match.group(1)) if match else None


def classify_semantic(
    body: str,
    layout: dict[str, Any],
    fragments: dict[str, str],
    call_modes: dict[int, dict[str, Any]],
) -> dict[str, Any]:
    roles = layout["continuation"]["attack_details"]["role_accessors"]
    inst, top, stack = roles["Inst"], roles["Top"], roles["Stk"]
    normalized = _normalize_arithmetic(body)
    compact = normalized
    call_token = _call_token(normalized, fragments["call"], inst, top)
    if call_token is not None:
        if call_token not in call_modes:
            raise ValueError(f"CALL handler uses unknown mode token {call_token}")
        return {"semantic": "TAILCALL" if call_modes[call_token]["tail"] else "CALL", **call_modes[call_token]}
    table_match = re.search(
        rf"\b{re.escape(fragments['table'])}\s*\(\s*(\d+)\s*,\s*{re.escape(inst)}\s*\)",
        normalized,
    ) if fragments["table"] else None
    if table_match:
        return {"semantic": "SETTABLE", "table_mode_token": int(table_match.group(1))}

    inst_compact = re.escape(inst)
    read = re.escape(fragments["stack_read"])
    write = re.escape(fragments["stack_write"])
    env_read = re.escape(fragments["environment_read"])
    fused_match = re.match(r"__FUSED_STACK__=([A-Za-z_]\w*);", normalized)
    fused_stack = fused_match.group(1) if fused_match else None
    if fused_match:
        normalized = normalized[fused_match.end():]
        compact = normalized

    if re.search(rf"\b{env_read}\s*\(\s*{inst_compact}\[3\]", compact):
        return {"semantic": "GETGLOBAL"}
    if "return" in compact and not re.search(r"function\s*\(", compact):
        return {"semantic": "RETURN"}
    if "__index=function" in compact or (
        re.search(r",\s*nil\s*,", compact)
        and re.search(rf"{inst_compact}\s*\[\s*3\s*\]", compact)
        and re.search(rf"\b{write}\s*\(", compact)
    ):
        return {"semantic": "CLOSURE"}
    table_local = re.search(rf"local\s+({IDENT})\s*=\s*\{{\}}\s*;", compact)
    if (
        table_local and (
            re.search(rf"\b{write}\s*\([^;]*,\s*{re.escape(table_local.group(1))}\s*,", compact)
            or (fused_stack and re.search(rf"{re.escape(fused_stack)}\s*\[[^]]+\]\s*=\s*\{{\}}", compact))
        )
    ) or (
        "{}" in compact
        and re.search(rf"{inst_compact}\s*\[\s*2\s*\]", compact)
        and "__index" not in compact
    ):
        return {"semantic": "NEWTABLE"}
    if re.search(rf"{inst_compact}\[3\]~=0", compact):
        return {"semantic": "LOADBOOL"}

    storage = re.escape(fused_stack) if fused_stack else None
    self_shape = (
        re.search(rf"{inst_compact}\[2\].*?\+1", compact)
        and re.search(rf"\[{inst_compact}\[4\]\]", compact)
        and (re.search(rf"\b{read}\s*\(\s*{inst_compact}\[3\]", compact)
             or (storage and re.search(rf"{storage}\[{inst_compact}\[3\]\]", compact)))
    )
    if self_shape:
        return {"semantic": "SELF"}

    gettable_shape = (
        re.search(rf"\b{read}\s*\(\s*{inst_compact}\[3\]", compact)
        or (storage and re.search(rf"{storage}\[{inst_compact}\[3\]\]", compact))
    ) and re.search(rf"\[{inst_compact}\[4\]\]", compact)
    if gettable_shape:
        return {"semantic": "GETTABLE"}

    move_shape = (
        re.search(rf"\b{read}\s*\(\s*{inst_compact}\[3\]", compact)
        or (storage and re.search(rf"{storage}\[{inst_compact}\[3\]\]", compact))
    ) and inst + "[4]" not in normalized
    if move_shape:
        return {"semantic": "MOVE"}

    writes_a = (
        re.search(rf"\b{write}\s*\(\s*{inst_compact}\[2\]", compact)
        or (storage and re.search(rf"{storage}\[{inst_compact}\[2\]\]", compact))
    )
    if writes_a and re.search(rf"{inst_compact}\[3\]", compact):
        return {"semantic": "LOADK"}
    if (
        re.search(rf"{inst_compact}\s*\[\s*2\s*\]", compact)
        and re.search(rf"{inst_compact}\s*\[\s*3\s*\]", compact)
        and not re.search(rf"\b(?:{read}|{env_read})\s*\(", compact)
        and not re.search(rf"{inst_compact}\s*\[\s*4\s*\]", compact)
    ):
        return {"semantic": "LOADK"}
    if "setmetatable" in compact.lower() or "__index" in compact:
        return {"semantic": "CLOSURE"}
    return {"semantic": "UNKNOWN"}


def classify_handlers(
    handlers: dict[int, str],
    layout: dict[str, Any],
    fragments: dict[str, str],
    call_modes: dict[int, dict[str, Any]],
) -> tuple[dict[int, list[dict[str, Any]]], int]:
    inst = layout["continuation"]["attack_details"]["role_accessors"]["Inst"]
    result: dict[int, list[dict[str, Any]]] = {}
    fused_programs = 0
    for canonical, body in handlers.items():
        members = expand_fused_handler(body, inst)
        if members:
            fused_programs += 1
            result[canonical] = []
            for member, operand_slot in members:
                semantic = classify_semantic(member, layout, fragments, call_modes)
                semantic["operand_slot"] = operand_slot
                result[canonical].append(semantic)
        else:
            semantic = classify_semantic(body, layout, fragments, call_modes)
            semantic["operand_slot"] = 0
            result[canonical] = [semantic]
    return result, fused_programs


@dataclass
class _TableValue:
    name: str
    fields: dict[Any, Any] = field(default_factory=dict)


@dataclass
class _MethodTarget:
    receiver: Any
    key: Any


def _literal(value: Any) -> str:
    if value is None:
        return "nil"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _render_value(value: Any, expand_table: bool = False) -> str:
    if isinstance(value, _TableValue):
        if not expand_table:
            return value.name
        fields = []
        for key, member in value.fields.items():
            key_text = key if isinstance(key, str) and re.fullmatch(IDENT, key) else f"[{_literal(key)}]"
            fields.append(f"{key_text}={_render_value(member, True)}")
        return "{" + ", ".join(fields) + "}"
    if isinstance(value, _MethodTarget):
        return f"{_render_value(value.receiver)}[{_literal(value.key)}]"
    return str(value)


def _operand_value(operand: DecodedOperand, registers: dict[int, Any]) -> Any:
    if operand.kind == "register":
        return registers.get(int(operand.value), f"r{operand.value}")
    return _literal(operand.value)


def _prototype_predecessors(prototype: payload.Prototype) -> dict[int, tuple[int, ...]]:
    predecessors: dict[int, set[int]] = {block.start_pc: set() for block in prototype.blocks}
    for source in prototype.blocks:
        for successor_start, _wrapped_state, _wrapped_chunk_state, _wrapped_mode in source.successors:
            predecessors.setdefault(successor_start, set()).add(source.start_pc)
    return {start: tuple(sorted(sources)) for start, sources in predecessors.items()}


def _prototype_modes(
    prototype: payload.Prototype,
) -> dict[int, tuple[tuple[int, ...], tuple[tuple[int, int], ...]]]:
    incoming: dict[int, list[tuple[int, int]]] = {
        block.start_pc: [] for block in prototype.blocks
    }
    for source in prototype.blocks:
        for destination, mode in source.successor_modes.items():
            incoming.setdefault(destination, []).append((source.start_pc, mode))
    result: dict[int, tuple[tuple[int, ...], tuple[tuple[int, int], ...]]] = {}
    for block in prototype.blocks:
        predecessor_modes = tuple(sorted(incoming.get(block.start_pc, [])))
        modes = {mode for _predecessor, mode in predecessor_modes}
        if block.start_pc == 1:
            modes.add(prototype.initial_mode or 0)
        if not modes:
            modes.update(block.accepted_modes)
        if modes != set(block.accepted_modes):
            raise ValueError(
                f"block {block.start_pc} reachable modes disagree with authenticated manifest"
            )
        result[block.start_pc] = (tuple(sorted(modes)), predecessor_modes)
    return result


def _column_state_fingerprint(
    info: payload.PayloadInfo,
    prototype: payload.Prototype,
    block: payload.Block,
    offset: int,
) -> str:
    columns = _decoded_columns(info, prototype, block, offset)
    material = bytearray()
    for role in sorted(columns):
        material.extend(role.to_bytes(1, "little"))
        material.extend(len(columns[role]).to_bytes(4, "little"))
        material.extend(columns[role])
    return hashlib.sha256(material).hexdigest()[:16]


SELECTOR_LANE_NAMES = {
    0: "opcode-carrier",
    1: "descriptor-digest",
    2: "supplemental-operands",
    3: "mode-synthetic",
}


def _selector_lane_trace(generation_trace: list[list[int]], mode: int) -> tuple[str, ...]:
    if len(generation_trace) <= 1:
        return ("canonical-opcode" if mode == 0 else f"dialect-affine:{mode}",)
    lanes = [SELECTOR_LANE_NAMES[0]]
    for values in generation_trace[1:]:
        raw_lane = int(values[2])
        effective_lane = 1 + ((raw_lane - 1 + mode % 3) % 3)
        lanes.append(SELECTOR_LANE_NAMES[effective_lane])
    return tuple(lanes)


def recover_logical_instructions(
    info: payload.PayloadInfo,
    handlers: dict[int, str],
    dialect_classifications: dict[int, dict[int, list[dict[str, Any]]]],
    primary_mode: int,
) -> list[LogicalInstruction]:
    instructions: list[LogicalInstruction] = []
    virtual_count = len(handlers)
    for proto_path, prototype in baseline.prototypes(info.root):
        predecessors = _prototype_predecessors(prototype)
        block_modes = _prototype_modes(prototype)
        opcode_rows = {
            row["pc"]: row
            for row in baseline.decode_opcodes(info, prototype, proto_path, virtual_count)
            if not row["data_word"]
        }
        for block in sorted(prototype.blocks, key=lambda item: item.start_pc):
            for offset in range(block.count):
                pc = block.start_pc + offset
                if block.descriptors[offset] & 1:
                    continue
                opcode_row = opcode_rows[pc]
                canonical = int(opcode_row["canonical_id"])
                generation_trace = opcode_row.get("generation_trace") or []
                final_a = int(generation_trace[-1][1]) if generation_trace else None
                column_state = _column_state_fingerprint(info, prototype, block, offset)
                generation_fingerprints = tuple(
                    hashlib.sha256(
                        f"{column_state}:".encode("ascii")
                        + ":".join(map(str, values)).encode("ascii")
                    ).hexdigest()[:16]
                    for values in generation_trace
                )
                members = decode_instruction_members(info, prototype, block, offset, final_a)
                reachable_modes, predecessor_modes = block_modes[block.start_pc]
                available_modes = tuple(
                    mode for mode in reachable_modes if mode in dialect_classifications
                )
                if not available_modes:
                    available_modes = (primary_mode,)
                selector_lane_trace = _selector_lane_trace(generation_trace, available_modes[0])
                alternatives = [
                    dialect_classifications[mode][canonical] for mode in available_modes
                ]
                widths = {len(items) for items in alternatives}
                if len(widths) != 1:
                    raise ValueError(f"dialect handler widths disagree at {proto_path}:{pc}")
                semantics: list[dict[str, Any]] = []
                for member_index in range(next(iter(widths))):
                    candidates = [items[member_index] for items in alternatives]
                    known = {item["semantic"] for item in candidates if item["semantic"] != "UNKNOWN"}
                    if len(known) > 1:
                        raise ValueError(
                            f"dialect classifier found conflicting semantics at {proto_path}:{pc}.{member_index}: {known}"
                        )
                    selected = next(
                        (item for item in candidates if item["semantic"] != "UNKNOWN"), candidates[0]
                    )
                    semantics.append(selected)
                if len(members) != len(semantics):
                    raise ValueError(
                        f"fused handler width mismatch at {proto_path}:{pc}: "
                        f"{len(semantics)} != {len(members)}"
                    )
                physical_members = {member: (descriptor, a, b, c) for descriptor, a, b, c, member in members}
                for semantic_index, semantic in enumerate(semantics):
                    operand_slot = int(semantic.get("operand_slot", semantic_index))
                    if operand_slot not in physical_members:
                        raise ValueError(
                            f"fused semantic member {semantic_index} selects absent physical slot {operand_slot}"
                        )
                    descriptor, a, b, c = physical_members[operand_slot]
                    operands = (
                        _resolve_operand(info, prototype, block, descriptor, 1, a),
                        _resolve_operand(info, prototype, block, descriptor, 2, b),
                        _resolve_operand(info, prototype, block, descriptor, 4, c),
                    )
                    instructions.append(LogicalInstruction(
                        state=AttackExecutionState(
                            prototype=proto_path,
                            block_start=block.start_pc,
                            predecessors=predecessors.get(block.start_pc, ()),
                            predecessor_modes=predecessor_modes,
                            mode=available_modes[0],
                            reachable_modes=available_modes,
                            physical_pc=pc,
                            generation=int(opcode_row.get("generation_count", 0)),
                            replay_depth=int(opcode_row.get("generation_count", 0)),
                            generation_trace=generation_fingerprints or (column_state,),
                            selector_lane=selector_lane_trace[-1],
                            selector_lane_trace=selector_lane_trace,
                            column_state=column_state,
                        ),
                        prototype=proto_path,
                        physical_pc=pc,
                        member=semantic_index,
                        canonical_id=canonical,
                        semantic=semantic["semantic"],
                        a=operands[0], b=operands[1], c=operands[2],
                        argument_mode=semantic.get("argument_mode"),
                        result_mode=semantic.get("result_mode"),
                        tail=bool(semantic.get("tail")),
                        fused=len(members) > 1,
                    ))
    return instructions


def render_dataflow(instructions: list[LogicalInstruction]) -> tuple[list[str], dict[str, int]]:
    rendered: list[str] = []
    counts = {"calls": 0, "self_calls": 0, "new_tables": 0, "table_writes": 0,
              "discarded_calls": 0, "returns": 0}
    grouped: dict[tuple[int, ...], list[LogicalInstruction]] = {}
    for instruction in instructions:
        grouped.setdefault(instruction.prototype, []).append(instruction)
    for prototype, members in grouped.items():
        registers: dict[int, Any] = {}
        top: int | None = None
        for instruction in members:
            semantic = instruction.semantic
            a = int(instruction.a.value) if instruction.a.kind == "register" else instruction.a.value
            if semantic == "GETGLOBAL":
                key = _operand_value(instruction.b, registers)
                key_plain = instruction.b.value if instruction.b.kind != "register" else key
                registers[a] = f"_ENV.{key_plain}" if isinstance(key_plain, str) and re.fullmatch(IDENT, key_plain) else f"_ENV[{key}]"
            elif semantic == "LOADK":
                registers[a] = _operand_value(instruction.b, registers)
            elif semantic == "LOADBOOL":
                registers[a] = "true" if int(instruction.b.value) != 0 else "false"
            elif semantic == "MOVE":
                registers[a] = _operand_value(instruction.b, registers)
            elif semantic == "CLOSURE":
                registers[a] = f"closure<{instruction.b.value}>"
            elif semantic == "NEWTABLE":
                registers[a] = _TableValue(f"table@{'.'.join(map(str, prototype)) or 'root'}:{instruction.physical_pc}")
                counts["new_tables"] += 1
            elif semantic == "SETTABLE":
                target = registers.get(a, f"r{a}")
                key_value = _operand_value(instruction.b, registers)
                value = _operand_value(instruction.c, registers)
                raw_key = instruction.b.value if instruction.b.kind != "register" else key_value
                if isinstance(raw_key, (_TableValue, _MethodTarget)):
                    raw_key = _render_value(raw_key)
                if isinstance(target, _TableValue):
                    target.fields[raw_key] = value
                rendered.append(
                    f"{prototype}:{instruction.physical_pc}.{instruction.member} SETTABLE "
                    f"{_render_value(target)}[{_literal(raw_key)}]={_render_value(value, True)}"
                )
                counts["table_writes"] += 1
            elif semantic == "GETTABLE":
                target = _operand_value(instruction.b, registers)
                key = _operand_value(instruction.c, registers)
                registers[a] = f"{_render_value(target)}[{key}]"
            elif semantic == "SELF":
                receiver = _operand_value(instruction.b, registers)
                key = instruction.c.value if instruction.c.kind != "register" else _operand_value(instruction.c, registers)
                registers[a] = _MethodTarget(receiver, key)
                registers[a + 1] = receiver
                counts["self_calls"] += 1
            elif semantic in ("CALL", "TAILCALL"):
                argument_mode = instruction.argument_mode
                if argument_mode == "none":
                    argument_registers: list[int] = []
                elif argument_mode == "single":
                    argument_registers = [a + 1]
                elif argument_mode == "fixed":
                    argument_registers = list(range(a + 1, int(instruction.b.value) + 1))
                else:
                    argument_registers = list(range(a + 1, (top if top is not None else a) + 1))
                arguments = [registers.get(index, f"r{index}") for index in argument_registers]
                callee = registers.get(a, f"r{a}")
                if isinstance(callee, _MethodTarget) and arguments and arguments[0] is callee.receiver:
                    call_arguments = arguments[1:]
                    call_text = (
                        f"{_render_value(callee.receiver)}:{callee.key}("
                        + ", ".join(_render_value(value, True) for value in call_arguments) + ")"
                    )
                else:
                    call_text = _render_value(callee) + "(" + ", ".join(
                        _render_value(value, True) for value in arguments
                    ) + ")"
                rendered.append(
                    f"{prototype}:{instruction.physical_pc}.{instruction.member} "
                    f"{semantic} args={argument_mode}:{len(arguments) if argument_mode != 'top' or top is not None else 'top'} "
                    f"results={instruction.result_mode} {call_text}"
                )
                counts["calls"] += 1
                if instruction.result_mode == "discard":
                    counts["discarded_calls"] += 1
                elif instruction.result_mode == "single":
                    registers[a] = call_text
                elif instruction.result_mode == "fixed":
                    last = int(instruction.c.value)
                    registers[a] = call_text
                    for index in range(a + 1, last + 1):
                        registers[index] = f"result#{index - a + 1}<{call_text}>"
                elif instruction.result_mode == "variable":
                    registers[a] = call_text
                    top = a
            elif semantic == "RETURN":
                counts["returns"] += 1
                rendered.append(f"{prototype}:{instruction.physical_pc}.{instruction.member} RETURN")
    return rendered, counts


def analyze_decompiler(path: Path) -> DecompilerReport:
    info = payload.parse_and_verify(path)
    dialect_handlers, layout = recover_dialect_handler_bodies(info.source)
    primary_mode = next(iter(dialect_handlers))
    handlers = dialect_handlers[primary_mode]
    code = _code_only(info.source)
    call_name, call_modes = recover_call_modes(code, handlers, layout)
    fragments = recover_fragment_names(code, handlers, layout, call_name)
    dialect_classifications: dict[int, dict[int, list[dict[str, Any]]]] = {}
    fused_programs = 0
    for mode_token, mode_handlers in dialect_handlers.items():
        mode_classifications, mode_fused = classify_handlers(
            mode_handlers, layout, fragments, call_modes
        )
        dialect_classifications[mode_token] = mode_classifications
        fused_programs = max(fused_programs, mode_fused)
    instructions = recover_logical_instructions(
        info, handlers, dialect_classifications, primary_mode
    )
    rendered, counts = render_dataflow(instructions)
    recovered_string_set: set[str] = set()
    for _prototype_path, prototype in baseline.prototypes(info.root):
        for capsule in prototype.capsules:
            kind, value = baseline.decode_constant(info, prototype, capsule)
            if kind == "string" and isinstance(value, str):
                recovered_string_set.add(value)
    recovered_strings = sorted(recovered_string_set)

    unique_states: dict[tuple[Any, ...], AttackExecutionState] = {}
    recovered_modes: set[int] = set()
    recovered_selector_lanes: set[str] = set()
    recovered_generations: set[int] = set()
    replay_transitions = 0
    selector_lane_transitions = 0
    replay_bases: set[tuple[tuple[int, ...], int, int]] = set()
    mode_edges: set[tuple[tuple[int, ...], int, int, int]] = set()
    for instruction in instructions:
        state = instruction.state
        recovered_modes.update(state.reachable_modes)
        for predecessor, target_mode in state.predecessor_modes:
            if target_mode != 0:
                mode_edges.add((state.prototype, predecessor, state.block_start, target_mode))
        recovered_selector_lanes.update(state.selector_lane_trace)
        for mode in state.reachable_modes:
            for generation, generation_state in enumerate(state.generation_trace):
                recovered_generations.add(generation)
                selector_lane = state.selector_lane_trace[min(generation, len(state.selector_lane_trace) - 1)]
                key = (
                    state.prototype, state.block_start, mode, state.physical_pc,
                    generation, selector_lane, generation_state,
                )
                unique_states.setdefault(key, state)
            replay_base = (state.prototype, state.physical_pc, mode)
            if replay_base not in replay_bases:
                replay_bases.add(replay_base)
                replay_transitions += max(0, len(state.generation_trace) - 1)
                selector_lane_transitions += sum(
                    left != right
                    for left, right in zip(state.selector_lane_trace, state.selector_lane_trace[1:])
                )
    ordered_states = list(unique_states.values())
    mode_transitions = len(mode_edges)
    predecessor_edges = {
        (state.prototype, predecessor, state.block_start)
        for state in ordered_states
        for predecessor in state.predecessors
    }
    classified = sum(instruction.semantic != "UNKNOWN" for instruction in instructions)

    serialized = []
    for instruction in instructions:
        record = asdict(instruction)
        record["prototype"] = list(instruction.prototype)
        serialized.append(record)
    return DecompilerReport(
        file=str(path),
        state_model_version=2,
        prototypes=sum(1 for _ in baseline.prototypes(info.root)),
        physical_instructions=sum(prototype.instruction_count for _, prototype in baseline.prototypes(info.root)),
        logical_instructions=len(instructions),
        execution_states=len(ordered_states),
        classified_instructions=classified,
        unknown_instructions=len(instructions) - classified,
        block_predecessor_edges=len(predecessor_edges),
        dialect_modes=sorted(recovered_modes),
        mode_transitions=mode_transitions,
        generations=sorted(recovered_generations),
        max_generation=max(recovered_generations, default=0),
        replay_transitions=replay_transitions,
        selector_lanes=sorted(recovered_selector_lanes),
        selector_lane_transitions=selector_lane_transitions,
        fused_programs=fused_programs,
        fused_members=sum(instruction.fused for instruction in instructions),
        calls=counts["calls"],
        self_calls=counts["self_calls"],
        new_tables=counts["new_tables"],
        table_writes=counts["table_writes"],
        discarded_calls=counts["discarded_calls"],
        returns=counts["returns"],
        recovered_strings=recovered_strings,
        rendered=rendered,
        instructions=serialized,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--dump-handlers", action="store_true")
    parser.add_argument("--dump-instructions", action="store_true")
    parser.add_argument("--expect-rendered", action="append", default=[])
    parser.add_argument("--require-call-chain", action="store_true")
    args = parser.parse_args()
    try:
        info = payload.parse_and_verify(args.generated)
        handlers, layout = recover_handler_bodies(info.source)
        if args.dump_handlers:
            for canonical, body in handlers.items():
                print(f"\n=== {canonical} ===\n{body[:3000]}")
        if args.dump_instructions:
            virtual_count = len(handlers)
            for proto_path, prototype in baseline.prototypes(info.root):
                opcode_rows = {
                    row["pc"]: row
                    for row in baseline.decode_opcodes(info, prototype, proto_path, virtual_count)
                    if not row["data_word"]
                }
                for block in sorted(prototype.blocks, key=lambda item: item.start_pc):
                    for offset in range(block.count):
                        pc = block.start_pc + offset
                        if block.descriptors[offset] & 1:
                            print(f"{proto_path}:{pc} DATA")
                            continue
                        row = opcode_rows[pc]
                        generation_trace = row.get("generation_trace") or []
                        final_a = int(generation_trace[-1][1]) if generation_trace else None
                        members = decode_instruction_members(info, prototype, block, offset, final_a)
                        rendered_members = []
                        for descriptor, a, b, c, member in members:
                            operands = (
                                _resolve_operand(info, prototype, block, descriptor, 1, a),
                                _resolve_operand(info, prototype, block, descriptor, 2, b),
                                _resolve_operand(info, prototype, block, descriptor, 4, c),
                            )
                            rendered_members.append(
                                f"m{member}:d={descriptor}:A={operands[0].value!r}:"
                                f"B={operands[1].value!r}:C={operands[2].value!r}"
                            )
                        print(
                            f"{proto_path}:{pc} op={row['canonical_id']} fused={len(members) - 1} "
                            + " ".join(rendered_members)
                        )
        report = analyze_decompiler(args.generated)
        rendered_text = "\n".join(report.rendered)
        missing = [value for value in args.expect_rendered if value not in rendered_text]
        if missing:
            raise ValueError(f"decompiler did not recover requested rendered fragments: {missing}")
        if args.require_call_chain:
            required_strings = {
                "loadstring", "HttpGet", "saveinstance", "NilInstances",
                "IgnoreNonArchivable", "IsolateLocalPlayerCharacter", "TreatUnionsAsParts",
            }
            missing_strings = sorted(required_strings - set(report.recovered_strings))
            if missing_strings:
                raise ValueError(f"decompiler missed call-chain constants: {missing_strings}")
            if report.self_calls < 2 or report.new_tables < 2 or report.table_writes < 6:
                raise ValueError("SELF/table construction coverage was not recovered")
            if report.calls < 10 or report.discarded_calls < 3 or report.returns < 1:
                raise ValueError("CALL/discarded-result/RETURN coverage was not recovered")
            chain_markers = (
                ':HttpGet("https://example.invalid/saveinstance.luau", true)',
                "_ENV.loadstring(",
                ', "saveinstance")',
                "NilInstances=true",
                "IgnoreNonArchivable=false",
                "IsolateLocalPlayerCharacter=true",
                "TreatUnionsAsParts=true",
            )
            absent_markers = [marker for marker in chain_markers if marker not in rendered_text]
            if absent_markers:
                raise ValueError(f"complete loader/options data flow was not recovered: {absent_markers}")
            if report.fused_members < 2 or report.classified_instructions < report.logical_instructions // 2:
                raise ValueError("fused-member expansion/classification coverage is insufficient")
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(
                json.dumps(asdict(report), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(
            "STATIC_DECOMPILER "
            f"physical/logical={report.physical_instructions}/{report.logical_instructions} "
            f"states={report.execution_states} modes={len(report.dialect_modes)} "
            f"generations={len(report.generations)} replay={report.replay_transitions} "
            f"selector-migrations={report.selector_lane_transitions} "
            f"classified={report.classified_instructions} fused={report.fused_programs}/{report.fused_members} "
            f"calls={report.calls} self={report.self_calls} tables={report.new_tables}/{report.table_writes} "
            f"discarded={report.discarded_calls} returns={report.returns}"
        )
    except (OSError, ValueError, IndexError, KeyError, struct.error) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
