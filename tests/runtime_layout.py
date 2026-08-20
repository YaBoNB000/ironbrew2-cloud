#!/usr/bin/env python3
"""Recover and validate a generated VM's build-wide runtime slot ABI."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

from build_domains import extract_build_domains

IDENT = r"[A-Za-z_]\w*"


def _code_only(source: str) -> str:
    """Blank Lua strings/comments while preserving offsets and line breaks."""
    output = list(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, min(end, len(output))):
            if output[position] not in "\r\n":
                output[position] = " "

    def long_bracket(start: int) -> tuple[int, str] | None:
        match = re.match(r"\[(=*)\[", source[start:])
        if not match:
            return None
        return len(match.group(0)), "]" + match.group(1) + "]"

    index = 0
    while index < len(source):
        if source.startswith("--", index):
            bracket = long_bracket(index + 2)
            if bracket:
                opening_length, closing = bracket
                end = source.find(closing, index + 2 + opening_length)
                end = len(source) if end < 0 else end + len(closing)
            else:
                end = source.find("\n", index + 2)
                end = len(source) if end < 0 else end
            blank(index, end)
            index = end
            continue
        bracket = long_bracket(index)
        if bracket:
            opening_length, closing = bracket
            end = source.find(closing, index + opening_length)
            end = len(source) if end < 0 else end + len(closing)
            blank(index, end)
            index = end
            continue
        if source[index] not in "'\"":
            index += 1
            continue
        quote = source[index]
        end = index + 1
        while end < len(source):
            if source[end] == "\\":
                end += 2
                continue
            if source[end] == quote:
                end += 1
                break
            end += 1
        blank(index, end)
        index = end
    return "".join(output)


def _expect(pattern: str, source: str, message: str, flags: int = 0) -> re.Match[str]:
    match = re.search(pattern, source, flags)
    if not match:
        raise ValueError(message)
    return match


def _permutation(mapping: dict[int, int], count: int, name: str) -> None:
    if set(mapping) != set(range(1, count + 1)) or set(mapping.values()) != set(range(1, count + 1)):
        raise ValueError(f"{name} slots are not a complete {count}-slot permutation: {mapping}")
    if all(mapping[index] == index for index in range(1, count + 1)):
        raise ValueError(f"{name} unexpectedly retained the identity layout")


def _arithmetic_value(expression: str) -> int:
    match = re.fullmatch(r"\(\s*(\d+)\s*([+\-*])\s*(\d+)\s*\)", expression)
    if not match:
        raise ValueError(f"unsupported scrambled integer expression: {expression}")
    left, operator, right = int(match.group(1)), match.group(2), int(match.group(3))
    if operator == "+":
        return left + right
    if operator == "-":
        return left - right
    return left * right


def derive_runtime_layout(source: str) -> dict[str, object]:
    if "invalid protected payload" in source:
        raise ValueError("stable protected-payload diagnostic leaked into generated VM")
    domains = extract_build_domains(source)
    source = _code_only(source)

    # Deserialize reads prototype keys before creating a prototype-local proxy.
    # The proxy transparently maps the build-wide numeric ABI used by generated
    # code into a second K1/K2/K3-derived storage permutation.
    init = _expect(
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"local\s+({IDENT})\s*=\s*({IDENT})\(\);\s*"
        rf"local\s+({IDENT})\s*=\s*\5\(\);\s*"
        rf"local\s+({IDENT})\s*=\s*\5\(\);\s*"
        rf"local\s+{IDENT}\s*=\s*{IDENT}\(\);\s*"
        rf"local\s+({IDENT})\s*=\s*{IDENT}\(\s*16\s*,\s*\4\s*,\s*\6\s*,\s*\7\s*,[^;]+\);\s*"
        rf"\8\[(\d+)\]\s*=\s*\1;\s*"
        rf"\8\[(\d+)\]\s*=\s*\2;\s*"
        rf"\8\[(\d+)\]\s*=\s*\3;",
        source,
        "could not recover prototype-local Chunk initialization",
    )
    instrs, functions, lines = init.group(1, 2, 3)
    k1, k2, k3, chunk = init.group(4, 6, 7, 8)
    chunk_map: dict[int, int] = {1: int(init.group(9)), 2: int(init.group(10)), 4: int(init.group(11))}
    key_match = _expect(
        rf"{re.escape(chunk)}\[(\d+)\]\s*,\s*{re.escape(chunk)}\[(\d+)\]\s*,\s*{re.escape(chunk)}\[(\d+)\]"
        rf"\s*=\s*{re.escape(k1)}\s*,\s*{re.escape(k2)}\s*,\s*{re.escape(k3)};",
        source[init.end():],
        "could not recover Chunk key slots",
    )
    chunk_map.update({5: int(key_match.group(1)), 6: int(key_match.group(2)), 7: int(key_match.group(3))})

    # The opcode bank assignment is tied to this build's recovered derivation domain.
    opcode = _expect(
        rf"local\s+({IDENT})\s*=\s*{IDENT}\(\s*(\d+)\s*,[^;]*,\s*"
        rf"{re.escape(str(domains.opcode_permutation))}\);\s*"
        rf"{re.escape(chunk)}\[(\d+)\]\s*=\s*\1;",
        source,
        "could not recover Chunk opcode-bank slot",
    )
    opcode_count = int(opcode.group(2))
    chunk_map[8] = int(opcode.group(3))

    # The prototype-wide constant pool is gone: Chunk[15] stores only the
    # declared constant count before InstrCount/Blocks are initialized.
    capsules = _expect(
        rf"local\s+({IDENT})\s*=\s*0;\s*{re.escape(chunk)}\[(\d+)\]\s*=\s*\1;\s*"
        rf"local\s+{IDENT}\s*=\s*0;\s*local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*local\s+({IDENT})\s*=\s*0;",
        source,
        "could not recover Chunk constant-count/block locals",
    )
    constant_count_name, constant_count_slot, blocks, block_map, block_count = capsules.group(1, 2, 3, 4, 5)
    chunk_map[15] = int(constant_count_slot)
    pair = _expect(
        rf"{re.escape(chunk)}\[(\d+)\]\s*,\s*{re.escape(chunk)}\[(\d+)\]\s*=\s*"
        rf"{re.escape(blocks)}\s*,\s*{re.escape(block_map)};",
        source[capsules.start():],
        "could not recover Chunk Blocks/BlockMap slots",
    )
    chunk_map.update({9: int(pair.group(1)), 10: int(pair.group(2))})

    counts = _expect(
        rf"{re.escape(chunk)}\[(\d+)\]\s*=\s*{re.escape(block_count)};\s*"
        rf"{re.escape(chunk)}\[(\d+)\]\s*=\s*({IDENT})\(\);\s*"
        rf"{re.escape(chunk)}\[(\d+)\]\s*=\s*\3\(\);",
        source[capsules.end():],
        "could not recover Chunk block-count/initial flow/chunk-state slots",
    )
    chunk_map.update({11: int(counts.group(1)), 12: int(counts.group(2)), 16: int(counts.group(4))})

    dispatcher_init = _expect(
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*local\s+{IDENT}\s*=\s*0;\s*"
        rf"local\s+({IDENT})\s*=\s*0;",
        source[capsules.start():],
        "could not recover dispatcher locals",
    )
    dispatcher, initial_route = dispatcher_init.group(1, 2)
    dispatcher_pair = _expect(
        rf"{re.escape(chunk)}\[(\d+)\]\s*,\s*{re.escape(chunk)}\[(\d+)\]\s*=\s*"
        rf"{re.escape(dispatcher)}\s*,\s*{re.escape(initial_route)};",
        source,
        "could not recover Chunk dispatcher slots",
    )
    chunk_map.update({13: int(dispatcher_pair.group(1)), 14: int(dispatcher_pair.group(2))})

    # Params is the sole remaining Chunk semantic after all keyed fields above.
    remaining_old = set(range(1, 17)) - set(chunk_map)
    remaining_new = set(range(1, 17)) - set(chunk_map.values())
    if len(remaining_old) != 1 or len(remaining_new) != 1 or remaining_old != {3}:
        raise ValueError("could not infer the remaining Chunk parameter slot")
    chunk_map[3] = remaining_new.pop()

    # Block is a prototype-local proxy followed by ten build-ABI assignments in
    # semantic order. The proxy applies a second K1/K2/K3-derived permutation.
    block_match = _expect(
        rf"local\s+({IDENT})\s*=\s*{IDENT}\(\s*10\s*,[^;]+\);\s*"
        + "".join(rf"\1\[(\d+)\]\s*=\s*[^;]+;\s*" for _ in range(10))
        + rf"{re.escape(blocks)}\s*\[[^\]]+\]\s*=\s*\1;",
        source,
        "could not recover prototype-local Block constructor",
        re.S,
    )
    block_name = block_match.group(1)
    block_map_slots = {index: int(block_match.group(index + 1)) for index in range(1, 11)}

    # Flow updates CurrentPC, CurrentBlock, EntryState and its authenticated
    # cache in one keyed tuple.
    flow_tuples = list(re.finditer(
        rf"({IDENT})\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*=\s*"
        rf"{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT};",
        source,
    ))
    flow_candidates = [match for match in flow_tuples if match.group(1) != chunk and
                       set(int(match.group(index)) for index in (2, 3, 4, 5)) == set(range(1, 5))]
    if len(flow_candidates) != 1:
        raise ValueError(f"expected one four-role Flow tuple assignment, found {len(flow_candidates)}")
    flow_match = flow_candidates[0]
    flow_name = flow_match.group(1)
    flow_map = {
        1: int(flow_match.group(2)),
        2: int(flow_match.group(3)),
        3: int(flow_match.group(4)),
        4: int(flow_match.group(5)),
    }

    # FlowCache authenticates source block, entry state, chunk state,
    # instruction state/seal, and opcode state/seal as one randomized tuple.
    cache_match = _expect(
        rf"(?:local\s+)?({IDENT})\s*=\s*\{{\}};\s*"
        rf"\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*"
        rf"\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*=\s*"
        rf"{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT};\s*"
        rf"{re.escape(flow_name)}\[[^\]]+\]\s*,\s*{re.escape(flow_name)}\[[^\]]+\]\s*,\s*"
        rf"{re.escape(flow_name)}\[[^\]]+\]\s*,\s*{re.escape(flow_name)}\[{flow_map[4]}\]\s*=\s*"
        rf"{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT}\s*,\s*\1;",
        source,
        "could not recover keyed seven-role FlowCache constructor",
    )
    flow_cache_name = cache_match.group(1)
    flow_cache_map = {index: int(cache_match.group(index + 1)) for index in range(1, 8)}
    cache_roles = _expect(
        rf"=\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*,\s*"
        rf"({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*;",
        cache_match.group(0),
        "could not recover seven FlowCache state roles",
    ).groups()
    # The live Guard chain must consume independently carried instruction,
    # chunk, entry, opcode and opcode-seal roles rather than a single key.
    bind_call = _expect(
        rf"if\s+({IDENT})\s*\(\s*{re.escape(cache_roles[3])}\s*,\s*{re.escape(cache_roles[2])}\s*,\s*"
        rf"{re.escape(cache_roles[1])}\s*,\s*{IDENT}\s*,\s*{re.escape(cache_roles[5])}\s*,\s*"
        rf"{re.escape(cache_roles[6])}\s*\)\s*then",
        source,
        "runtime state roles are not independently bound into the Guard chain",
    )
    guard_bind_name = bind_call.group(1)
    guard_bind = _expect(
        rf"(?:local\s+function\s+{re.escape(guard_bind_name)}\s*\(|"
        rf"{re.escape(guard_bind_name)}\s*=\s*function\s*\()\s*"
        rf"({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*,\s*"
        rf"({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*\)",
        source,
        "runtime Guard binding does not expose six dispersed state inputs",
    )
    if len(set(guard_bind.groups())) != 6:
        raise ValueError("runtime Guard state inputs are not independent locals")

    _permutation(chunk_map, 16, "Chunk")
    _permutation(block_map_slots, 10, "Block")
    _permutation(flow_map, 4, "Flow")
    _permutation(flow_cache_map, 7, "FlowCache")

    # Alias consistency checks cover parser and transition aliases. Opcode-handler
    # behavior is subsequently exercised by the differential suite.
    block_start_slot = block_map_slots[1]
    alias_checks = {
        "SuccessorBlock": rf"local\s+({IDENT})\s*=\s*{re.escape(block_map)}\[[^\]]+\];\s*"
                          rf"if\s+not\s+\1\s+or\s+\1\[{block_start_slot}\]",
        "CurrentBlock": rf"local\s+({IDENT})\s*=\s*{re.escape(flow_name)}\[{flow_map[2]}\];.*?"
                        rf"\1\[{block_map_slots[5]}\]",
        "NextBlock": rf"(?:local\s+{IDENT}\s*=\s*{IDENT}\[{chunk_map[10]}\];\s*)?"
                     rf"local\s+({IDENT})\s*=\s*(?:{IDENT}\[{chunk_map[10]}\]|{IDENT})\s*and\s*"
                     rf"(?:{IDENT}\[{chunk_map[10]}\]|{IDENT})\[[^\]]+\];.*?\1\[{block_map_slots[8]}\]",
    }
    aliases: dict[str, str] = {"Block": block_name}
    for label, pattern in alias_checks.items():
        match = _expect(pattern, source, f"{label} does not use the permuted Block layout", re.S)
        aliases[label] = match.group(1)

    # Recover the invocation-state carrier topology from the Wrap closure. Every
    # supported layout starts the returned closure with two or three randomized
    # frame tables, then routes state roles through numeric frame slots. Names,
    # role partitions, declaration order and slots are all excluded from template
    # classification but retained in the per-build structural fingerprint.
    invocation_pattern = rf"return\s+({IDENT})\s*\(\s*({IDENT})\s*,\s*\{{\s*\}}\s*,"
    invocation_candidates = []
    for candidate in re.finditer(invocation_pattern, source):
        wrap_candidate = candidate.group(1)
        if re.search(rf"local\s+function\s+{re.escape(wrap_candidate)}\s*\(", source[:candidate.start()]):
            invocation_candidates.append(candidate)
    if len(invocation_candidates) != 1:
        raise ValueError(f"could not uniquely recover the generated root invocation: {len(invocation_candidates)}")
    root_invocation = invocation_candidates[0]
    wrap_name, root_name = root_invocation.group(1, 2)
    root_declarations = list(re.finditer(
        rf"local\s+{re.escape(root_name)}\s*=\s*{IDENT}\s*\(\s*\)\s*;",
        source[:root_invocation.start()],
    ))
    if not root_declarations:
        raise ValueError("could not recover the generated root deserialization boundary")
    root_boundary = root_declarations[-1]
    wrap_declaration = _expect(
        rf"local\s+function\s+{re.escape(wrap_name)}\s*\(\s*({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*\)",
        source[:root_boundary.start()],
        "could not recover the VM Wrap closure",
    )
    closure = _expect(
        r"return\s+function\s*\(\s*\.\.\.\s*\)",
        source[wrap_declaration.end():root_boundary.start()],
        "could not recover the VM invocation closure",
    )
    closure_start = wrap_declaration.end() + closure.end()
    wrap_end = root_boundary.start()
    if closure_start >= wrap_end:
        raise ValueError("VM invocation closure crosses the root-deserialization boundary")
    wrap_body = source[closure_start:wrap_end]

    frame_names: list[str] = []
    cursor = 0
    while True:
        declaration = re.match(rf"\s*local\s+({IDENT})\s*=\s*\{{\s*\}}\s*;", wrap_body[cursor:])
        if not declaration:
            break
        frame_names.append(declaration.group(1))
        cursor += declaration.end()
    if len(frame_names) not in {2, 3} or len(frame_names) != len(set(frame_names)):
        raise ValueError(f"expected two or three independent VM state frames, recovered {frame_names}")
    stable_layout = re.search(
        r"\b(?:LayoutFrameA|LayoutFrameB|LayoutFrameC|DualPartitioned|TieredPartitioned|HybridLocals)\b",
        source,
    )
    if stable_layout:
        raise ValueError(f"stable VM layout identifier leaked: {stable_layout.group(0)}")

    frame_slot_orders: list[list[int]] = []
    first_accesses: list[tuple[int, int, int]] = []
    for frame_index, frame_name in enumerate(frame_names):
        accesses = list(re.finditer(rf"\b{re.escape(frame_name)}\s*\[\s*(\d+)\s*\]", wrap_body))
        if not accesses:
            raise ValueError("a declared VM state frame is unused")
        first_by_slot: dict[int, int] = {}
        for access in accesses:
            slot = int(access.group(1))
            first_by_slot.setdefault(slot, access.start())
        frame_size = max(first_by_slot)
        if set(first_by_slot) != set(range(1, frame_size + 1)):
            raise ValueError(f"VM state frame slots are not contiguous: {sorted(first_by_slot)}")
        order = [slot for slot, _position in sorted(first_by_slot.items(), key=lambda item: item[1])]
        if order == list(range(1, frame_size + 1)):
            raise ValueError("VM state frame retained identity role-to-slot ordering")
        frame_slot_orders.append(order)
        for slot, position in first_by_slot.items():
            access_tail = wrap_body[position:]
            if not re.match(rf"{re.escape(frame_name)}\s*\[\s*{slot}\s*\]\s*=", access_tail):
                raise ValueError("a VM state frame is read before its role is initialized")
            first_accesses.append((position, frame_index, slot))

    frame_sizes = [len(order) for order in frame_slot_orders]
    sorted_sizes = sorted(frame_sizes)
    if sorted_sizes == [4, 5]:
        vm_layout_template = "dual-partitioned"
        state_role_order = ["InstrPoint", "Flow", "Top", "Vararg", "Lupvals", "Stk", "Varargsz", "Inst", "Enum"]
        direct_roles: list[str] = []
    elif sorted_sizes == [2, 3, 4]:
        vm_layout_template = "tiered-partitioned"
        state_role_order = ["InstrPoint", "Flow", "Top", "Vararg", "Lupvals", "Stk", "Varargsz", "Inst", "Enum"]
        direct_roles = []
    elif sorted_sizes == [3, 3]:
        vm_layout_template = "hybrid-locals"
        state_role_order = ["InstrPoint", "Flow", "Top", "Stk", "Inst", "Enum"]
        direct_roles = ["Vararg", "Lupvals", "Varargsz"]
    else:
        raise ValueError(f"unsupported VM state frame topology: {frame_sizes}")
    first_accesses.sort()
    if len(first_accesses) != len(state_role_order):
        raise ValueError(
            f"VM layout initialized {len(first_accesses)} framed roles, expected {len(state_role_order)}"
        )
    role_slots = {
        role: {"frame": frame_index + 1, "slot": slot}
        for role, (_position, frame_index, slot) in zip(state_role_order, first_accesses)
    }
    flow_position = role_slots["Flow"]
    flow_accessor = frame_names[flow_position["frame"] - 1] + f"[{flow_position['slot']}]"
    layout_shape_sequence = [f"T:{vm_layout_template}"]
    layout_shape_sequence.extend(
        f"F:{index + 1}:{frame_sizes[index]}:" + ",".join(str(slot) for slot in frame_slot_orders[index])
        for index in range(len(frame_names))
    )
    layout_shape_sequence.extend(
        f"R:{role}:F{placement['frame']}S{placement['slot']}" for role, placement in role_slots.items()
    )
    layout_material = "|".join(layout_shape_sequence)
    vm_layout = {
        "template": vm_layout_template,
        "frames": len(frame_names),
        "frame_sizes": frame_sizes,
        "slot_orders": frame_slot_orders,
        "role_slots": role_slots,
        "direct_roles": direct_roles,
        "fingerprint": hashlib.sha256(layout_material.encode("ascii")).hexdigest()[:16],
        "shape_sequence": layout_shape_sequence,
    }

    # Protected-payload checks must fan out across four randomized native-fault
    # paths rather than repeating one searchable direct error call.
    reject_declaration = re.compile(
        rf"local\s+function\s+({IDENT})\s*\(\s*({IDENT})\s*\)\s*"
        rf"local\s+({IDENT})\s*;\s*return\s*([^;]+);\s*end;"
    )
    reject_paths: dict[str, str] = {}
    expected_fault_shapes = {"void[code]", "void(code)", "code+void", "#void+code"}
    for match in reject_declaration.finditer(source):
        name, code_name, void_name, expression = match.groups()
        normalized = re.sub(r"\s+", "", expression)
        shape = re.sub(rf"\b{re.escape(void_name)}\b", "void", normalized)
        shape = re.sub(rf"\b{re.escape(code_name)}\b", "code", shape)
        if shape in expected_fault_shapes:
            if name in reject_paths:
                raise ValueError("duplicate protected-payload rejection function")
            reject_paths[name] = shape
    if len(reject_paths) != 4 or set(reject_paths.values()) != expected_fault_shapes:
        raise ValueError(f"expected four distinct hidden rejection paths, recovered {reject_paths}")

    arithmetic_raw = r"\(\s*\d+\s*[+\-*]\s*\d+\s*\)"
    for reject_name in reject_paths:
        if not re.search(rf"\b{re.escape(reject_name)}\s*\(\s*{arithmetic_raw}\s*\)", source):
            raise ValueError("a generated protected-payload rejection path is unused")

    # The opcode comparison tree only chooses a masked entry token. A build-local
    # continuation graph then reaches the handler through one of three genuinely
    # different dispatcher CFG templates. Recover names and structure rather than
    # relying on stable implementation identifiers.
    continuation_init = _expect(
        rf"local\s+({IDENT})\s*=\s*({IDENT})\(\s*({IDENT})\([^;]+\)\s*\);\s*"
        rf"local\s+({IDENT})\s*=\s*[^;]+;\s*"
        rf"local\s+({IDENT})\s*,\s*({IDENT})\s*,\s*({IDENT})\s*;\s*"
        rf"local\s+({IDENT})\s*=\s*true;\s*local\s+({IDENT})\s*=\s*0;\s*"
        rf"local\s+({IDENT})\s*;",
        source,
        "could not recover continuation dispatcher locals",
    )
    (dispatch_mask, dispatch_u32, dispatch_xor, dispatch_salt, dispatch_state, dispatch_lane,
     dispatch_step_mask, dispatch_active, dispatch_steps, dispatch_matched) = continuation_init.groups()
    dispatch_names = {
        dispatch_mask, dispatch_u32, dispatch_xor, dispatch_salt, dispatch_state, dispatch_lane,
        dispatch_step_mask, dispatch_active, dispatch_steps, dispatch_matched,
    }
    if len(dispatch_names) != 10:
        raise ValueError("continuation dispatcher locals are not independently randomized")
    stable_dispatch = re.search(
        r"\b(?:DispatchMask|DispatchSalt|DispatchState|DispatchLane|DispatchActive|"
        r"DispatchSteps|DispatchStepMask|DispatchMatched|BitXOR|U32)\b",
        source,
    )
    if stable_dispatch:
        raise ValueError(f"stable continuation identifier leaked: {stable_dispatch.group(0)}")
    if not re.search(rf"{re.escape(flow_accessor)}\s*\[\s*{flow_map[3]}\s*\]", continuation_init.group(0)):
        raise ValueError("continuation entry mask is not bound through the selected VM Flow carrier")

    periodic_calls = list(re.finditer(rf"\b({IDENT})\s*\(\s*false\s*\)\s*;", source))
    if len(periodic_calls) != 1:
        raise ValueError(f"expected one VM-loop periodic guard probe, found {len(periodic_calls)}")
    guard_probe = periodic_calls[0].group(1)
    if periodic_calls[0].start() >= continuation_init.start():
        raise ValueError("periodic guard probe is not executed before continuation decoding")
    if not re.search(
        rf"(?:local\s+function\s+{re.escape(guard_probe)}\s*\(|"
        rf"{re.escape(guard_probe)}\s*=\s*function\s*\()\s*{IDENT}\s*\)",
        source,
    ):
        raise ValueError("periodic guard call does not resolve to the generated guard probe")
    if not re.search(
        rf"(?:\brepeat|\bwhile\s+true\s+do)\s+{re.escape(guard_probe)}\s*\(\s*false\s*\)\s*;",
        source,
    ):
        raise ValueError("periodic guard probe is not fused into the VM execution loop")

    arithmetic_raw = r"\(\s*\d+\s*[+\-*]\s*\d+\s*\)"
    arithmetic = f"({arithmetic_raw})"
    continuation_tail = source[continuation_init.end():]
    loop_candidates: list[tuple[int, str, re.Match[str]]] = []
    while_loop = re.search(
        rf"while\s+{re.escape(dispatch_active)}\s+do\s+(.*?)"
        rf"if\s+not\s+{re.escape(dispatch_matched)}\s+then\s+"
        rf"({IDENT})\(\s*{arithmetic_raw}\s*\);\s*end;\s*end;",
        continuation_tail,
        re.S,
    )
    if while_loop:
        loop_candidates.append((while_loop.start(), "while", while_loop))
    repeat_loop = re.search(
        rf"repeat\s+(.*?)if\s+not\s+{re.escape(dispatch_matched)}\s+then\s+"
        rf"({IDENT})\(\s*{arithmetic_raw}\s*\);\s*end;\s*"
        rf"until\s+not\s+{re.escape(dispatch_active)}\s*;",
        continuation_tail,
        re.S,
    )
    if repeat_loop:
        loop_candidates.append((repeat_loop.start(), "repeat", repeat_loop))
    if not loop_candidates:
        raise ValueError("could not recover a complete continuation dispatcher loop")
    loop_start, loop_kind, continuation_loop = min(loop_candidates, key=lambda item: item[0])
    if continuation_loop.group(2) not in reject_paths:
        raise ValueError("continuation dispatcher does not terminate through a hidden rejection path")
    selector = continuation_tail[:loop_start]
    loop_body = continuation_loop.group(1)

    salt_init = _expect(
        rf"local\s+{re.escape(dispatch_salt)}\s*=\s*\([^;]*\*\s*{arithmetic}\s*\+\s*{arithmetic}"
        rf"\s*\)\s*%\s*4294967296\s*;",
        continuation_init.group(0),
        "continuation salt is not flow-derived 32-bit arithmetic",
    )
    salt_factor = _arithmetic_value(salt_init.group(1))
    if salt_factor == 0 or salt_factor % 2 == 0:
        raise ValueError("continuation step salt factor must be odd and non-zero")

    state_entry = (
        rf"{re.escape(dispatch_state)}\s*=\s*{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
        rf"{arithmetic}\s*,\s*{re.escape(dispatch_mask)}\s*\)\s*\);"
    )
    lane_entry = rf"{re.escape(dispatch_lane)}\s*=\s*{arithmetic}\s*;"
    entries: list[tuple[int, int, int]] = []
    for match in re.finditer(state_entry + rf"\s*" + lane_entry, selector):
        entries.append((match.start(), _arithmetic_value(match.group(1)), _arithmetic_value(match.group(2))))
    for match in re.finditer(lane_entry + rf"\s*" + state_entry, selector):
        entries.append((match.start(), _arithmetic_value(match.group(2)), _arithmetic_value(match.group(1))))
    entries.sort()
    entry_tokens = [token for _position, token, _lane in entries]
    entry_lanes = [lane for _position, _token, lane in entries]
    if len(entry_tokens) != opcode_count or len(set(entry_tokens)) != opcode_count:
        raise ValueError(f"opcode selector exposed {len(entry_tokens)} non-unique entries for {opcode_count} opcodes")

    fault_use = _expect(
        rf"{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
        rf"{re.escape(dispatch_xor)}\(\s*{re.escape(dispatch_state)}\s*,\s*"
        rf"{re.escape(dispatch_step_mask)}\s*\)\s*,\s*({IDENT})\s*\)\s*\)",
        loop_body,
        "continuation decoder does not consume a sticky guard fault word",
    )
    guard_fault = fault_use.group(1)
    fault_zero_assignments = list(re.finditer(
        rf"\b{re.escape(guard_fault)}\s*=\s*0\s*;", source
    ))
    if len(fault_zero_assignments) != 1:
        raise ValueError("sticky guard fault word does not have one initialization")
    fault_init = fault_zero_assignments[0]
    if not re.search(rf"local\s+[^;]*\b{re.escape(guard_fault)}\b[^;]*;", source[:fault_init.start()]):
        raise ValueError("sticky guard fault word is not held in a private local")
    fault_assignments = [
        int(match.group(1))
        for match in re.finditer(rf"\b{re.escape(guard_fault)}\s*=\s*(\d+)\s*;", source)
        if int(match.group(1)) != 0
    ]
    # Rejection is intentionally decentralized across several build-local tight
    # sinks. Each sink may seed the same continuation fault word before entering
    # its non-yielding state mixer; no live path may reset it.
    if not 1 <= len(fault_assignments) <= 4 or len(set(fault_assignments)) != 1:
        raise ValueError(f"distributed guard fault word assignments are invalid: {fault_assignments}")
    if fault_init.start() >= periodic_calls[0].start():
        raise ValueError("sticky guard fault word is declared after periodic probing")
    if re.search(rf"\b{re.escape(guard_fault)}\b", selector):
        raise ValueError("sticky guard fault word leaked into continuation token encoding")

    decoded_state = (
        rf"{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
        rf"{re.escape(dispatch_xor)}\(\s*{re.escape(dispatch_state)}\s*,\s*"
        rf"{re.escape(dispatch_step_mask)}\s*\)\s*,\s*{re.escape(guard_fault)}\s*\)\s*\)"
    )
    # A tempered prefix prevents an outer depth/lane branch from being mistaken
    # for the nested token condition: a real node header cannot cross another
    # Lua 'then' before it reaches the decoded continuation state.
    node_header = re.compile(
        rf"(?:if|elseif)\s+(?P<prefix>(?:(?!\bthen\b).)*?){decoded_state}\s*"
        rf"(?:==|~=|<=)\s*(?P<token>{arithmetic_raw})(?P<suffix>[^;]*?)"
        rf"then\s+{re.escape(dispatch_matched)}\s*=\s*true;",
        re.S,
    )
    node_matches = list(node_header.finditer(loop_body))
    node_tokens = [_arithmetic_value(match.group("token")) for match in node_matches]
    if not node_tokens or len(node_tokens) != len(set(node_tokens)):
        raise ValueError("continuation state tokens are missing or non-unique")
    fault_decode_uses = len(re.findall(decoded_state, loop_body))
    # Lexically scoped opcode/super-operator locals may reuse the minified fault
    # identifier. Validate the continuation expressions themselves rather than
    # treating every same-spelled local in the dispatcher body as one binding.
    if not len(node_tokens) <= fault_decode_uses <= 2 * len(node_tokens):
        raise ValueError("sticky guard fault word is missing from continuation decode comparisons")

    step_mask_assignment = (
        rf"{re.escape(dispatch_step_mask)}\s*=\s*{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
        rf"{re.escape(dispatch_mask)}\s*,\s*\(\s*{re.escape(dispatch_steps)}\s*\*\s*"
        rf"{re.escape(dispatch_salt)}\s*\)\s*%\s*4294967296\s*\)\s*\);"
    )
    step_increment = rf"{re.escape(dispatch_steps)}\s*=\s*{re.escape(dispatch_steps)}\s*\+\s*1;"
    successor_state = re.compile(
        rf"{re.escape(dispatch_state)}\s*=\s*{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
        rf"({arithmetic_raw})\s*,\s*{re.escape(dispatch_step_mask)}\s*\)\s*\);"
    )
    successor_lane = re.compile(rf"{re.escape(dispatch_lane)}\s*=\s*({arithmetic_raw})\s*;")
    active_false = re.compile(rf"\b{re.escape(dispatch_active)}\s*=\s*false;")

    transitions: dict[int, int] = {}
    transition_lanes: dict[int, int] = {}
    update_orders: set[str] = set()
    terminals: set[int] = set()
    for index, match in enumerate(node_matches):
        token = node_tokens[index]
        end = node_matches[index + 1].start() if index + 1 < len(node_matches) else len(loop_body)
        segment = loop_body[match.end():end]
        state_match = successor_state.search(segment)
        terminal_match = active_false.search(segment)
        if state_match:
            step_match = re.search(step_increment, segment)
            mask_match = re.search(step_mask_assignment, segment)
            lane_match = successor_lane.search(segment)
            if not step_match or not mask_match or not lane_match:
                raise ValueError("continuation transition is missing a state component")
            if terminal_match and terminal_match.start() < state_match.end():
                raise ValueError("continuation node is both terminal and transitional")
            transitions[token] = _arithmetic_value(state_match.group(1))
            transition_lanes[token] = _arithmetic_value(lane_match.group(1))
            components = sorted(
                ((step_match.start(), "S"), (mask_match.start(), "M"),
                 (state_match.start(), "T"), (lane_match.start(), "L"))
            )
            update_orders.add("".join(label for _position, label in components))
        elif terminal_match:
            terminals.add(token)
        else:
            raise ValueError("continuation node has neither a transition nor a terminal handler")

    terminal_count = len(terminals)
    if terminal_count != opcode_count:
        raise ValueError(f"expected {opcode_count} terminal handlers, found {terminal_count}")
    if re.search(rf"\b{re.escape(dispatch_active)}\s*=\s*false;", selector):
        raise ValueError("opcode selector still contains a terminal handler marker")
    if len(node_tokens) != len(transitions) + terminal_count:
        raise ValueError("continuation node/transition/terminal counts are inconsistent")
    if not set(transitions.values()).issubset(set(node_tokens)):
        raise ValueError("continuation transition targets an unknown state token")
    if len(re.findall(step_mask_assignment, loop_body)) != len(transitions) + 1:
        raise ValueError("continuation step mask is not recomputed at loop entry and after every transition")
    if len(update_orders) != 1 or next(iter(update_orders)) not in {"SMTL", "LSMT", "SMLT"}:
        raise ValueError(f"dispatcher state update ordering is inconsistent: {update_orders}")
    update_order = next(iter(update_orders))

    # Reconstruct every node's expected lane from selector entries and transition
    # destinations. This remains independent of the chosen outer CFG template.
    node_lanes: dict[int, int] = {}
    for token, lane in zip(entry_tokens, entry_lanes):
        if token in node_lanes and node_lanes[token] != lane:
            raise ValueError("opcode selector assigned conflicting entry lanes")
        node_lanes[token] = lane
    for successor, lane in zip(transitions.values(), transition_lanes.values()):
        if successor in node_lanes and node_lanes[successor] != lane:
            raise ValueError("continuation transition assigned a conflicting target lane")
        node_lanes[successor] = lane
    if set(node_lanes) != set(node_tokens):
        raise ValueError("could not recover a lane for every continuation node")
    lanes = set(node_lanes.values())
    if len(lanes) < 3 or len(lanes) > 5 or lanes != set(range(len(lanes))):
        raise ValueError(f"continuation dispatcher does not use one complete 3-5 lane set: {sorted(lanes)}")
    for current, successor in transitions.items():
        successor_lane_value = transition_lanes[current]
        if node_lanes[successor] != successor_lane_value:
            raise ValueError("continuation transition chose the wrong target lane")
        if node_lanes[current] == successor_lane_value:
            raise ValueError("continuation path retained the same lane across adjacent nodes")

    lane_branch_pattern = re.compile(
        rf"(?:if|elseif)\s+{re.escape(dispatch_lane)}\s*==\s*({arithmetic_raw})\s*then"
    )
    inline_lane_pattern = re.compile(
        rf"(?:if|elseif)\s+{re.escape(dispatch_lane)}\s*==\s*({arithmetic_raw})\s*and\s*\("
    )
    depth_branch_pattern = re.compile(
        rf"(?:if|elseif)\s+{re.escape(dispatch_steps)}\s*==\s*({arithmetic_raw})\s*then"
    )
    lane_branches = [_arithmetic_value(match.group(1)) for match in lane_branch_pattern.finditer(loop_body)]
    inline_lanes = [_arithmetic_value(match.group(1)) for match in inline_lane_pattern.finditer(loop_body)]
    depth_branches = [_arithmetic_value(match.group(1)) for match in depth_branch_pattern.finditer(loop_body)]
    if depth_branches:
        dispatcher_template = "depth-layered"
        if loop_kind != "while" or inline_lanes:
            raise ValueError("depth-layered dispatcher has the wrong loop/lane organization")
        if set(depth_branches) != set(range(max(depth_branches) + 1)) or len(depth_branches) != len(set(depth_branches)):
            raise ValueError(f"depth-layered dispatcher has an incomplete depth partition: {depth_branches}")
        if set(lane_branches) != lanes:
            raise ValueError("depth-layered dispatcher does not cover every lane")
    elif inline_lanes:
        dispatcher_template = "token-threaded"
        if loop_kind != "repeat" or lane_branches or len(inline_lanes) != len(node_tokens):
            raise ValueError("token-threaded dispatcher is not one flat lane/token chain")
        for match, expected_lane in zip(node_matches, (node_lanes[token] for token in node_tokens)):
            inline = re.search(rf"{re.escape(dispatch_lane)}\s*==\s*({arithmetic_raw})", match.group("prefix"))
            if not inline or _arithmetic_value(inline.group(1)) != expected_lane:
                raise ValueError("token-threaded node checks the wrong lane")
    else:
        dispatcher_template = "lane-partitioned"
        if loop_kind != "while" or set(lane_branches) != lanes or len(lane_branches) != len(lanes):
            raise ValueError("lane-partitioned dispatcher does not contain one complete lane partition")

    visited: set[int] = set()
    node_labels: dict[int, str] = {}
    has_full_lane_path = False
    for entry_index, entry in enumerate(entry_tokens):
        path: set[int] = set()
        path_lanes: set[int] = set()
        current = entry
        depth = 0
        while current in transitions:
            if current in path:
                raise ValueError("continuation path contains a cycle")
            path.add(current)
            path_lanes.add(node_lanes[current])
            node_labels[current] = f"{entry_index}:{depth}"
            current = transitions[current]
            depth += 1
        path.add(current)
        path_lanes.add(node_lanes[current])
        node_labels[current] = f"{entry_index}:{depth}"
        if current not in terminals:
            raise ValueError("continuation entry does not reach a terminal handler")
        if len(path) < 3 or len(path) > 5:
            raise ValueError(f"continuation path length is outside 3-5 nodes: {len(path)}")
        if visited.intersection(path):
            raise ValueError("opcode continuation paths unexpectedly merge")
        visited.update(path)
        has_full_lane_path |= path_lanes == lanes
    if visited != set(node_tokens):
        raise ValueError("continuation graph contains unreachable states")
    if not has_full_lane_path:
        raise ValueError("no continuation path covers every generated lane")

    # Capture enough normalized structure for cross-build n-gram similarity tests.
    # Random token values and randomized identifiers are deliberately excluded.
    first_node = node_matches[0].start()
    prefix = loop_body[:first_node]
    prefix_positions = {
        "G": prefix.find("then"),
        "M": (re.search(step_mask_assignment, prefix).start()
              if re.search(step_mask_assignment, prefix) else -1),
        "R": (re.search(rf"{re.escape(dispatch_matched)}\s*=\s*false;", prefix).start()
              if re.search(rf"{re.escape(dispatch_matched)}\s*=\s*false;", prefix) else -1),
    }
    prefix_order = "".join(label for label, position in sorted(prefix_positions.items(), key=lambda item: item[1]) if position >= 0)
    shape_sequence = [f"T:{dispatcher_template}", f"P:{prefix_order}", f"U:{update_order}"]
    shape_sequence.extend(f"D:{value}" for value in depth_branches)
    shape_sequence.extend(f"B:{value}" for value in lane_branches)
    shape_sequence.extend(
        f"N:{node_labels[token]}:L{node_lanes[token]}" for token in node_tokens
    )

    graph_material = ",".join(
        f"{index}:{entry}@{entry_lanes[index]}" for index, entry in enumerate(entry_tokens)
    ) + ";" + ",".join(
        f"{current}@{node_lanes[current]}>{successor}@{transition_lanes[current]}"
        for current, successor in sorted(transitions.items())
    )
    structure_material = "|".join(shape_sequence)
    continuation = {
        "opcodes": opcode_count,
        "reject_paths": len(reject_paths),
        "lanes": len(lanes),
        "entries": len(entry_tokens),
        "nodes": len(node_tokens),
        "transitions": len(transitions),
        "terminals": terminal_count,
        "template": dispatcher_template,
        "loop": loop_kind,
        "state_update_order": update_order,
        "periodic_guard_probe": guard_probe,
        "sticky_fault_word": guard_fault,
        "fingerprint": hashlib.sha256(graph_material.encode("ascii")).hexdigest()[:16],
        "structure_fingerprint": hashlib.sha256(structure_material.encode("ascii")).hexdigest()[:16],
        # Kept in the in-process result for the Phase 4 frozen-extractor test.
        # The CLI removes raw build-local selector tokens from normal reports.
        "entry_tokens": entry_tokens,
        "shape_sequence": shape_sequence,
    }
    return {
        "domains": domains.as_dict(),
        "chunk": chunk_map,
        "block": block_map_slots,
        "flow": flow_map,
        "flow_cache": flow_cache_map,
        "vm_layout": vm_layout,
        "continuation": continuation,
        "identifiers": {
            "Chunk": chunk,
            "Block": block_name,
            "Flow": flow_name,
            "FlowAccessor": flow_accessor,
            "FlowCache": flow_cache_name,
            "Wrap": wrap_name,
            "Root": root_name,
            "DispatchState": dispatch_state,
            "DispatchLane": dispatch_lane,
            **aliases,
        },
    }


def json_ready(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_ready(item) for item in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated_vm", type=Path)
    parser.add_argument("--compare", type=Path, help="require a second generation to use different layouts")
    parser.add_argument(
        "--include-shape",
        action="store_true",
        help="include normalized VM-layout and dispatcher sequences for multi-build similarity analysis",
    )
    args = parser.parse_args()
    try:
        first = derive_runtime_layout(args.generated_vm.read_text("latin1"))
        display = json_ready(first)
        display["continuation"].pop("entry_tokens", None)
        if not args.include_shape:
            display["continuation"].pop("shape_sequence", None)
            display["vm_layout"].pop("shape_sequence", None)
        print("PASS runtime slot ABI " + json.dumps(display, sort_keys=True))
        if args.compare:
            second = derive_runtime_layout(args.compare.read_text("latin1"))
            changed = [name for name in ("chunk", "block", "flow", "flow_cache") if first[name] != second[name]]
            if not changed:
                raise ValueError("independent builds unexpectedly reused the complete runtime slot ABI")
            if first["vm_layout"]["fingerprint"] == second["vm_layout"]["fingerprint"]:
                raise ValueError("independent builds unexpectedly reused the VM state layout")
            if first["continuation"]["fingerprint"] == second["continuation"]["fingerprint"]:
                raise ValueError("independent builds unexpectedly reused the continuation graph")
            print("PASS independent runtime slot ABI differs: " + ", ".join(changed))
            print("PASS independent VM state layout differs")
            print("PASS independent continuation graph differs")
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
