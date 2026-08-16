#!/usr/bin/env python3
"""Recover and validate a generated VM's build-wide runtime slot ABI."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

IDENT = r"[A-Za-z_]\w*"


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
    # Deserialize begins with three local storage tables and the Chunk table,
    # followed by keyed assignments for Instructions, Functions and Lines.
    init = _expect(
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"\4\[(\d+)\]\s*=\s*\1;\s*"
        rf"\4\[(\d+)\]\s*=\s*\2;\s*"
        rf"\4\[(\d+)\]\s*=\s*\3;",
        source,
        "could not recover keyed Chunk initialization",
    )
    instrs, functions, lines, chunk = init.group(1, 2, 3, 4)
    chunk_map: dict[int, int] = {1: int(init.group(5)), 2: int(init.group(6)), 4: int(init.group(7))}

    # Prototype keys are the first three 16-bit reads after initialization.
    key_match = _expect(
        rf"local\s+({IDENT})\s*=\s*({IDENT})\(\);\s*"
        rf"local\s+({IDENT})\s*=\s*\2\(\);\s*"
        rf"local\s+({IDENT})\s*=\s*\2\(\);.*?"
        rf"{re.escape(chunk)}\[(\d+)\]\s*,\s*{re.escape(chunk)}\[(\d+)\]\s*,\s*{re.escape(chunk)}\[(\d+)\]"
        rf"\s*=\s*\1\s*,\s*\3\s*,\s*\4;",
        source[init.end():],
        "could not recover Chunk key slots",
        re.S,
    )
    chunk_map.update({5: int(key_match.group(5)), 6: int(key_match.group(6)), 7: int(key_match.group(7))})

    # The opcode bank assignment is uniquely tied to derivation domain 1777.
    opcode = _expect(
        rf"local\s+({IDENT})\s*=\s*{IDENT}\(\s*(\d+)\s*,[^;]*,\s*1777\);\s*"
        rf"{re.escape(chunk)}\[(\d+)\]\s*=\s*\1;",
        source,
        "could not recover Chunk opcode-bank slot",
    )
    opcode_count = int(opcode.group(2))
    chunk_map[8] = int(opcode.group(3))

    # Constant capsules are initialized immediately before InstrCount/Blocks.
    capsules = _expect(
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*{re.escape(chunk)}\[(\d+)\]\s*=\s*\1;\s*"
        rf"local\s+{IDENT}\s*=\s*0;\s*local\s+({IDENT})\s*=\s*\{{\}};\s*"
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*local\s+({IDENT})\s*=\s*0;",
        source,
        "could not recover Chunk capsule/block locals",
    )
    capsule_name, capsule_slot, blocks, block_map, block_count = capsules.group(1, 2, 3, 4, 5)
    chunk_map[15] = int(capsule_slot)
    pair = _expect(
        rf"{re.escape(chunk)}\[(\d+)\]\s*,\s*{re.escape(chunk)}\[(\d+)\]\s*=\s*"
        rf"{re.escape(blocks)}\s*,\s*{re.escape(block_map)};",
        source[capsules.start():],
        "could not recover Chunk Blocks/BlockMap slots",
    )
    chunk_map.update({9: int(pair.group(1)), 10: int(pair.group(2))})

    counts = _expect(
        rf"{re.escape(chunk)}\[(\d+)\]\s*=\s*{re.escape(block_count)};\s*"
        rf"{re.escape(chunk)}\[(\d+)\]\s*=\s*{IDENT}\(\);",
        source[capsules.end():],
        "could not recover Chunk block-count/initial-state slots",
    )
    chunk_map.update({11: int(counts.group(1)), 12: int(counts.group(2))})

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
    remaining_old = set(range(1, 16)) - set(chunk_map)
    remaining_new = set(range(1, 16)) - set(chunk_map.values())
    if len(remaining_old) != 1 or len(remaining_new) != 1 or remaining_old != {3}:
        raise ValueError("could not infer the remaining Chunk parameter slot")
    chunk_map[3] = remaining_new.pop()

    # Block is built by nine explicit keyed assignments in semantic order.
    block_match = _expect(
        rf"local\s+({IDENT})\s*=\s*\{{\}};\s*"
        + "".join(rf"\1\[(\d+)\]\s*=\s*[^;]+;\s*" for _ in range(9)),
        source,
        "could not recover keyed Block constructor",
    )
    block_name = block_match.group(1)
    block_map_slots = {index: int(block_match.group(index + 1)) for index in range(1, 10)}

    # Flow updates CurrentPC, CurrentBlock and EntryState in one keyed tuple.
    triples = list(re.finditer(
        rf"({IDENT})\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*,\s*\1\[(\d+)\]\s*=\s*"
        rf"{IDENT}\s*,\s*{IDENT}\s*,\s*{IDENT};",
        source,
    ))
    flow_candidates = [match for match in triples if match.group(1) != chunk and
                       all(1 <= int(match.group(index)) <= 4 for index in (2, 3, 4))]
    if len(flow_candidates) != 1:
        raise ValueError(f"expected one Flow tuple assignment, found {len(flow_candidates)}")
    flow_match = flow_candidates[0]
    flow_name = flow_match.group(1)
    flow_map = {1: int(flow_match.group(2)), 2: int(flow_match.group(3)), 3: int(flow_match.group(4))}
    missing_flow = (set(range(1, 5)) - set(flow_map.values()))
    if len(missing_flow) != 1:
        raise ValueError("could not infer Flow cache slot")
    flow_map[4] = missing_flow.pop()

    # FlowCache has three semantic keyed assignments and is then stored in Flow.
    cache_match = _expect(
        rf"(?:local\s+)?({IDENT})\s*=\s*\{{\}};\s*"
        rf"\1\[(\d+)\]\s*=\s*{IDENT};\s*"
        rf"\1\[(\d+)\]\s*=\s*{IDENT};\s*"
        rf"\1\[(\d+)\]\s*=\s*{IDENT};\s*"
        rf"{re.escape(flow_name)}\[{flow_map[4]}\]\s*=\s*\1;",
        source,
        "could not recover keyed FlowCache constructor",
    )
    flow_cache_name = cache_match.group(1)
    flow_cache_map = {1: int(cache_match.group(2)), 2: int(cache_match.group(3)), 3: int(cache_match.group(4))}

    _permutation(chunk_map, 15, "Chunk")
    _permutation(block_map_slots, 9, "Block")
    _permutation(flow_map, 4, "Flow")
    _permutation(flow_cache_map, 3, "FlowCache")

    # Alias consistency checks cover parser and transition aliases. Opcode-handler
    # behavior is subsequently exercised by the differential suite.
    block_start_slot = block_map_slots[1]
    alias_checks = {
        "SuccessorBlock": rf"local\s+({IDENT})\s*=\s*{re.escape(block_map)}\[[^\]]+\];\s*"
                          rf"if\s+not\s+\1\s+or\s+\1\[{block_start_slot}\]",
        "CurrentBlock": rf"local\s+({IDENT})\s*=\s*{re.escape(flow_name)}\[{flow_map[2]}\];.*?"
                        rf"\1\[{block_map_slots[5]}\]",
        "NextBlock": rf"local\s+({IDENT})\s*=\s*{re.escape(chunk)}\[{chunk_map[10]}\]\s+and\s+"
                     rf"{re.escape(chunk)}\[{chunk_map[10]}\]\[[^\]]+\];.*?\1\[{block_map_slots[8]}\]",
    }
    aliases: dict[str, str] = {"Block": block_name}
    for label, pattern in alias_checks.items():
        match = _expect(pattern, source, f"{label} does not use the permuted Block layout", re.S)
        aliases[label] = match.group(1)

    # The opcode comparison tree must only choose a masked entry token. A
    # continuation graph then crosses 3-5 shuffled lanes and 3-5 nodes before a
    # terminal handler runs in the VM closure. Recover the randomized names from
    # the declaration shape rather than relying on implementation identifiers.
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
    if not re.search(rf"\b{re.escape(flow_name)}\s*\[\s*{flow_map[3]}\s*\]", continuation_init.group(0)):
        raise ValueError("continuation entry mask is not bound to the current Flow state")

    continuation_loop = _expect(
        rf"while\s+{re.escape(dispatch_active)}\s+do\s+(.*?)"
        rf"if\s+not\s+{re.escape(dispatch_matched)}\s+then\s+"
        rf"error\(\s*['\"]invalid protected payload['\"]\s*,\s*0\s*\);\s*end;\s*end;",
        source[continuation_init.end():],
        "could not recover complete continuation dispatcher loop",
        re.S,
    )
    selector = source[continuation_init.end():continuation_init.end() + continuation_loop.start()]
    loop_body = continuation_loop.group(1)
    arithmetic = r"(\(\s*\d+\s*[+\-*]\s*\d+\s*\))"

    salt_init = _expect(
        rf"local\s+{re.escape(dispatch_salt)}\s*=\s*\([^;]*\*\s*{arithmetic}\s*\+\s*{arithmetic}"
        rf"\s*\)\s*%\s*4294967296\s*;",
        continuation_init.group(0),
        "continuation salt is not flow-derived 32-bit arithmetic",
    )
    salt_factor = _arithmetic_value(salt_init.group(1))
    if salt_factor == 0 or salt_factor % 2 == 0:
        raise ValueError("continuation step salt factor must be odd and non-zero")

    entry_matches = re.findall(
        rf"{re.escape(dispatch_state)}\s*=\s*{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
        rf"{arithmetic}\s*,\s*{re.escape(dispatch_mask)}\s*\)\s*\);\s*"
        rf"{re.escape(dispatch_lane)}\s*=\s*{arithmetic}\s*;",
        selector,
    )
    entry_tokens = [_arithmetic_value(token) for token, _lane in entry_matches]
    entry_lanes = [_arithmetic_value(lane) for _token, lane in entry_matches]
    if len(entry_tokens) != opcode_count or len(set(entry_tokens)) != opcode_count:
        raise ValueError(f"opcode selector exposed {len(entry_tokens)} non-unique entries for {opcode_count} opcodes")

    lane_pattern = re.compile(
        rf"(?:if|elseif)\s+{re.escape(dispatch_lane)}\s*==\s*{arithmetic}\s+then"
    )
    lane_matches = list(lane_pattern.finditer(loop_body))
    lane_values = [_arithmetic_value(match.group(1)) for match in lane_matches]
    lanes = set(lane_values)
    if len(lanes) < 3 or len(lanes) > 5 or lanes != set(range(len(lanes))) or len(lane_values) != len(lanes):
        raise ValueError(f"continuation dispatcher does not use one complete 3-5 lane set: {lane_values}")

    decoded_state = (rf"{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
                     rf"{re.escape(dispatch_state)}\s*,\s*{re.escape(dispatch_step_mask)}\s*\)\s*\)")
    node_header = (
        rf"(?:if|elseif)\s+(?:not\s*\(\s*)?{decoded_state}\s*(?:==|~=|<=)\s*{arithmetic}"
        rf"[^;]*?then\s+{re.escape(dispatch_matched)}\s*=\s*true;"
    )
    node_matches = list(re.finditer(node_header, loop_body))
    node_tokens = [_arithmetic_value(match.group(1)) for match in node_matches]
    if len(node_tokens) != len(set(node_tokens)):
        raise ValueError("continuation state tokens are not unique")

    node_lanes: dict[int, int] = {}
    for lane_index, lane_match in enumerate(lane_matches):
        lane = _arithmetic_value(lane_match.group(1))
        lane_end = lane_matches[lane_index + 1].start() if lane_index + 1 < len(lane_matches) else len(loop_body)
        for node_match in re.finditer(node_header, loop_body[lane_match.end():lane_end]):
            token = _arithmetic_value(node_match.group(1))
            if token in node_lanes:
                raise ValueError("continuation state appears in multiple lanes")
            node_lanes[token] = lane
    if set(node_lanes) != set(node_tokens):
        raise ValueError("could not bind every continuation state to exactly one lane")

    step_mask_assignment = (
        rf"{re.escape(dispatch_step_mask)}\s*=\s*{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
        rf"{re.escape(dispatch_mask)}\s*,\s*\(\s*{re.escape(dispatch_steps)}\s*\*\s*"
        rf"{re.escape(dispatch_salt)}\s*\)\s*%\s*4294967296\s*\)\s*\);"
    )
    transition_pattern = re.compile(
        node_header +
        rf"\s*{re.escape(dispatch_steps)}\s*=\s*{re.escape(dispatch_steps)}\s*\+\s*1;\s*"
        + step_mask_assignment +
        rf"\s*{re.escape(dispatch_state)}\s*=\s*{re.escape(dispatch_u32)}\(\s*{re.escape(dispatch_xor)}\(\s*"
        rf"{arithmetic}\s*,\s*{re.escape(dispatch_step_mask)}\s*\)\s*\);\s*"
        rf"{re.escape(dispatch_lane)}\s*=\s*{arithmetic}\s*;"
    )
    transitions: dict[int, int] = {}
    transition_lanes: dict[int, int] = {}
    for match in transition_pattern.finditer(loop_body):
        current = _arithmetic_value(match.group(1))
        successor = _arithmetic_value(match.group(2))
        successor_lane = _arithmetic_value(match.group(3))
        if current in transitions:
            raise ValueError("continuation state has multiple successor assignments")
        transitions[current] = successor
        transition_lanes[current] = successor_lane

    terminal_count = len(re.findall(rf"\b{re.escape(dispatch_active)}\s*=\s*false;", loop_body))
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

    for entry, entry_lane in zip(entry_tokens, entry_lanes):
        if node_lanes.get(entry) != entry_lane:
            raise ValueError("opcode selector chose the wrong lane for its continuation entry")
    for current, successor in transitions.items():
        successor_lane = transition_lanes[current]
        if node_lanes[successor] != successor_lane:
            raise ValueError("continuation transition chose the wrong target lane")
        if node_lanes[current] == successor_lane:
            raise ValueError("continuation path retained the same lane across adjacent nodes")

    visited: set[int] = set()
    has_full_lane_path = False
    for entry in entry_tokens:
        path: set[int] = set()
        path_lanes: set[int] = set()
        current = entry
        while current in transitions:
            if current in path:
                raise ValueError("continuation path contains a cycle")
            path.add(current)
            path_lanes.add(node_lanes[current])
            current = transitions[current]
        path.add(current)
        path_lanes.add(node_lanes[current])
        if current not in node_tokens:
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

    graph_material = ",".join(
        f"{index}:{entry}@{entry_lanes[index]}" for index, entry in enumerate(entry_tokens)
    ) + ";" + ",".join(
        f"{current}@{node_lanes[current]}>{successor}@{transition_lanes[current]}"
        for current, successor in sorted(transitions.items())
    )
    continuation = {
        "opcodes": opcode_count,
        "lanes": len(lanes),
        "entries": len(entry_tokens),
        "nodes": len(node_tokens),
        "transitions": len(transitions),
        "terminals": terminal_count,
        "fingerprint": hashlib.sha256(graph_material.encode("ascii")).hexdigest()[:16],
    }

    return {
        "chunk": chunk_map,
        "block": block_map_slots,
        "flow": flow_map,
        "flow_cache": flow_cache_map,
        "continuation": continuation,
        "identifiers": {
            "Chunk": chunk,
            "Block": block_name,
            "Flow": flow_name,
            "FlowCache": flow_cache_name,
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
    args = parser.parse_args()
    try:
        first = derive_runtime_layout(args.generated_vm.read_text("latin1"))
        print("PASS runtime slot ABI " + json.dumps(json_ready(first), sort_keys=True))
        if args.compare:
            second = derive_runtime_layout(args.compare.read_text("latin1"))
            changed = [name for name in ("chunk", "block", "flow", "flow_cache") if first[name] != second[name]]
            if not changed:
                raise ValueError("independent builds unexpectedly reused the complete runtime slot ABI")
            if first["continuation"]["fingerprint"] == second["continuation"]["fingerprint"]:
                raise ValueError("independent builds unexpectedly reused the continuation graph")
            print("PASS independent runtime slot ABI differs: " + ", ".join(changed))
            print("PASS independent continuation graph differs")
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
