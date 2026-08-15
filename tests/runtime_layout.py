#!/usr/bin/env python3
"""Recover and validate a generated VM's build-wide runtime slot ABI."""

from __future__ import annotations

import argparse
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


def derive_runtime_layout(source: str) -> dict[str, dict[int, int] | str]:
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
        rf"local\s+({IDENT})\s*=\s*{IDENT}\([^;]*,\s*1777\);\s*"
        rf"{re.escape(chunk)}\[(\d+)\]\s*=\s*\1;",
        source,
        "could not recover Chunk opcode-bank slot",
    )
    chunk_map[8] = int(opcode.group(2))

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

    return {
        "chunk": chunk_map,
        "block": block_map_slots,
        "flow": flow_map,
        "flow_cache": flow_cache_map,
        "identifiers": {
            "Chunk": chunk,
            "Block": block_name,
            "Flow": flow_name,
            "FlowCache": flow_cache_name,
            **aliases,
        },
    }


def json_ready(layout: dict[str, dict[int, int] | str]) -> dict[str, object]:
    return {
        key: ({str(old): new for old, new in value.items()} if key != "identifiers" else value)
        for key, value in layout.items()
    }


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
            print("PASS independent runtime slot ABI differs: " + ", ".join(changed))
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
