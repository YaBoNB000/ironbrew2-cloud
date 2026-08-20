#!/usr/bin/env python3
"""Measure how much of a final IronBrew2 output is recoverable statically.

This is deliberately an attacker-side harness: it accepts only the production
Lua file and does not read temp/t2.lua, generator logs, BuildSeed state, luac
output, or the original source. It mirrors formulas that are shipped in the
wrapper and records the current baseline; later hardening milestones should
make individual recovery stages fail and update the policy intentionally.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re
import struct
import sys
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify_v4_payload as payload
from build_domains import IDENT

MASK32 = 0xFFFFFFFF


@dataclass
class StaticAttackReport:
    file: str
    source_bytes: int
    carrier_segments: int
    encoded_payload_bytes: int
    envelope_bytes: int
    protected_body_bytes: int
    plain_body_bytes: int
    outer_seed: int
    attestation_value: int
    prototypes: int
    blocks: int
    instructions: int
    logical_instructions: int
    fused_records: int
    capsules: int
    decoded_constants: list[dict[str, Any]]
    recovered_strings: list[str]
    canonical_opcode_ids: list[dict[str, Any]]
    requested_strings: list[str]
    requested_strings_recovered: list[str]


def prototypes(root: payload.Prototype, path: tuple[int, ...] = ()):
    yield path, root
    for index, child in enumerate(root.children):
        yield from prototypes(child, path + (index,))


def decode_constant(info: payload.PayloadInfo, proto: payload.Prototype, capsule: payload.Capsule):
    encoded = info.body[capsule.encoded_start:capsule.end]
    raw = payload.stream_xor(encoded, payload.constant_mask_state(capsule.index, proto, capsule))
    tags = payload.derive_permutation(
        4, proto.k1, proto.k2, proto.k3, payload.CONSTANT_TAG_DOMAIN
    )
    constant_type = tags.index(raw[0])
    if constant_type == 0:
        return "nil", None
    if constant_type == 1:
        return "boolean", bool(raw[1])
    if constant_type == 2:
        return "number", struct.unpack("<d", raw[1:9])[0]
    value, _shard_count = payload.decode_string_shards(raw, capsule.index, proto, capsule)
    try:
        return "string", value.decode("utf-8")
    except UnicodeDecodeError:
        return "binary-string", value.hex()


def opcode_count(source: str, domain: int) -> int:
    ident = IDENT
    matches = {
        int(match.group(1))
        for match in re.finditer(
            rf"local\s+{ident}\s*=\s*{ident}\(\s*(\d+)\s*,\s*{ident}\s*,\s*{ident}\s*,\s*{ident}\s*,"
            rf"\s*{domain}\s*\)\s*;\s*{ident}\s*\[\s*\d+\s*\]\s*=\s*{ident}\s*;",
            source,
            re.S,
        )
    }
    if len(matches) != 1:
        raise ValueError(f"could not recover virtual opcode count: {sorted(matches)}")
    return matches.pop()


def opcode_mask(pc: int, k1: int, k2: int, k3: int) -> int:
    linear = (pc * k1 + k2) % 65536
    return (linear * ((pc % 251) + 1) + k3) % 65536


def begin_opcode_state(
    proto: payload.Prototype, block: payload.Block, current_chunk_state: int
) -> int:
    value = (
        current_chunk_state * 22695477
        + block.entry_state * payload.LCG_MULTIPLIER
        + block.start_pc * 65537
        + proto.k1 * 251
        + proto.k2 * 17
        + proto.k3
        + payload.OPCODE_STATE_DOMAIN
        + payload.PAYLOAD_ATTESTATION
    ) & MASK32
    return (value * payload.LCG_MULTIPLIER + payload.LCG_INCREMENT) & MASK32


def advance_opcode_state(
    state: int,
    digest: int,
    pc: int,
    current_chunk_state: int,
    entry_state: int,
) -> int:
    value = (
        state * payload.LCG_MULTIPLIER
        + digest
        + pc * 257
        + current_chunk_state * 17
        + entry_state
        + payload.OPCODE_STATE_DOMAIN
        + payload.PAYLOAD_ATTESTATION
    ) & MASK32
    return (value * 22695477 + 1) & MASK32


def opcode_state_mask(state: int, pc: int) -> int:
    low, high = state & 0xFFFF, state >> 16
    return (
        low * ((pc % 251) + 1)
        + high * 17
        + (payload.OPCODE_STATE_DOMAIN & 0xFFFF)
    ) & 0xFFFF


def decode_opcodes(
    info: payload.PayloadInfo, proto: payload.Prototype, proto_path: tuple[int, ...], virtual_count: int
) -> list[dict[str, Any]]:
    bank = payload.derive_permutation(
        virtual_count, proto.k1, proto.k2, proto.k3, payload.OPCODE_PERMUTATION_DOMAIN
    )
    result: list[dict[str, Any]] = []
    for block in sorted(proto.blocks, key=lambda item: item.start_pc):
        current_chunk_state = payload.chunk_state(
            block.entry_state, block.start_pc, block.count, proto
        )
        state = begin_opcode_state(proto, block, current_chunk_state)
        for offset in range(block.count):
            pc = block.start_pc + offset
            descriptor = block.descriptors[offset]
            if descriptor & 1:
                result.append({"prototype": list(proto_path), "pc": pc, "data_word": True, "fused_members": 0, "logical_width": 1})
            else:
                opcode_span = block.record_column_spans[offset][1]
                encoded = info.body[opcode_span[1]:opcode_span[2]]
                decoded_column = payload.decode_prototype_column(
                    encoded, proto, block, 1, pc
                )
                if len(decoded_column) != 2:
                    raise ValueError("opcode column is not a uint16 field")
                stored = int.from_bytes(decoded_column, "little")
                local_opcode = (
                    stored
                    ^ opcode_mask(pc, proto.k1, proto.k2, proto.k3)
                    ^ payload.block_field_mask(block.entry_state, pc, 0, proto)
                    ^ opcode_state_mask(state, pc)
                ) & 0xFFFF
                if local_opcode >= len(bank):
                    raise ValueError("decoded local opcode is outside the prototype bank")
                result.append(
                    {
                        "prototype": list(proto_path),
                        "pc": pc,
                        "data_word": False,
                        "local_id": local_opcode,
                        "canonical_id": bank[local_opcode],
                        "fused_members": block.fused_counts[offset],
                        "logical_width": 1 + block.fused_counts[offset],
                    }
                )
            fragment = block.fragment_spans[offset]
            record = info.body[fragment[1]:fragment[2]]
            digest = payload.instruction_digest(
                record, pc, proto, current_chunk_state, block.entry_state
            )
            state = advance_opcode_state(
                state, digest, pc, current_chunk_state, block.entry_state
            )
    return result


def analyze(path: Path, expected_strings: list[str]) -> StaticAttackReport:
    info = payload.parse_and_verify(path)
    source = info.source
    virtual_count = opcode_count(source, info.domains.opcode_permutation)

    constants: list[dict[str, Any]] = []
    seen_constants: set[tuple[tuple[int, ...], int, str]] = set()
    opcodes: list[dict[str, Any]] = []
    prototype_count = block_count = instruction_count = logical_instruction_count = fused_record_count = capsule_count = 0
    for proto_path, proto in prototypes(info.root):
        prototype_count += 1
        block_count += len(proto.blocks)
        instruction_count += proto.instruction_count
        proto_fused_counts = [count for block in proto.blocks for count in block.fused_counts]
        logical_instruction_count += proto.instruction_count + sum(proto_fused_counts)
        fused_record_count += sum(count > 0 for count in proto_fused_counts)
        capsule_count += len(proto.capsules)
        for capsule in proto.capsules:
            kind, value = decode_constant(info, proto, capsule)
            fingerprint = (proto_path, capsule.index, json.dumps(value, sort_keys=True))
            if fingerprint in seen_constants:
                continue
            seen_constants.add(fingerprint)
            constants.append(
                {
                    "prototype": list(proto_path),
                    "index": capsule.index,
                    "type": kind,
                    "value": value,
                }
            )
        opcodes.extend(decode_opcodes(info, proto, proto_path, virtual_count))

    recovered_strings = sorted(
        {
            item["value"]
            for item in constants
            if item["type"] == "string" and isinstance(item["value"], str)
        }
    )
    recovered_requested = [value for value in expected_strings if value in recovered_strings]
    return StaticAttackReport(
        file=str(path),
        source_bytes=len(source.encode("latin1")),
        carrier_segments=len(info.literals),
        encoded_payload_bytes=len(info.payload),
        envelope_bytes=len(info.envelope),
        protected_body_bytes=len(info.protected_body),
        plain_body_bytes=len(info.body),
        outer_seed=info.seed,
        attestation_value=info.attestation_token,
        prototypes=prototype_count,
        blocks=block_count,
        instructions=instruction_count,
        logical_instructions=logical_instruction_count,
        fused_records=fused_record_count,
        capsules=capsule_count,
        decoded_constants=constants,
        recovered_strings=recovered_strings,
        canonical_opcode_ids=opcodes,
        requested_strings=expected_strings,
        requested_strings_recovered=recovered_requested,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("generated", type=Path)
    parser.add_argument("--expect-string", action="append", default=[])
    parser.add_argument("--report", type=Path)
    parser.add_argument("--require-current-baseline", action="store_true")
    args = parser.parse_args()
    try:
        report = analyze(args.generated, args.expect_string)
        output = json.dumps(asdict(report), ensure_ascii=False, sort_keys=True, indent=2)
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(output + "\n", encoding="utf-8")
        if args.require_current_baseline:
            missing = sorted(set(report.requested_strings) - set(report.requested_strings_recovered))
            if missing:
                raise ValueError(f"attack harness no longer recovers baseline strings: {missing}")
            if not (
                report.carrier_segments >= 1
                and report.plain_body_bytes > 0
                and report.prototypes >= 1
                and report.instructions >= 1
                and report.canonical_opcode_ids
            ):
                raise ValueError("attack harness did not recover the current structural baseline")
        print(
            "STATIC_ATTACK_BASELINE "
            f"carrier={report.carrier_segments} body={report.plain_body_bytes} "
            f"prototypes={report.prototypes} instructions={report.instructions}/{report.logical_instructions} "
            f"fused={report.fused_records} constants={len(report.decoded_constants)} "
            f"requested={len(report.requested_strings_recovered)}/{len(report.requested_strings)}"
        )
        if args.report:
            print(f"report={args.report}")
    except (OSError, ValueError, IndexError, struct.error) as error:
        raise SystemExit(str(error)) from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
